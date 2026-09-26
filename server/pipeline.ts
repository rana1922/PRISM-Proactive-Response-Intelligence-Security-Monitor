import { SecurityEvent, AlertRecord, IncidentRecord } from './types';
import { db } from './db';
import { detectionEngine } from './detectionEngine';
import { iocEngine } from './iocEngine';
import { cveEngine } from './cveEngine';
import { scoringEngine } from './scoringEngine';
import { responseEngine } from './responseEngine';
import { generateId } from './idGenerator';

// Event emitter / SSE clients list
type SSEListener = (data: { type: string; payload: unknown }) => void;
const sseListeners: Set<SSEListener> = new Set();

export function registerSSEListener(listener: SSEListener): () => void {
  sseListeners.add(listener);
  return () => {
    sseListeners.delete(listener);
  };
}

export function broadcast(type: string, payload: unknown) {
  for (const listener of sseListeners) {
    try {
      listener({ type, payload });
    } catch {
      // ignore dropped stream
    }
  }
}

export interface PipelineResult {
  event: SecurityEvent;
  is_attack: boolean;
  alert?: AlertRecord;
  incident?: IncidentRecord;
  explainable_breakdown?: {
    factors: { factor: string; score: number; detail: string }[];
    total: number;
    severity: string;
  };
  simulation_trace: {
    step: number;
    title: string;
    status: 'COMPLETED' | 'TRIGGERED' | 'BYPASSED';
    output: string;
  }[];
}

export class SecurityPipeline {
  public processEvent(rawEvent: Partial<SecurityEvent>): PipelineResult {
    // 1. Normalize Event
    const eventId = rawEvent.event_id || generateId('evt');
    const normalizedEvent: SecurityEvent = {
      event_id: eventId,
      timestamp: rawEvent.timestamp || new Date().toISOString(),
      source: rawEvent.source || 'web_server',
      source_ip: rawEvent.source_ip || '185.220.101.45',
      destination_ip: rawEvent.destination_ip || '10.0.1.25',
      destination_port: rawEvent.destination_port || 443,
      hostname: rawEvent.hostname || 'web-prod-01',
      username: rawEvent.username || 'admin',
      event_type: rawEvent.event_type || 'http_request',
      protocol: rawEvent.protocol || 'HTTP',
      method: rawEvent.method || 'POST',
      url: rawEvent.url || '/login',
      payload: rawEvent.payload || '',
      user_agent: rawEvent.user_agent || 'Mozilla/5.0',
      process_name: rawEvent.process_name,
      process_command: rawEvent.process_command,
      file_hash: rawEvent.file_hash,
      domain: rawEvent.domain
    };

    // Store in historical events
    db.events.unshift(normalizedEvent);
    if (db.events.length > 500) {
      db.events.pop();
    }

    const trace: PipelineResult['simulation_trace'] = [
      {
        step: 1,
        title: 'Event Normalization',
        status: 'COMPLETED',
        output: `Normalized ${normalizedEvent.event_type} event [${normalizedEvent.event_id}] from ${normalizedEvent.source_ip} to ${normalizedEvent.hostname}`
      }
    ];

    // 2. Detection Engine
    const detection = detectionEngine.analyzeEvent(normalizedEvent);
    if (!detection) {
      trace.push({
        step: 2,
        title: 'Attack Detection',
        status: 'BYPASSED',
        output: 'Event evaluated as benign traffic. No detection signatures matched.'
      });
      return {
        event: normalizedEvent,
        is_attack: false,
        simulation_trace: trace
      };
    }

    trace.push({
      step: 2,
      title: 'Attack Detection',
      status: 'COMPLETED',
      output: `Identified ${detection.attack_type} attack (Rule: ${detection.rule_id}, Confidence: ${detection.confidence}%)`
    });

    // 3. IOC Correlation
    const iocMatch = iocEngine.correlate(normalizedEvent);
    trace.push({
      step: 3,
      title: 'IOC Correlation',
      status: iocMatch.matched ? 'COMPLETED' : 'BYPASSED',
      output: iocMatch.matched
        ? `IOC match identified! ${iocMatch.reputation_summary}`
        : 'Source IP and indicators cleared against known threat databases.'
    });

    // 4. CVE Correlation
    const cveMatch = cveEngine.correlate(normalizedEvent, detection.attack_type);
    trace.push({
      step: 4,
      title: 'CVE Correlation',
      status: cveMatch.matched ? 'COMPLETED' : 'BYPASSED',
      output: cveMatch.matched
        ? `Vulnerability match: ${cveMatch.cve_record?.cve_id} (CVSS ${cveMatch.cvss_score}) affecting ${cveMatch.affected_product}`
        : 'No specific unpatched CVE profile matched for target service.'
    });

    // 5. Threat Scoring
    const scoreFactors = scoringEngine.calculateScore(
      normalizedEvent,
      detection.attack_type,
      detection.confidence,
      iocMatch,
      cveMatch
    );

    trace.push({
      step: 5,
      title: 'Explainable Threat Scoring',
      status: 'COMPLETED',
      output: `Computed Threat Score: ${scoreFactors.total_score}/100 (${scoreFactors.severity} Severity)`
    });

    // 6. Create Alert
    const alertId = generateId('alt');
    const alertRecord: AlertRecord = {
      alert_id: alertId,
      timestamp: normalizedEvent.timestamp,
      event_id: normalizedEvent.event_id,
      attack_type: detection.attack_type,
      source_ip: normalizedEvent.source_ip,
      destination_ip: normalizedEvent.destination_ip,
      destination_port: normalizedEvent.destination_port,
      hostname: normalizedEvent.hostname,
      username: normalizedEvent.username,
      url: normalizedEvent.url,
      payload: normalizedEvent.payload,
      ioc_match: iocMatch.matched,
      ioc_details: iocMatch.matched && iocMatch.ioc_record ? {
        ioc: iocMatch.ioc_record.ioc,
        type: iocMatch.ioc_record.type,
        threat_level: iocMatch.threat_level || 'high',
        source: iocMatch.source || 'PRISM Threat Intelligence',
        confidence: iocMatch.confidence || 90
      } : undefined,
      cve_match: cveMatch.matched,
      cve_details: cveMatch.matched && cveMatch.cve_record ? {
        cve_id: cveMatch.cve_record.cve_id,
        cvss_score: cveMatch.cvss_score || 9.8,
        severity: cveMatch.severity || 'CRITICAL',
        affected_product: cveMatch.affected_product || 'Core Web Stack'
      } : undefined,
      threat_score: scoreFactors.total_score,
      severity: scoreFactors.severity,
      score_factors: scoreFactors,
      status: 'NEW',
      recommended_actions: [],
      executed_actions: [],
      response_mode: db.responseMode
    };

    // 7. Response Engine & Automated Mitigation
    const decision = responseEngine.decideAndExecute(alertRecord, scoreFactors, normalizedEvent);
    alertRecord.recommended_actions = decision.recommended_actions;
    alertRecord.executed_actions = decision.executed_actions;
    if (decision.incident_record) {
      alertRecord.incident_id = decision.incident_record.incident_id;
    }

    db.alerts.unshift(alertRecord);
    if (db.alerts.length > 200) {
      db.alerts.pop();
    }

    trace.push({
      step: 6,
      title: 'Automated Response Execution',
      status: decision.executed_actions.length > 0 ? 'COMPLETED' : 'BYPASSED',
      output: decision.executed_actions.length > 0
        ? `Executed in SIMULATION mode: [${decision.executed_actions.join(', ')}]`
        : 'Score below automated mitigation threshold. Alert routed to SOC monitoring.'
    });

    if (decision.incident_record) {
      trace.push({
        step: 7,
        title: 'SOC Incident Creation',
        status: 'COMPLETED',
        output: `Created Incident #${decision.incident_record.incident_id} and escalated to on-call SOC team`
      });
    }

    // Broadcast live to connected clients
    broadcast('ALERT_CREATED', {
      alert: alertRecord,
      incident: decision.incident_record,
      summary: db.getSummary()
    });

    return {
      event: normalizedEvent,
      is_attack: true,
      alert: alertRecord,
      incident: decision.incident_record,
      explainable_breakdown: {
        factors: [
          { factor: 'Base Attack Severity', score: scoreFactors.attack_score, detail: `${detection.attack_type} pattern matched` },
          { factor: 'IOC Match', score: scoreFactors.ioc_score, detail: scoreFactors.ioc_matched || 'No IOC match' },
          { factor: 'CVE Correlation', score: scoreFactors.cve_score, detail: scoreFactors.cve_matched || 'No specific CVE' },
          { factor: 'Asset Criticality', score: scoreFactors.asset_score, detail: `${normalizedEvent.hostname} tier weighting` },
          { factor: 'Detection Confidence', score: scoreFactors.confidence_score, detail: `${detection.confidence}% rule confidence` }
        ],
        total: scoreFactors.total_score,
        severity: scoreFactors.severity
      },
      simulation_trace: trace
    };
  }
}

export const pipeline = new SecurityPipeline();
