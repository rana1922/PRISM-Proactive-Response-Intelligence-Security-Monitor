import {
  AlertRecord,
  IncidentRecord,
  ResponseActionType,
  ResponseAuditRecord,
  ScoreFactors,
  SecurityEvent
} from './types';
import { db } from './db';
import { generateId } from './idGenerator';

export interface ResponseDecision {
  recommended_actions: ResponseActionType[];
  executed_actions: ResponseActionType[];
  should_create_incident: boolean;
  incident_record?: IncidentRecord;
  audit_records: ResponseAuditRecord[];
}

export class ResponseEngine {
  public decideAndExecute(
    alert: AlertRecord,
    scoreFactors: ScoreFactors,
    event: SecurityEvent
  ): ResponseDecision {
    const recommended: ResponseActionType[] = [];
    const executed: ResponseActionType[] = [];
    const audits: ResponseAuditRecord[] = [];
    let shouldCreateIncident = false;
    let incidentRecord: IncidentRecord | undefined = undefined;

    const score = scoreFactors.total_score;

    if (score < 30) {
      // Monitor only
    } else if (score < 60) {
      // 30-59: Alert only
      recommended.push('CREATE_INCIDENT');
    } else if (score < 80) {
      // 60-79: High severity
      recommended.push('CREATE_INCIDENT', 'BLOCK_IP');
      executed.push('CREATE_INCIDENT');
      shouldCreateIncident = true;
    } else {
      // 80-100: Critical severity
      recommended.push('CREATE_INCIDENT', 'BLOCK_IP', 'ISOLATE_HOST', 'ESCALATE_SOC');
      executed.push('CREATE_INCIDENT', 'BLOCK_IP', 'ISOLATE_HOST', 'ESCALATE_SOC');
      shouldCreateIncident = true;

      // In safe simulation mode, register simulated mitigation
      db.blockedIPs.add(event.source_ip);
      db.isolatedHosts.add(event.hostname);
    }

    // Generate Audit Logs for executed actions
    for (const action of executed) {
      let target = event.source_ip;
      if (action === 'ISOLATE_HOST') target = event.hostname;
      if (action === 'DISABLE_USER') target = event.username || 'unknown_user';
      if (action === 'KILL_PROCESS') target = event.process_name || 'suspicious_proc';

      const audit: ResponseAuditRecord = {
        id: generateId('aud'),
        timestamp: new Date().toISOString(),
        actor: 'PRISM-AUTO',
        action,
        target,
        reason: `Automated response rule triggered for ${scoreFactors.severity} threat (Score: ${score}/100)`,
        threat_score: score,
        mode: db.responseMode,
        result: 'SUCCESS',
        details: {
          alert_id: alert.alert_id,
          attack_type: alert.attack_type,
          simulation_notice: 'Safe simulation: no destructive system operations executed'
        }
      };

      audits.push(audit);
      db.addAudit(audit);
    }

    // Create Incident Record if required
    if (shouldCreateIncident) {
      const incId = generateId('inc');
      incidentRecord = {
        incident_id: incId,
        alert_id: alert.alert_id,
        title: `Security Incident [${scoreFactors.severity}]: ${alert.attack_type.replace('_', ' ')} detected on ${event.hostname}`,
        timestamp: new Date().toISOString(),
        severity: scoreFactors.severity,
        threat_score: score,
        status: 'NEW',
        source_ip: event.source_ip,
        hostname: event.hostname,
        attack_type: alert.attack_type,
        summary: `PRISM Automated Detection confirmed ${scoreFactors.severity} ${alert.attack_type} probing from IP ${event.source_ip} to host ${event.hostname}. Score ${score}/100. Simulated mitigations active.`,
        assigned_to: score >= 80 ? 'Alex Chen (Tier 2 SOC Escalation)' : 'Automated Triage Pool',
        actions_taken: executed,
        why_detected: scoreFactors.reasons
      };

      db.addIncident(incidentRecord);
    }

    return {
      recommended_actions: recommended,
      executed_actions: executed,
      should_create_incident: shouldCreateIncident,
      incident_record: incidentRecord,
      audit_records: audits
    };
  }

  public executeManualAction(
    action: ResponseActionType,
    target: string,
    reason: string,
    actor: 'SOC-ANALYST' | 'ADMIN' = 'SOC-ANALYST'
  ): ResponseAuditRecord {
    if (action === 'BLOCK_IP') {
      db.blockedIPs.add(target);
    } else if (action === 'ISOLATE_HOST') {
      db.isolatedHosts.add(target);
    }

    const audit: ResponseAuditRecord = {
      id: generateId('aud-manual'),
      timestamp: new Date().toISOString(),
      actor,
      action,
      target,
      reason,
      threat_score: 90,
      mode: db.responseMode,
      result: 'SUCCESS',
      details: {
        invoked_by: actor,
        simulation_notice: 'Safe simulation mode confirmed'
      }
    };

    db.addAudit(audit);
    return audit;
  }
}

export const responseEngine = new ResponseEngine();
