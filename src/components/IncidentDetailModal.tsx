import React, { useState } from 'react';
import { X, CheckCircle, ShieldAlert, AlertTriangle, Server, Network, UserCheck, ShieldOff, Zap, ExternalLink } from 'lucide-react';
import { AlertRecord, IncidentRecord } from '../types';
import { ThreatScoreBadge } from './ThreatScoreBadge';
import { api } from '../services/api';

interface IncidentDetailModalProps {
  alert: AlertRecord | null;
  incident?: IncidentRecord | null;
  onClose: () => void;
  onAlertUpdated: (updatedAlert: AlertRecord) => void;
}

export const IncidentDetailModal: React.FC<IncidentDetailModalProps> = ({
  alert,
  incident,
  onClose,
  onAlertUpdated
}) => {
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [feedbackMessage, setFeedbackMessage] = useState<string | null>(null);

  if (!alert) return null;

  const handleResolve = async () => {
    setActionLoading('resolve');
    try {
      const res = await api.resolveAlert(alert.alert_id);
      onAlertUpdated(res.alert);
      setFeedbackMessage('Incident and alert resolved.');
    } catch (err) {
      console.error(err);
    } finally {
      setActionLoading(null);
    }
  };

  const handleFalsePositive = async () => {
    setActionLoading('fp');
    try {
      const res = await api.markFalsePositive(alert.alert_id);
      onAlertUpdated(res.alert);
      setFeedbackMessage('Alert marked as false positive.');
    } catch (err) {
      console.error(err);
    } finally {
      setActionLoading(null);
    }
  };

  const handleManualBlock = async () => {
    setActionLoading('block');
    try {
      await api.blockIP(alert.source_ip, `Analyst simulated block from incident ${alert.alert_id}`);
      setFeedbackMessage(`Simulated IP block executed for ${alert.source_ip}`);
    } catch (err) {
      console.error(err);
    } finally {
      setActionLoading(null);
    }
  };

  const handleManualIsolate = async () => {
    setActionLoading('isolate');
    try {
      await api.isolateHost(alert.hostname, `Analyst simulated quarantine for host ${alert.hostname}`);
      setFeedbackMessage(`Simulated host quarantine executed for ${alert.hostname}`);
    } catch (err) {
      console.error(err);
    } finally {
      setActionLoading(null);
    }
  };

  const scoreFactors = alert.score_factors;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-in fade-in duration-200">
      <div 
        className="relative w-full max-w-4xl max-h-[90vh] overflow-y-auto bg-slate-900 border border-slate-800 rounded-lg shadow-2xl text-slate-200"
        role="dialog"
        aria-modal="true"
      >
        {/* Modal Header */}
        <div className="sticky top-0 z-10 flex items-center justify-between px-6 py-4 bg-slate-900/95 backdrop-blur border-b border-slate-800">
          <div className="flex items-center gap-3">
            <span className="font-mono text-xs text-rose-400 font-semibold tracking-wider uppercase">
              {alert.alert_id}
            </span>
            <span aria-hidden="true" className="text-slate-600">·</span>
            <h2 className="text-base font-semibold text-white">
              {alert.attack_type.replace('_', ' ')} Incident Analysis
            </h2>
            <span className={`text-[11px] font-mono px-2 py-0.5 rounded border ${
              alert.status === 'RESOLVED' 
                ? 'bg-emerald-950/40 text-emerald-400 border-emerald-800/40' 
                : alert.status === 'FALSE_POSITIVE'
                ? 'bg-slate-800 text-slate-400 border-slate-700'
                : 'bg-rose-950/40 text-rose-400 border-rose-800/40'
            }`}>
              {alert.status}
            </span>
          </div>

          <button
            onClick={onClose}
            className="p-1 text-slate-400 hover:text-white rounded hover:bg-slate-800 transition-colors"
            aria-label="Close dialog"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {feedbackMessage && (
          <div className="mx-6 mt-4 p-3 bg-emerald-950/40 border border-emerald-800/60 rounded text-xs text-emerald-300 font-medium">
            {feedbackMessage}
          </div>
        )}

        <div className="p-6 space-y-6">
          {/* Section 1: Top Overview & Score Breakdown */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 p-4 rounded-lg bg-slate-950/60 border border-slate-800/80">
            <div className="flex flex-col justify-center items-start md:border-r border-slate-800/80 md:pr-4">
              <span className="text-xs text-slate-400 mb-2">Overall Threat Score</span>
              <ThreatScoreBadge score={alert.threat_score} severity={alert.severity} size="lg" />
            </div>

            <div className="space-y-2 md:col-span-2 text-xs">
              <span className="text-slate-400 uppercase tracking-wider font-semibold">Incident Telemetry Target</span>
              <div className="grid grid-cols-2 gap-y-2 gap-x-4 pt-1 font-mono">
                <div>
                  <span className="text-slate-500 block">Attacker IP:</span>
                  <span className="text-rose-400 font-medium">{alert.source_ip}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Target Host:</span>
                  <span className="text-slate-200">{alert.hostname}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Destination IP:</span>
                  <span className="text-slate-300">{alert.destination_ip}:{alert.destination_port || 443}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Timestamp:</span>
                  <span className="text-slate-300 tabular-nums">{new Date(alert.timestamp).toLocaleString()}</span>
                </div>
              </div>

              {alert.url && (
                <div className="pt-2">
                  <span className="text-slate-500 block font-mono text-[11px]">Request Path:</span>
                  <code className="text-[11px] text-amber-300 bg-slate-900 px-2 py-0.5 rounded border border-slate-800 break-all block mt-0.5">
                    {alert.url}
                  </code>
                </div>
              )}
            </div>
          </div>

          {/* Section 2: Why PRISM Detected This (Explainable Score Breakdown) */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <CheckCircle className="w-4 h-4 text-emerald-400" />
                <span>Explainable Detection Intelligence</span>
              </h3>
              <span className="text-xs text-slate-400 font-mono">
                Formula: Attack + IOC + CVE + Asset + Confidence = {alert.threat_score}/100
              </span>
            </div>

            <div className="p-4 rounded-lg bg-slate-950/40 border border-slate-800 space-y-3">
              <div className="grid grid-cols-1 sm:grid-cols-5 gap-3 text-xs">
                <div className="p-2.5 rounded bg-slate-900/80 border border-slate-800">
                  <div className="text-slate-400 text-[11px]">Base Attack</div>
                  <div className="text-lg font-mono font-bold text-rose-400 mt-1">+{scoreFactors.attack_score}</div>
                  <div className="text-[11px] text-slate-500 truncate">{alert.attack_type}</div>
                </div>

                <div className="p-2.5 rounded bg-slate-900/80 border border-slate-800">
                  <div className="text-slate-400 text-[11px]">IOC Match</div>
                  <div className="text-lg font-mono font-bold text-amber-400 mt-1">+{scoreFactors.ioc_score}</div>
                  <div className="text-[11px] text-slate-500 truncate">{scoreFactors.ioc_matched ? 'Confirmed' : 'None'}</div>
                </div>

                <div className="p-2.5 rounded bg-slate-900/80 border border-slate-800">
                  <div className="text-slate-400 text-[11px]">CVE Match</div>
                  <div className="text-lg font-mono font-bold text-amber-400 mt-1">+{scoreFactors.cve_score}</div>
                  <div className="text-[11px] text-slate-500 truncate">{scoreFactors.cve_matched ? 'Correlated' : 'None'}</div>
                </div>

                <div className="p-2.5 rounded bg-slate-900/80 border border-slate-800">
                  <div className="text-slate-400 text-[11px]">Asset Criticality</div>
                  <div className="text-lg font-mono font-bold text-sky-400 mt-1">+{scoreFactors.asset_score}</div>
                  <div className="text-[11px] text-slate-500 truncate">{alert.hostname}</div>
                </div>

                <div className="p-2.5 rounded bg-slate-900/80 border border-slate-800">
                  <div className="text-slate-400 text-[11px]">Confidence</div>
                  <div className="text-lg font-mono font-bold text-emerald-400 mt-1">+{scoreFactors.confidence_score}</div>
                  <div className="text-[11px] text-slate-500 truncate">{scoreFactors.confidence_pct}% rule conf</div>
                </div>
              </div>

              {/* Checklist reasons */}
              <div className="pt-2 border-t border-slate-800/80 space-y-1.5 text-xs">
                <span className="text-slate-400 block font-medium">Detection Validation Trace:</span>
                {scoreFactors.reasons.map((reason: string, idx: number) => (
                  <div key={idx} className="flex items-center gap-2 text-slate-300">
                    <span className="text-emerald-400">✓</span>
                    <span>{reason}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Section 3: Threat Intelligence Correlation */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* IOC Card */}
            <div className="p-4 rounded-lg bg-slate-950/40 border border-slate-800 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                  <Network className="w-3.5 h-3.5 text-amber-400" />
                  <span>IOC Intelligence</span>
                </span>
                <span className={`text-[11px] font-mono px-2 py-0.5 rounded border ${
                  alert.ioc_match 
                    ? 'bg-rose-950/40 text-rose-300 border-rose-800/40' 
                    : 'bg-slate-800/40 text-slate-400 border-slate-700/40'
                }`}>
                  {alert.ioc_match ? 'MATCH CONFIRMED' : 'NO IOC MATCH'}
                </span>
              </div>

              {alert.ioc_details ? (
                <div className="space-y-1.5 text-xs font-mono pt-1">
                  <div>
                    <span className="text-slate-500">Indicator:</span>{' '}
                    <span className="text-slate-200">{alert.ioc_details.ioc}</span>
                  </div>
                  <div>
                    <span className="text-slate-500">Reputation Level:</span>{' '}
                    <span className="text-rose-400 uppercase font-semibold">{alert.ioc_details.threat_level}</span>
                  </div>
                  <div>
                    <span className="text-slate-500">Source Provider:</span>{' '}
                    <span className="text-slate-300">{alert.ioc_details.source}</span>
                  </div>
                  <div>
                    <span className="text-slate-500">Threat Confidence:</span>{' '}
                    <span className="text-slate-300">{alert.ioc_details.confidence}%</span>
                  </div>
                </div>
              ) : (
                <p className="text-xs text-slate-500 pt-1">
                  IP not currently listed on high-severity global blocklists.
                </p>
              )}
            </div>

            {/* CVE Card */}
            <div className="p-4 rounded-lg bg-slate-950/40 border border-slate-800 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
                  <Server className="w-3.5 h-3.5 text-sky-400" />
                  <span>CVE Vulnerability Correlation</span>
                </span>
                <span className={`text-[11px] font-mono px-2 py-0.5 rounded border ${
                  alert.cve_match 
                    ? 'bg-rose-950/40 text-rose-300 border-rose-800/40' 
                    : 'bg-slate-800/40 text-slate-400 border-slate-700/40'
                }`}>
                  {alert.cve_match ? 'CVE CORRELATED' : 'NO KNOWN CVE'}
                </span>
              </div>

              {alert.cve_details ? (
                <div className="space-y-1.5 text-xs font-mono pt-1">
                  <div className="flex items-center justify-between">
                    <div>
                      <span className="text-slate-500">Vulnerability:</span>{' '}
                      <span className="text-rose-400 font-semibold">{alert.cve_details.cve_id}</span>
                    </div>
                    <span className="px-1.5 py-0.5 bg-rose-950/60 border border-rose-800 text-rose-400 text-[10px] rounded font-bold">
                      CVSS {alert.cve_details.cvss_score}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-500">Affected Product:</span>{' '}
                    <span className="text-slate-300">{alert.cve_details.affected_product}</span>
                  </div>
                  <div>
                    <span className="text-slate-500">Severity Tier:</span>{' '}
                    <span className="text-rose-400 uppercase font-semibold">{alert.cve_details.severity}</span>
                  </div>
                </div>
              ) : (
                <p className="text-xs text-slate-500 pt-1">
                  No direct NVD unpatched vulnerability mapped for this attack vector.
                </p>
              )}
            </div>
          </div>

          {/* Section 4: Automated Response Actions & Execution */}
          <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-white flex items-center gap-1.5">
                <Zap className="w-4 h-4 text-rose-400" />
                <span>Response Mitigation Pipeline</span>
              </span>
              <span className="text-[11px] font-mono text-emerald-400 bg-emerald-950/30 px-2 py-0.5 rounded border border-emerald-800/40">
                SAFE SIMULATION MODE ENFORCED
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs font-mono">
              <div className="p-3 bg-slate-900 rounded border border-slate-800">
                <span className="text-slate-400 block text-[11px] uppercase tracking-wider mb-1">
                  Recommended Policy:
                </span>
                <div className="flex flex-wrap gap-1.5">
                  {alert.recommended_actions.length > 0 ? (
                    alert.recommended_actions.map((act: string) => (
                      <span key={act} className="px-2 py-0.5 bg-slate-800 text-slate-200 rounded border border-slate-700 text-[11px]">
                        {act}
                      </span>
                    ))
                  ) : (
                    <span className="text-slate-500">MONITOR_ONLY</span>
                  )}
                </div>
              </div>

              <div className="p-3 bg-slate-900 rounded border border-slate-800">
                <span className="text-slate-400 block text-[11px] uppercase tracking-wider mb-1">
                  Executed Response Actions:
                </span>
                <div className="flex flex-wrap gap-1.5">
                  {alert.executed_actions.length > 0 ? (
                    alert.executed_actions.map((act: string) => (
                      <span key={act} className="px-2 py-0.5 bg-rose-950/50 text-rose-300 rounded border border-rose-800/50 text-[11px] font-bold">
                        {act} (SIMULATED)
                      </span>
                    ))
                  ) : (
                    <span className="text-slate-500">NO AUTOMATED EXECUTION</span>
                  )}
                </div>
              </div>
            </div>

            <p className="text-[11px] text-slate-500">
              Note: Because PRISM is running in safe simulation mode, firewall and network isolation rules are registered in the PRISM Security State and Audit Log without disrupting active host networking.
            </p>
          </div>
        </div>

        {/* Modal Footer with Actions */}
        <div className="sticky bottom-0 z-10 flex flex-wrap items-center justify-between gap-3 px-6 py-4 bg-slate-900 border-t border-slate-800">
          <div className="flex items-center gap-2">
            <button
              onClick={handleManualBlock}
              disabled={actionLoading !== null}
              className="px-3 py-1.5 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 rounded border border-slate-700 transition-colors disabled:opacity-50"
            >
              Simulate Block IP
            </button>
            <button
              onClick={handleManualIsolate}
              disabled={actionLoading !== null}
              className="px-3 py-1.5 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 rounded border border-slate-700 transition-colors disabled:opacity-50"
            >
              Simulate Isolate Host
            </button>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleFalsePositive}
              disabled={actionLoading !== null || alert.status === 'FALSE_POSITIVE'}
              className="px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-white bg-slate-800/60 hover:bg-slate-800 rounded border border-slate-700 transition-colors disabled:opacity-50"
            >
              Mark False Positive
            </button>
            <button
              onClick={handleResolve}
              disabled={actionLoading !== null || alert.status === 'RESOLVED'}
              className="px-3.5 py-1.5 text-xs font-medium text-white bg-emerald-700 hover:bg-emerald-600 rounded transition-colors disabled:opacity-50"
            >
              Resolve Incident
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
