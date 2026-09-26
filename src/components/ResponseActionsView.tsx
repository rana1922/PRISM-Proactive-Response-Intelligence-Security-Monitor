import React, { useState, useEffect } from 'react';
import { ShieldAlert, Zap, Ban, Server, CheckCircle2, RefreshCw } from 'lucide-react';
import { ResponseAuditRecord } from '../types';
import { api } from '../services/api';

export const ResponseActionsView: React.FC = () => {
  const [audits, setAudits] = useState<ResponseAuditRecord[]>([]);
  const [targetIp, setTargetIp] = useState('');
  const [targetHost, setTargetHost] = useState('');
  const [reason, setReason] = useState('');
  const [loading, setLoading] = useState(false);
  const [feedback, setFeedback] = useState<string | null>(null);

  const fetchAudits = async () => {
    try {
      const data = await api.getAuditLog();
      setAudits(data);
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    fetchAudits();
  }, []);

  const handleSimulateBlock = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetIp) return;
    setLoading(true);
    try {
      const res = await api.blockIP(targetIp, reason || 'Manual SOC-initiated simulated IP block');
      setFeedback(res.message);
      setTargetIp('');
      setReason('');
      fetchAudits();
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleSimulateIsolate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetHost) return;
    setLoading(true);
    try {
      const res = await api.isolateHost(targetHost, reason || 'Manual SOC-initiated simulated host isolation');
      setFeedback(res.message);
      setTargetHost('');
      setReason('');
      fetchAudits();
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 rounded-lg bg-slate-900 border border-slate-800">
        <div>
          <h1 className="text-lg font-bold text-white tracking-tight flex items-center gap-2">
            <Zap className="w-4 h-4 text-rose-500" />
            <span>Response Engine & Security Audit Trail</span>
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Immutable log of all automated policy executions and manual mitigation dispatches.
          </p>
        </div>

        <button
          onClick={fetchAudits}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-mono text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 rounded border border-slate-700 transition-colors"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Refresh Audit Trail</span>
        </button>
      </div>

      {feedback && (
        <div className="p-3 bg-emerald-950/40 border border-emerald-800/60 rounded text-xs text-emerald-300 font-medium">
          {feedback}
        </div>
      )}

      {/* Manual Simulation Controls */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Simulate Block IP */}
        <form onSubmit={handleSimulateBlock} className="p-4 rounded-lg bg-slate-900/90 border border-slate-800 space-y-3 font-mono text-xs">
          <div className="flex items-center gap-2 text-white font-semibold text-sm">
            <Ban className="w-4 h-4 text-rose-400" />
            <span>Manual IP Block Simulation</span>
          </div>
          <p className="text-[11px] text-slate-400 font-sans">
            Simulates dynamic perimeter firewall rule addition to drop incoming packets from target attacker IP.
          </p>

          <div className="space-y-2">
            <input
              type="text"
              required
              value={targetIp}
              onChange={e => setTargetIp(e.target.value)}
              placeholder="Attacker IP (e.g. 185.220.101.45)"
              className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded text-slate-200 focus:outline-none focus:border-rose-500"
            />
            <input
              type="text"
              value={reason}
              onChange={e => setReason(e.target.value)}
              placeholder="Reason for block (optional)"
              className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded text-slate-200 focus:outline-none focus:border-rose-500"
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="px-3.5 py-1.5 text-xs font-semibold text-white bg-rose-600 hover:bg-rose-500 rounded transition-colors disabled:opacity-50"
          >
            Dispatch Simulated Block
          </button>
        </form>

        {/* Simulate Host Quarantine */}
        <form onSubmit={handleSimulateIsolate} className="p-4 rounded-lg bg-slate-900/90 border border-slate-800 space-y-3 font-mono text-xs">
          <div className="flex items-center gap-2 text-white font-semibold text-sm">
            <Server className="w-4 h-4 text-sky-400" />
            <span>Manual Host Quarantine Simulation</span>
          </div>
          <p className="text-[11px] text-slate-400 font-sans">
            Simulates endpoint agent network containment restricting target host to SOC management channel only.
          </p>

          <div className="space-y-2">
            <input
              type="text"
              required
              value={targetHost}
              onChange={e => setTargetHost(e.target.value)}
              placeholder="Target Hostname (e.g. web-prod-01)"
              className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded text-slate-200 focus:outline-none focus:border-sky-500"
            />
            <input
              type="text"
              value={reason}
              onChange={e => setReason(e.target.value)}
              placeholder="Reason for quarantine (optional)"
              className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded text-slate-200 focus:outline-none focus:border-sky-500"
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="px-3.5 py-1.5 text-xs font-semibold text-white bg-sky-600 hover:bg-sky-500 rounded transition-colors disabled:opacity-50"
          >
            Dispatch Simulated Quarantine
          </button>
        </form>
      </div>

      {/* Audit Log Table */}
      <div className="rounded-lg bg-slate-900/90 border border-slate-800 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="text-[11px] text-slate-500 bg-slate-950/80 border-b border-slate-800 uppercase">
              <tr>
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4">Actor</th>
                <th className="py-3 px-4">Action</th>
                <th className="py-3 px-4">Target Entity</th>
                <th className="py-3 px-4">Justification</th>
                <th className="py-3 px-4">Threat Score</th>
                <th className="py-3 px-4">Mode</th>
                <th className="py-3 px-4 text-right">Result</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {audits.map((item, idx) => (
                <tr key={`${item.id}-${idx}`} className="hover:bg-slate-800/30 transition-colors">
                  <td className="py-3 px-4 text-slate-400 tabular-nums">
                    {new Date(item.timestamp).toLocaleTimeString()}
                  </td>

                  <td className="py-3 px-4">
                    <span className={`text-[10px] px-1.5 py-0.5 rounded font-bold ${
                      item.actor === 'PRISM-AUTO'
                        ? 'bg-rose-950/50 text-rose-300 border border-rose-800/50'
                        : 'bg-sky-950/50 text-sky-300 border border-sky-800/50'
                    }`}>
                      {item.actor}
                    </span>
                  </td>

                  <td className="py-3 px-4 font-bold text-white">
                    {item.action}
                  </td>

                  <td className="py-3 px-4 text-rose-400">
                    {item.target}
                  </td>

                  <td className="py-3 px-4 text-slate-300 max-w-xs truncate">
                    {item.reason}
                  </td>

                  <td className="py-3 px-4 font-bold tabular-nums text-white">
                    {item.threat_score}/100
                  </td>

                  <td className="py-3 px-4">
                    <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                      {item.mode}
                    </span>
                  </td>

                  <td className="py-3 px-4 text-right">
                    <span className="text-emerald-400 font-bold text-[10px] flex items-center justify-end gap-1">
                      <CheckCircle2 className="w-3 h-3" />
                      <span>{item.result}</span>
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
