import React, { useState, useEffect } from 'react';
import { 
  Radio, 
  Filter, 
  Search, 
  CheckCircle, 
  AlertTriangle, 
  Volume2, 
  VolumeX, 
  ArrowUpDown,
  ExternalLink,
  RefreshCw
} from 'lucide-react';
import { AlertRecord, SeverityLevel, AlertStatus } from '../types';
import { ThreatScoreBadge } from './ThreatScoreBadge';
import { api } from '../services/api';

interface LiveAlertsViewProps {
  onViewAlertDetail: (alert: AlertRecord) => void;
}

export const LiveAlertsView: React.FC<LiveAlertsViewProps> = ({
  onViewAlertDetail
}) => {
  const [alerts, setAlerts] = useState<AlertRecord[]>([]);
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [isPaused, setIsPaused] = useState(false);
  const [audioChime, setAudioChime] = useState(false);
  const [loading, setLoading] = useState(true);

  const fetchAlerts = async () => {
    try {
      const data = await api.getAlerts(severityFilter, statusFilter, 100);
      setAlerts(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
  }, [severityFilter, statusFilter]);

  // Connect to SSE stream for live real-time feed
  useEffect(() => {
    let eventSource: EventSource | null = null;
    try {
      eventSource = new EventSource('/api/stream/alerts');

      eventSource.onmessage = (event) => {
        if (isPaused) return;
        try {
          const data = JSON.parse(event.data);
          if (data.type === 'ALERT_CREATED' && data.payload?.alert) {
            const newAlert: AlertRecord = data.payload.alert;
            setAlerts((prev) => {
              // Deduplicate
              if (prev.some(a => a.alert_id === newAlert.alert_id)) return prev;
              return [newAlert, ...prev];
            });
            if (audioChime && newAlert.severity === 'CRITICAL') {
              playChime();
            }
          } else if (data.type === 'ALERT_UPDATED' && data.payload?.alert) {
            const updated = data.payload.alert;
            setAlerts((prev) => prev.map(a => a.alert_id === updated.alert_id ? updated : a));
          }
        } catch {
          // ignore non-json
        }
      };
    } catch (err) {
      console.error('SSE connection error:', err);
    }

    return () => {
      if (eventSource) {
        eventSource.close();
      }
    };
  }, [isPaused, audioChime]);

  const playChime = () => {
    try {
      const ctx = new (window.AudioContext || (window as any).webkitAudioContext)();
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.type = 'sine';
      osc.frequency.setValueAtTime(880, ctx.currentTime);
      gain.gain.setValueAtTime(0.05, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + 0.3);
      osc.start();
      osc.stop(ctx.currentTime + 0.3);
    } catch {
      // AudioContext may be blocked before interaction
    }
  };

  const seenAlertIds = new Set<string>();
  const uniqueFilteredAlerts = alerts
    .filter(a => {
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        const match = a.source_ip.toLowerCase().includes(q) ||
                      a.hostname.toLowerCase().includes(q) ||
                      a.attack_type.toLowerCase().includes(q) ||
                      a.alert_id.toLowerCase().includes(q);
        if (!match) return false;
      }
      return true;
    })
    .filter(a => {
      if (seenAlertIds.has(a.alert_id)) return false;
      seenAlertIds.add(a.alert_id);
      return true;
    });

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      {/* View Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 rounded-lg bg-slate-900 border border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <Radio className="w-4 h-4 text-rose-500 animate-pulse" />
            <h1 className="text-lg font-bold text-white tracking-tight">
              Live SOC Alert Feed
            </h1>
            <span className="font-mono text-xs text-slate-400">
              ({uniqueFilteredAlerts.length} events active)
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Streaming autonomous incident correlations without page refresh.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {/* Audio Chime toggle */}
          <button
            onClick={() => setAudioChime(!audioChime)}
            className={`p-2 rounded border text-xs transition-colors ${
              audioChime 
                ? 'bg-rose-950/40 border-rose-700/60 text-rose-300' 
                : 'bg-slate-800 border-slate-700 text-slate-400 hover:text-white'
            }`}
            title={audioChime ? "Alert chime enabled" : "Alert chime disabled"}
          >
            {audioChime ? <Volume2 className="w-4 h-4" /> : <VolumeX className="w-4 h-4" />}
          </button>

          {/* Pause stream toggle */}
          <button
            onClick={() => setIsPaused(!isPaused)}
            className={`px-3 py-1.5 rounded border text-xs font-mono font-medium transition-colors ${
              isPaused
                ? 'bg-amber-950/40 border-amber-700 text-amber-300'
                : 'bg-slate-800 border-slate-700 text-slate-300 hover:text-white'
            }`}
          >
            {isPaused ? 'STREAM PAUSED' : 'LIVE STREAM ACTIVE'}
          </button>

          <button
            onClick={fetchAlerts}
            className="p-2 rounded bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 transition-colors"
            title="Refresh alerts"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Filter Controls (Segmented Tabs / Inputs) */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-3 rounded-lg bg-slate-900/80 border border-slate-800 text-xs">
        {/* Severity Filter Tabs */}
        <div className="flex items-center gap-1 p-1 bg-slate-950 rounded border border-slate-800">
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={`px-2.5 py-1 rounded text-xs font-mono font-medium transition-colors ${
                severityFilter === sev
                  ? 'bg-slate-800 text-white font-bold shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {sev}
            </button>
          ))}
        </div>

        {/* Status Filter */}
        <div className="flex items-center gap-1 p-1 bg-slate-950 rounded border border-slate-800">
          {['ALL', 'NEW', 'INVESTIGATING', 'CONTAINED', 'RESOLVED'].map(st => (
            <button
              key={st}
              onClick={() => setStatusFilter(st)}
              className={`px-2.5 py-1 rounded text-xs font-mono font-medium transition-colors ${
                statusFilter === st
                  ? 'bg-slate-800 text-white font-bold shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {st}
            </button>
          ))}
        </div>

        {/* Search Input */}
        <div className="relative min-w-[200px]">
          <Search className="absolute left-2.5 top-2.5 w-3.5 h-3.5 text-slate-500" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search IP, Host, Rule..."
            className="w-full pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-700/80 rounded text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-rose-500 font-mono"
          />
        </div>
      </div>

      {/* Alerts Table / Feed */}
      <div className="rounded-lg bg-slate-900/90 border border-slate-800 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="text-[11px] text-slate-500 bg-slate-950/80 border-b border-slate-800 uppercase">
              <tr>
                <th className="py-3 px-4">Threat Score</th>
                <th className="py-3 px-4">Alert ID & Attack</th>
                <th className="py-3 px-4">Attacker IP</th>
                <th className="py-3 px-4">Target Host</th>
                <th className="py-3 px-4">Correlations</th>
                <th className="py-3 px-4">Simulated Action</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {uniqueFilteredAlerts.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-500 text-xs">
                    No security alerts found matching the current filter criteria.
                  </td>
                </tr>
              ) : (
                uniqueFilteredAlerts.map((alert, idx) => (
                  <tr
                    key={`${alert.alert_id}-${idx}`}
                    onClick={() => onViewAlertDetail(alert)}
                    className="hover:bg-slate-800/40 transition-colors cursor-pointer group"
                  >
                    <td className="py-3 px-4">
                      <ThreatScoreBadge score={alert.threat_score} severity={alert.severity} size="sm" showLabel={true} />
                    </td>

                    <td className="py-3 px-4">
                      <div className="font-semibold text-white group-hover:text-rose-400 transition-colors">
                        {alert.attack_type.replace('_', ' ')}
                      </div>
                      <div className="text-[10px] text-slate-500">
                        {alert.alert_id} · {new Date(alert.timestamp).toLocaleTimeString()}
                      </div>
                    </td>

                    <td className="py-3 px-4 font-medium text-rose-400">
                      {alert.source_ip}
                    </td>

                    <td className="py-3 px-4 text-slate-300">
                      {alert.hostname}
                    </td>

                    <td className="py-3 px-4">
                      <div className="flex items-center gap-1.5 text-[10px]">
                        <span className={`px-1.5 py-0.5 rounded border ${
                          alert.ioc_match 
                            ? 'bg-rose-950/40 text-rose-300 border-rose-800/40 font-bold' 
                            : 'bg-slate-800/40 text-slate-500 border-slate-700/40'
                        }`}>
                          IOC: {alert.ioc_match ? 'YES' : 'NO'}
                        </span>
                        <span className={`px-1.5 py-0.5 rounded border ${
                          alert.cve_match 
                            ? 'bg-rose-950/40 text-rose-300 border-rose-800/40 font-bold' 
                            : 'bg-slate-800/40 text-slate-500 border-slate-700/40'
                        }`}>
                          CVE: {alert.cve_match ? 'YES' : 'NO'}
                        </span>
                      </div>
                    </td>

                    <td className="py-3 px-4">
                      <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300 font-semibold">
                        {alert.executed_actions[0] ? `${alert.executed_actions[0]} (SIM)` : 'MONITORED'}
                      </span>
                    </td>

                    <td className="py-3 px-4">
                      <span className={`text-[10px] px-1.5 py-0.5 rounded border ${
                        alert.status === 'RESOLVED' 
                          ? 'bg-emerald-950/40 text-emerald-400 border-emerald-800/40' 
                          : alert.status === 'FALSE_POSITIVE'
                          ? 'bg-slate-800 text-slate-400 border-slate-700'
                          : 'bg-rose-950/30 text-rose-400 border-rose-800/40'
                      }`}>
                        {alert.status}
                      </span>
                    </td>

                    <td className="py-3 px-4 text-right">
                      <span className="text-slate-400 group-hover:text-white transition-colors text-xs">
                        &rarr;
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
