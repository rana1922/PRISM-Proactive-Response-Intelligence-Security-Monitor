import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  Flame, 
  AlertOctagon, 
  Ban, 
  FileText, 
  Gauge, 
  ExternalLink, 
  TrendingUp, 
  ArrowRight,
  ShieldCheck,
  RefreshCw
} from 'lucide-react';
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell,
  BarChart, Bar
} from 'recharts';
import { DashboardSummary, AlertRecord } from '../types';
import { api } from '../services/api';
import { ThreatScoreBadge } from './ThreatScoreBadge';

interface DashboardViewProps {
  summary: DashboardSummary | null;
  onViewAlertDetail: (alert: AlertRecord) => void;
  onNavigateToTab: (tab: any) => void;
}

const ATTACK_COLORS = ['#EF4444', '#F97316', '#F59E0B', '#10B981', '#6366F1', '#8B5CF6'];

export const DashboardView: React.FC<DashboardViewProps> = ({
  summary,
  onViewAlertDetail,
  onNavigateToTab
}) => {
  const [timelineData, setTimelineData] = useState<{ time: string; events: number; critical: number }[]>([]);
  const [attackStats, setAttackStats] = useState<{ name: string; raw_type: string; value: number }[]>([]);
  const [severityStats, setSeverityStats] = useState<{ severity: string; count: number; fill: string }[]>([]);
  const [topIps, setTopIps] = useState<any[]>([]);
  const [recentAlerts, setRecentAlerts] = useState<AlertRecord[]>([]);
  const [loading, setLoading] = useState(true);

  const loadData = async () => {
    try {
      const [timeline, attacks, severity, ips, alerts] = await Promise.all([
        api.getTimelineStats(),
        api.getAttackStats(),
        api.getSeverityStats(),
        api.getTopIps(),
        api.getAlerts('ALL', 'ALL', 6)
      ]);
      setTimelineData(timeline);
      setAttackStats(attacks);
      setSeverityStats(severity);
      setTopIps(ips);
      setRecentAlerts(alerts);
    } catch (err) {
      console.error('Failed to load dashboard telemetry:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 8000);
    return () => clearInterval(interval);
  }, []);

  const handleSimulateBlock = async (ip: string) => {
    try {
      await api.blockIP(ip, 'Analyst manual simulated block from Top Attack Sources');
      loadData();
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      {/* Top Bar / Status Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 rounded-lg bg-slate-900 border border-slate-800">
        <div>
          <h1 className="text-lg font-bold text-white tracking-tight">
            Security Operations Center (SOC) Command
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time threat monitoring, automated risk scoring, and zero-impact response simulation.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={loadData}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-mono text-slate-300 hover:text-white bg-slate-800/80 hover:bg-slate-800 rounded border border-slate-700 transition-colors"
          >
            <RefreshCw className={`w-3 h-3 ${loading ? 'animate-spin' : ''}`} />
            <span>Sync</span>
          </button>

          <button
            onClick={() => onNavigateToTab('simulator')}
            className="flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold text-white bg-rose-600 hover:bg-rose-500 rounded transition-colors"
          >
            <span>Launch Attack Simulator</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* 6 Top KPI Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        {/* Total Events */}
        <div className="p-3.5 rounded-lg bg-slate-900/90 border border-slate-800 space-y-1">
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>Total Events</span>
            <TrendingUp className="w-3.5 h-3.5 text-slate-500" />
          </div>
          <div className="text-xl font-bold font-mono tabular-nums text-white">
            {summary ? summary.total_events.toLocaleString() : '---'}
          </div>
          <span className="text-[10px] text-slate-500 font-mono">Normalized & indexed</span>
        </div>

        {/* Active Threats */}
        <div className="p-3.5 rounded-lg bg-slate-900/90 border border-slate-800 space-y-1">
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>Active Threats</span>
            <Flame className="w-3.5 h-3.5 text-amber-500" />
          </div>
          <div className="text-xl font-bold font-mono tabular-nums text-amber-400">
            {summary ? summary.active_threats : '---'}
          </div>
          <span className="text-[10px] text-slate-500 font-mono">Under investigation</span>
        </div>

        {/* Critical Alerts */}
        <div className="p-3.5 rounded-lg bg-slate-900/90 border border-slate-800 space-y-1">
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>Critical Alerts</span>
            <AlertOctagon className="w-3.5 h-3.5 text-rose-500" />
          </div>
          <div className="text-xl font-bold font-mono tabular-nums text-rose-400">
            {summary ? summary.critical_alerts : '---'}
          </div>
          <span className="text-[10px] text-slate-500 font-mono">Score 80–100 threshold</span>
        </div>

        {/* Blocked IPs */}
        <div className="p-3.5 rounded-lg bg-slate-900/90 border border-slate-800 space-y-1">
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>Blocked IPs</span>
            <Ban className="w-3.5 h-3.5 text-slate-400" />
          </div>
          <div className="text-xl font-bold font-mono tabular-nums text-sky-400">
            {summary ? summary.blocked_ips : '---'}
          </div>
          <span className="text-[10px] text-slate-500 font-mono">Simulated mitigations</span>
        </div>

        {/* Open Incidents */}
        <div className="p-3.5 rounded-lg bg-slate-900/90 border border-slate-800 space-y-1">
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>Open Incidents</span>
            <FileText className="w-3.5 h-3.5 text-slate-400" />
          </div>
          <div className="text-xl font-bold font-mono tabular-nums text-purple-400">
            {summary ? summary.open_incidents : '---'}
          </div>
          <span className="text-[10px] text-slate-500 font-mono">Assigned to SOC team</span>
        </div>

        {/* Average Threat Score */}
        <div className="p-3.5 rounded-lg bg-slate-900/90 border border-slate-800 space-y-1">
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>Avg Threat Score</span>
            <Gauge className="w-3.5 h-3.5 text-rose-500" />
          </div>
          <div className="text-xl font-bold font-mono tabular-nums text-rose-400">
            {summary ? summary.average_threat_score : '---'}
            <span className="text-xs font-normal text-slate-500">/100</span>
          </div>
          <span className="text-[10px] text-slate-500 font-mono">Explainable aggregate</span>
        </div>
      </div>

      {/* Row 2: Charts (Threat Timeline, Attack Distribution, Severity) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Threat Timeline (7 cols) */}
        <div className="lg:col-span-7 p-4 rounded-lg bg-slate-900/90 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
              Threat Event Ingestion Velocity
            </h3>
            <span className="text-[11px] text-slate-500 font-mono">Past 2 Hours</span>
          </div>
          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={timelineData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="eventColor" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#6366f1" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#6366f1" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="critColor" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.6} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" stroke="#475569" tick={{ fontSize: 10 }} />
                <YAxis stroke="#475569" tick={{ fontSize: 10 }} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', fontSize: '11px', borderRadius: '4px' }}
                  itemStyle={{ color: '#e2e8f0' }}
                />
                <Area type="monotone" dataKey="events" stroke="#6366f1" fillOpacity={1} fill="url(#eventColor)" name="Total Events" />
                <Area type="monotone" dataKey="critical" stroke="#ef4444" fillOpacity={1} fill="url(#critColor)" name="Critical Spikes" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Attack Distribution (5 cols) */}
        <div className="lg:col-span-5 p-4 rounded-lg bg-slate-900/90 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
              Attack Vector Distribution
            </h3>
            <span className="text-[11px] text-slate-500 font-mono">By Category</span>
          </div>

          <div className="h-56 w-full flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={attackStats}
                  cx="50%"
                  cy="50%"
                  innerRadius={45}
                  outerRadius={75}
                  paddingAngle={3}
                  dataKey="value"
                >
                  {attackStats.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={ATTACK_COLORS[index % ATTACK_COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip 
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', fontSize: '11px', borderRadius: '4px' }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>

          <div className="flex flex-wrap justify-center gap-x-4 gap-y-1 text-[11px] font-mono">
            {attackStats.map((item, idx) => (
              <div key={item.name} className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full" style={{ backgroundColor: ATTACK_COLORS[idx % ATTACK_COLORS.length] }} />
                <span className="text-slate-400">{item.name}</span>
                <span className="text-slate-200 font-bold">({item.value})</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Row 3: Top Attack Sources Table & Live Recent Alerts Feed */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Top Attack Sources (7 cols) */}
        <div className="lg:col-span-7 p-4 rounded-lg bg-slate-900/90 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
              Top Attack Sources (Autonomous Correlated)
            </h3>
            <span className="text-[11px] text-slate-500 font-mono">Ranked by Risk Score</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="text-[11px] text-slate-500 border-b border-slate-800 uppercase">
                <tr>
                  <th className="pb-2">IP Address</th>
                  <th className="pb-2 text-right">Attacks</th>
                  <th className="pb-2 text-right">Peak Score</th>
                  <th className="pb-2">Threat Level</th>
                  <th className="pb-2 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {topIps.map(ip => (
                  <tr key={ip.ip_address} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-2.5 font-medium text-rose-400">
                      {ip.ip_address}
                    </td>
                    <td className="py-2.5 text-right tabular-nums text-slate-300">
                      {ip.attack_count}
                    </td>
                    <td className="py-2.5 text-right tabular-nums font-bold text-white">
                      {ip.highest_score}
                    </td>
                    <td className="py-2.5">
                      <span className={`text-[10px] px-1.5 py-0.5 rounded border ${
                        ip.threat_level === 'CRITICAL'
                          ? 'bg-rose-950/40 text-rose-300 border-rose-800/40'
                          : ip.threat_level === 'HIGH'
                          ? 'bg-amber-950/40 text-amber-300 border-amber-800/40'
                          : 'bg-yellow-950/30 text-yellow-300 border-yellow-800/40'
                      }`}>
                        {ip.threat_level}
                      </span>
                    </td>
                    <td className="py-2.5 text-right">
                      {ip.is_blocked ? (
                        <span className="text-[10px] text-emerald-400 font-medium bg-emerald-950/30 px-2 py-0.5 rounded border border-emerald-800/40">
                          BLOCKED
                        </span>
                      ) : (
                        <button
                          onClick={() => handleSimulateBlock(ip.ip_address)}
                          className="px-2 py-0.5 text-[10px] text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 rounded border border-slate-700 transition-colors"
                        >
                          Simulate Block
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Live Alerts Stream Snippet (5 cols) */}
        <div className="lg:col-span-5 p-4 rounded-lg bg-slate-900/90 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse" />
              <span>Real-Time Alert Feed</span>
            </h3>
            <button
              onClick={() => onNavigateToTab('alerts')}
              className="text-xs text-rose-400 hover:text-rose-300 flex items-center gap-1 font-medium"
            >
              <span>View All</span>
              <ArrowRight className="w-3 h-3" />
            </button>
          </div>

          <div className="space-y-2.5">
            {recentAlerts.map(alert => (
              <div
                key={alert.alert_id}
                onClick={() => onViewAlertDetail(alert)}
                className="p-3 rounded bg-slate-950/60 border border-slate-800/80 hover:border-slate-700 transition-all cursor-pointer space-y-1.5 text-xs font-mono"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="text-white font-semibold">{alert.attack_type.replace('_', ' ')}</span>
                    <span className={`text-[10px] px-1.5 py-0.5 rounded border ${
                      alert.severity === 'CRITICAL'
                        ? 'bg-rose-950/40 text-rose-400 border-rose-800/40'
                        : alert.severity === 'HIGH'
                        ? 'bg-amber-950/40 text-amber-400 border-amber-800/40'
                        : 'bg-yellow-950/30 text-yellow-400 border-yellow-800/40'
                    }`}>
                      {alert.severity}
                    </span>
                  </div>
                  <ThreatScoreBadge score={alert.threat_score} severity={alert.severity} size="sm" showLabel={false} />
                </div>

                <div className="flex items-center justify-between text-[11px] text-slate-400">
                  <span>Src: {alert.source_ip} &rarr; {alert.hostname}</span>
                  <span className="text-slate-500">{new Date(alert.timestamp).toLocaleTimeString()}</span>
                </div>

                <div className="flex items-center gap-2 text-[10px] text-slate-500 pt-0.5">
                  <span>IOC: {alert.ioc_match ? 'MATCH' : 'NONE'}</span>
                  <span>·</span>
                  <span>CVE: {alert.cve_match ? 'CORRELATED' : 'NONE'}</span>
                  <span>·</span>
                  <span className="text-rose-400">
                    {alert.executed_actions[0] || 'MONITORED'}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
