import React, { useState, useEffect } from 'react';
import { FileText, ShieldAlert, CheckCircle, Clock, User, ArrowRight, RefreshCw } from 'lucide-react';
import { IncidentRecord, AlertRecord } from '../types';
import { api } from '../services/api';
import { ThreatScoreBadge } from './ThreatScoreBadge';

interface IncidentsViewProps {
  onViewAlertDetail: (alert: AlertRecord) => void;
}

export const IncidentsView: React.FC<IncidentsViewProps> = ({
  onViewAlertDetail
}) => {
  const [incidents, setIncidents] = useState<IncidentRecord[]>([]);
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [loading, setLoading] = useState(true);

  const fetchIncidents = async () => {
    try {
      const data = await api.getIncidents(statusFilter);
      setIncidents(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
  }, [statusFilter]);

  const handleOpenIncident = async (incident: IncidentRecord) => {
    try {
      const detail = await api.getIncidentDetail(incident.incident_id);
      if (detail.related_alert) {
        onViewAlertDetail(detail.related_alert);
      }
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 rounded-lg bg-slate-900 border border-slate-800">
        <div>
          <h1 className="text-lg font-bold text-white tracking-tight flex items-center gap-2">
            <FileText className="w-4 h-4 text-purple-400" />
            <span>SOC Incident Case Management</span>
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Active and resolved critical security cases escalated from high-confidence correlations.
          </p>
        </div>

        <button
          onClick={fetchIncidents}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-mono text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-750 rounded border border-slate-700 transition-colors"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh Cases</span>
        </button>
      </div>

      {/* Status Segmented Filter */}
      <div className="flex items-center gap-1 p-1 bg-slate-950 rounded border border-slate-800 w-fit text-xs font-mono">
        {['ALL', 'NEW', 'INVESTIGATING', 'CONTAINED', 'RESOLVED'].map(st => (
          <button
            key={st}
            onClick={() => setStatusFilter(st)}
            className={`px-3 py-1.5 rounded transition-colors ${
              statusFilter === st
                ? 'bg-slate-800 text-white font-bold shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            {st}
          </button>
        ))}
      </div>

      {/* Incidents Table */}
      <div className="rounded-lg bg-slate-900/90 border border-slate-800 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="text-[11px] text-slate-500 bg-slate-950/80 border-b border-slate-800 uppercase">
              <tr>
                <th className="py-3 px-4">Incident ID</th>
                <th className="py-3 px-4">Severity & Score</th>
                <th className="py-3 px-4">Title & Attack Type</th>
                <th className="py-3 px-4">Target Host / IP</th>
                <th className="py-3 px-4">Assigned Analyst</th>
                <th className="py-3 px-4">Actions Taken</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4 text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {incidents.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-500 text-xs">
                    No incidents found matching current status filter.
                  </td>
                </tr>
              ) : (
                incidents.map(inc => (
                  <tr
                    key={inc.incident_id}
                    onClick={() => handleOpenIncident(inc)}
                    className="hover:bg-slate-800/40 transition-colors cursor-pointer group"
                  >
                    <td className="py-3.5 px-4 font-bold text-rose-400">
                      {inc.incident_id}
                    </td>

                    <td className="py-3.5 px-4">
                      <ThreatScoreBadge score={inc.threat_score} severity={inc.severity} size="sm" showLabel={true} />
                    </td>

                    <td className="py-3.5 px-4">
                      <div className="text-white font-semibold group-hover:text-rose-400 transition-colors">
                        {inc.attack_type.replace('_', ' ')}
                      </div>
                      <div className="text-[10px] text-slate-400 truncate max-w-xs">
                        {inc.title}
                      </div>
                    </td>

                    <td className="py-3.5 px-4">
                      <div className="text-slate-200">{inc.hostname}</div>
                      <div className="text-[10px] text-rose-400">{inc.source_ip}</div>
                    </td>

                    <td className="py-3.5 px-4 text-slate-300">
                      <div className="flex items-center gap-1.5">
                        <User className="w-3 h-3 text-slate-500" />
                        <span>{inc.assigned_to}</span>
                      </div>
                    </td>

                    <td className="py-3.5 px-4">
                      <div className="flex flex-wrap gap-1">
                        {inc.actions_taken.map((act: string) => (
                          <span key={act} className="text-[10px] px-1.5 py-0.5 rounded bg-rose-950/40 border border-rose-800/40 text-rose-300 font-bold">
                            {act} (SIM)
                          </span>
                        ))}
                      </div>
                    </td>

                    <td className="py-3.5 px-4">
                      <span className={`text-[10px] px-1.5 py-0.5 rounded border ${
                        inc.status === 'RESOLVED'
                          ? 'bg-emerald-950/40 text-emerald-400 border-emerald-800/40'
                          : 'bg-rose-950/40 text-rose-400 border-rose-800/40'
                      }`}>
                        {inc.status}
                      </span>
                    </td>

                    <td className="py-3.5 px-4 text-right">
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
