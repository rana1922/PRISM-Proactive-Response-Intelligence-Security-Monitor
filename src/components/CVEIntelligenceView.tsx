import React, { useState, useEffect } from 'react';
import { Server, RefreshCw, ExternalLink, ShieldCheck, AlertCircle, Search } from 'lucide-react';
import { CVERecord } from '../types';
import { api } from '../services/api';

export const CVEIntelligenceView: React.FC = () => {
  const [cves, setCves] = useState<CVERecord[]>([]);
  const [search, setSearch] = useState('');
  const [syncing, setSyncing] = useState(false);
  const [syncFeedback, setSyncFeedback] = useState<string | null>(null);

  const fetchCves = async () => {
    try {
      const data = await api.getCVEs();
      setCves(data);
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    fetchCves();
  }, []);

  const handleSyncNVD = async () => {
    setSyncing(true);
    setSyncFeedback(null);
    try {
      const res = await api.syncCVEs();
      setSyncFeedback(res.message);
      fetchCves();
    } catch (err) {
      console.error(err);
      setSyncFeedback('NVD sync failed; using cached advisories.');
    } finally {
      setSyncing(false);
    }
  };

  const filteredCves = cves.filter(item => {
    if (search) {
      const q = search.toLowerCase();
      return item.cve_id.toLowerCase().includes(q) ||
             item.affected_product.toLowerCase().includes(q) ||
             item.description.toLowerCase().includes(q);
    }
    return true;
  });

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 rounded-lg bg-slate-900 border border-slate-800">
        <div>
          <h1 className="text-lg font-bold text-white tracking-tight flex items-center gap-2">
            <Server className="w-4 h-4 text-sky-400" />
            <span>CVE Vulnerability Intelligence Feed</span>
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Cross-referenced CVE records matched against target asset versions and detected attack vectors.
          </p>
        </div>

        <button
          onClick={handleSyncNVD}
          disabled={syncing}
          className="flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold text-white bg-sky-600 hover:bg-sky-500 rounded transition-colors whitespace-nowrap self-start sm:self-auto disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${syncing ? 'animate-spin' : ''}`} />
          <span>{syncing ? 'Syncing NVD...' : 'Sync with NVD Feed'}</span>
        </button>
      </div>

      {syncFeedback && (
        <div className="p-3 bg-sky-950/40 border border-sky-800/60 rounded text-xs text-sky-300 font-medium">
          {syncFeedback}
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="flex items-center justify-between gap-4 p-3 rounded-lg bg-slate-900/80 border border-slate-800 text-xs">
        <div className="flex items-center gap-2 text-slate-400 text-xs">
          <span>Sources:</span>
          <span className="px-2 py-0.5 rounded bg-emerald-950/40 text-emerald-400 border border-emerald-800/40 font-mono text-[10px]">
            LIVE (NVD Feed)
          </span>
          <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700 font-mono text-[10px]">
            DEMO (Seeded Lab)
          </span>
        </div>

        <div className="relative min-w-[240px]">
          <Search className="absolute left-2.5 top-2.5 w-3.5 h-3.5 text-slate-500" />
          <input
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search CVE ID, affected software..."
            className="w-full pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-700/80 rounded text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-sky-500 font-mono"
          />
        </div>
      </div>

      {/* CVE Grid / Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {filteredCves.map(cve => (
          <div
            key={cve.cve_id}
            className="p-5 rounded-lg bg-slate-900/90 border border-slate-800 space-y-3 font-mono text-xs flex flex-col justify-between"
          >
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-bold text-white tracking-wide">
                    {cve.cve_id}
                  </span>
                  <span className={`text-[10px] px-2 py-0.5 rounded border font-semibold ${
                    cve.source_type === 'LIVE'
                      ? 'bg-emerald-950/40 text-emerald-400 border-emerald-800/40'
                      : 'bg-slate-800 text-slate-400 border-slate-700'
                  }`}>
                    {cve.source_type}
                  </span>
                </div>

                <div className="flex items-center gap-1.5">
                  <span className="text-[10px] uppercase font-semibold text-rose-400">
                    {cve.severity}
                  </span>
                  <span className="px-2 py-0.5 bg-rose-950/60 border border-rose-800 text-rose-400 rounded font-bold text-[11px] tabular-nums">
                    CVSS {cve.cvss_score}
                  </span>
                </div>
              </div>

              <div>
                <span className="text-slate-500 text-[11px] block">Affected Product Stack:</span>
                <span className="text-sky-300 font-semibold">{cve.affected_product}</span>
              </div>

              <p className="text-slate-300 font-sans text-xs leading-relaxed pt-1">
                {cve.description}
              </p>
            </div>

            <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-slate-500">
              <span>Published: {cve.published_date}</span>
              {cve.reference_url && (
                <a
                  href={cve.reference_url}
                  target="_blank"
                  rel="noreferrer"
                  className="flex items-center gap-1 text-sky-400 hover:text-sky-300"
                >
                  <span>NVD Record</span>
                  <ExternalLink className="w-3 h-3" />
                </a>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
