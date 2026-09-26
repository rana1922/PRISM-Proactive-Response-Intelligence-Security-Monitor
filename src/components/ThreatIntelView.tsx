import React, { useState, useEffect } from 'react';
import { Network, Plus, Search, Shield, Globe, Hash, Mail, Link as LinkIcon, ExternalLink } from 'lucide-react';
import { IOCRecord, IOCType } from '../types';
import { api } from '../services/api';

export const ThreatIntelView: React.FC = () => {
  const [iocs, setIocs] = useState<IOCRecord[]>([]);
  const [typeFilter, setTypeFilter] = useState<string>('ALL');
  const [search, setSearch] = useState('');
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  
  // New IOC Form State
  const [newIoc, setNewIoc] = useState('');
  const [newType, setNewType] = useState<IOCType>('IP');
  const [newThreatLevel, setNewThreatLevel] = useState<'low' | 'medium' | 'high' | 'critical'>('high');
  const [newSource, setNewSource] = useState('PRISM Threat Intelligence');
  const [newConfidence, setNewConfidence] = useState(90);
  const [newDescription, setNewDescription] = useState('');
  const [newTags, setNewTags] = useState('Malicious, Botnet');

  const fetchIocs = async () => {
    try {
      const data = await api.getIOCs();
      setIocs(data);
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    fetchIocs();
  }, []);

  const handleCreateIOC = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newIoc) return;

    try {
      await api.createIOC({
        ioc: newIoc,
        type: newType,
        threat_level: newThreatLevel,
        source: newSource,
        confidence: Number(newConfidence),
        description: newDescription || 'Analyst created threat indicator',
        tags: newTags.split(',').map(t => t.trim()).filter(Boolean)
      });
      setIsAddModalOpen(false);
      setNewIoc('');
      setNewDescription('');
      fetchIocs();
    } catch (err) {
      console.error(err);
    }
  };

  const filteredIocs = iocs.filter(item => {
    if (typeFilter !== 'ALL' && item.type !== typeFilter) return false;
    if (search) {
      const q = search.toLowerCase();
      return item.ioc.toLowerCase().includes(q) ||
             item.source.toLowerCase().includes(q) ||
             item.description.toLowerCase().includes(q) ||
             item.tags.some((t: string) => t.toLowerCase().includes(q));
    }
    return true;
  });

  const getTypeIcon = (type: IOCType) => {
    switch (type) {
      case 'IP': return <Network className="w-3.5 h-3.5 text-rose-400" />;
      case 'DOMAIN': return <Globe className="w-3.5 h-3.5 text-sky-400" />;
      case 'HASH': return <Hash className="w-3.5 h-3.5 text-amber-400" />;
      case 'EMAIL': return <Mail className="w-3.5 h-3.5 text-purple-400" />;
      case 'URL': return <LinkIcon className="w-3.5 h-3.5 text-emerald-400" />;
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 rounded-lg bg-slate-900 border border-slate-800">
        <div>
          <h1 className="text-lg font-bold text-white tracking-tight flex items-center gap-2">
            <Network className="w-4 h-4 text-rose-500" />
            <span>Threat Intelligence & IOC Repository</span>
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Active indicators of compromise continuously compared against ingested event streams.
          </p>
        </div>

        <button
          onClick={() => setIsAddModalOpen(true)}
          className="flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold text-white bg-rose-600 hover:bg-rose-500 rounded transition-colors whitespace-nowrap self-start sm:self-auto"
        >
          <Plus className="w-3.5 h-3.5" />
          <span>Add New Indicator</span>
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-3 rounded-lg bg-slate-900/80 border border-slate-800 text-xs">
        <div className="flex items-center gap-1 p-1 bg-slate-950 rounded border border-slate-800 font-mono">
          {['ALL', 'IP', 'DOMAIN', 'HASH', 'URL', 'EMAIL'].map(t => (
            <button
              key={t}
              onClick={() => setTypeFilter(t)}
              className={`px-3 py-1 rounded transition-colors ${
                typeFilter === t
                  ? 'bg-slate-800 text-white font-bold shadow-sm'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {t}
            </button>
          ))}
        </div>

        <div className="relative min-w-[220px]">
          <Search className="absolute left-2.5 top-2.5 w-3.5 h-3.5 text-slate-500" />
          <input
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search indicators, tags, providers..."
            className="w-full pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-700/80 rounded text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-rose-500 font-mono"
          />
        </div>
      </div>

      {/* IOC Records Table */}
      <div className="rounded-lg bg-slate-900/90 border border-slate-800 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="text-[11px] text-slate-500 bg-slate-950/80 border-b border-slate-800 uppercase">
              <tr>
                <th className="py-3 px-4">Indicator (IOC)</th>
                <th className="py-3 px-4">Type</th>
                <th className="py-3 px-4">Threat Level</th>
                <th className="py-3 px-4">Intelligence Source</th>
                <th className="py-3 px-4 text-right">Confidence</th>
                <th className="py-3 px-4">Tags & Context</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredIocs.map((item, idx) => (
                <tr key={`${item.id}-${idx}`} className="hover:bg-slate-800/30 transition-colors">
                  <td className="py-3 px-4 font-semibold text-rose-400 max-w-xs break-all">
                    {item.ioc}
                  </td>

                  <td className="py-3 px-4">
                    <div className="flex items-center gap-1.5 text-slate-300">
                      {getTypeIcon(item.type)}
                      <span>{item.type}</span>
                    </div>
                  </td>

                  <td className="py-3 px-4">
                    <span className={`text-[10px] px-1.5 py-0.5 rounded border uppercase font-bold ${
                      item.threat_level === 'critical'
                        ? 'bg-rose-950/40 text-rose-400 border-rose-800/40'
                        : item.threat_level === 'high'
                        ? 'bg-amber-950/40 text-amber-400 border-amber-800/40'
                        : 'bg-yellow-950/30 text-yellow-400 border-yellow-800/40'
                    }`}>
                      {item.threat_level}
                    </span>
                  </td>

                  <td className="py-3 px-4 text-slate-300">
                    {item.source}
                  </td>

                  <td className="py-3 px-4 text-right font-bold text-white tabular-nums">
                    {item.confidence}%
                  </td>

                  <td className="py-3 px-4 max-w-sm">
                    <div className="flex flex-wrap gap-1 mb-1">
                      {item.tags.map((t: string) => (
                        <span key={t} className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-400">
                          {t}
                        </span>
                      ))}
                    </div>
                    <p className="text-[11px] text-slate-400 font-sans truncate">
                      {item.description}
                    </p>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add IOC Modal */}
      {isAddModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-in fade-in duration-200">
          <div className="relative w-full max-w-md bg-slate-900 border border-slate-800 rounded-lg p-6 shadow-2xl text-slate-200 space-y-4">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Plus className="w-4 h-4 text-rose-400" />
              <span>Catalog New Threat Indicator</span>
            </h3>

            <form onSubmit={handleCreateIOC} className="space-y-3 text-xs font-mono">
              <div>
                <label className="block text-slate-400 mb-1">Indicator Value</label>
                <input
                  type="text"
                  required
                  value={newIoc}
                  onChange={e => setNewIoc(e.target.value)}
                  placeholder="e.g. 185.220.101.45 or evil-domain.cc"
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded text-slate-200 focus:outline-none focus:border-rose-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Type</label>
                  <select
                    value={newType}
                    onChange={e => setNewType(e.target.value as IOCType)}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded text-slate-200 focus:outline-none focus:border-rose-500"
                  >
                    <option value="IP">IP</option>
                    <option value="DOMAIN">DOMAIN</option>
                    <option value="HASH">HASH</option>
                    <option value="URL">URL</option>
                    <option value="EMAIL">EMAIL</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-400 mb-1">Threat Level</label>
                  <select
                    value={newThreatLevel}
                    onChange={e => setNewThreatLevel(e.target.value as any)}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded text-slate-200 focus:outline-none focus:border-rose-500"
                  >
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Source Provider</label>
                  <input
                    type="text"
                    value={newSource}
                    onChange={e => setNewSource(e.target.value)}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded text-slate-200 focus:outline-none focus:border-rose-500"
                  />
                </div>

                <div>
                  <label className="block text-slate-400 mb-1">Confidence (%)</label>
                  <input
                    type="number"
                    min="1"
                    max="100"
                    value={newConfidence}
                    onChange={e => setNewConfidence(Number(e.target.value))}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded text-slate-200 focus:outline-none focus:border-rose-500"
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Tags (Comma-separated)</label>
                <input
                  type="text"
                  value={newTags}
                  onChange={e => setNewTags(e.target.value)}
                  placeholder="Botnet, C2, Scanner"
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded text-slate-200 focus:outline-none focus:border-rose-500"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Description / Intel Context</label>
                <textarea
                  rows={2}
                  value={newDescription}
                  onChange={e => setNewDescription(e.target.value)}
                  placeholder="Observed in credential stuffing and reconnaissance campaigns"
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded text-slate-200 focus:outline-none focus:border-rose-500"
                />
              </div>

              <div className="flex justify-end gap-2 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setIsAddModalOpen(false)}
                  className="px-3.5 py-1.5 text-xs text-slate-400 hover:text-white bg-slate-800 rounded"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 text-xs font-semibold text-white bg-rose-600 hover:bg-rose-500 rounded"
                >
                  Save Indicator
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
