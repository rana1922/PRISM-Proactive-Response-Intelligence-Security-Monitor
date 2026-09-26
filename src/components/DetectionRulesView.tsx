import React, { useState, useEffect } from 'react';
import { Shield, ToggleLeft, ToggleRight, CheckCircle2, AlertTriangle } from 'lucide-react';
import { DetectionRule } from '../types';
import { api } from '../services/api';

export const DetectionRulesView: React.FC = () => {
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [loadingId, setLoadingId] = useState<string | null>(null);

  const fetchRules = async () => {
    try {
      const data = await api.getRules();
      setRules(data);
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    fetchRules();
  }, []);

  const handleToggle = async (ruleId: string) => {
    setLoadingId(ruleId);
    try {
      const res = await api.toggleRule(ruleId);
      setRules(prev => prev.map(r => r.rule_id === ruleId ? res.rule : r));
    } catch (err) {
      console.error(err);
    } finally {
      setLoadingId(null);
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      {/* Header */}
      <div className="p-4 rounded-lg bg-slate-900 border border-slate-800 space-y-1">
        <h1 className="text-lg font-bold text-white tracking-tight flex items-center gap-2">
          <Shield className="w-4 h-4 text-emerald-400" />
          <span>Active Signature & Heuristic Detection Rules</span>
        </h1>
        <p className="text-xs text-slate-400">
          Configurable detection algorithms governing real-time telemetry inspection and behavioral baseline thresholds.
        </p>
      </div>

      {/* Rules Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {rules.map(rule => (
          <div
            key={rule.rule_id}
            className={`p-5 rounded-lg border transition-all space-y-3 font-mono text-xs ${
              rule.enabled 
                ? 'bg-slate-900/90 border-slate-800' 
                : 'bg-slate-950/40 border-slate-900 opacity-60'
            }`}
          >
            <div className="flex items-start justify-between">
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-bold text-white">{rule.name}</span>
                  <span className={`text-[10px] px-1.5 py-0.5 rounded border ${
                    rule.severity === 'CRITICAL'
                      ? 'bg-rose-950/40 text-rose-400 border-rose-800/40'
                      : rule.severity === 'HIGH'
                      ? 'bg-amber-950/40 text-amber-400 border-amber-800/40'
                      : 'bg-yellow-950/30 text-yellow-400 border-yellow-800/40'
                  }`}>
                    {rule.severity}
                  </span>
                </div>
                <span className="text-[11px] text-rose-400 block mt-0.5">{rule.rule_id}</span>
              </div>

              <button
                onClick={() => handleToggle(rule.rule_id)}
                disabled={loadingId === rule.rule_id}
                className="text-slate-300 hover:text-white transition-colors focus:outline-none"
                title={rule.enabled ? "Disable rule" : "Enable rule"}
              >
                {rule.enabled ? (
                  <ToggleRight className="w-7 h-7 text-emerald-400" />
                ) : (
                  <ToggleLeft className="w-7 h-7 text-slate-600" />
                )}
              </button>
            </div>

            <p className="text-slate-300 font-sans text-xs leading-relaxed">
              {rule.description}
            </p>

            <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-slate-500">
              <span>Attack: <strong className="text-slate-300">{rule.attack_type}</strong></span>
              <span>Confidence: <strong className="text-emerald-400">{rule.confidence}%</strong></span>
              <span className={`font-semibold ${rule.enabled ? 'text-emerald-400' : 'text-slate-600'}`}>
                {rule.enabled ? 'ACTIVE' : 'MUTED'}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
