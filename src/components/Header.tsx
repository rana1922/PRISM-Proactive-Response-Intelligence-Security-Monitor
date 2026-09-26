import React from 'react';
import { Shield, Play, Pause, AlertTriangle, Activity } from 'lucide-react';

export type NavTab = 
  | 'dashboard' 
  | 'simulator' 
  | 'alerts' 
  | 'incidents' 
  | 'ioc' 
  | 'cve' 
  | 'responses' 
  | 'rules';

interface HeaderProps {
  currentTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  isDemoActive: boolean;
  onToggleDemo: () => void;
  systemStatus: string;
  responseMode: string;
  onLaunchSimulator: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  currentTab,
  onSelectTab,
  isDemoActive,
  onToggleDemo,
  systemStatus,
  responseMode,
  onLaunchSimulator
}) => {
  return (
    <header className="sticky top-0 z-40 flex items-center justify-between px-6 py-3.5 bg-[#0b0f19]/95 backdrop-blur border-b border-slate-800/80">
      {/* Zone 1: Single text element wordmark */}
      <div className="flex items-center gap-3">
        <a 
          href="#dashboard" 
          onClick={(e) => { e.preventDefault(); onSelectTab('dashboard'); }}
          className="flex items-center gap-2.5 text-lg font-bold tracking-tight text-white focus:outline-none"
        >
          <div className="relative flex items-center justify-center w-8 h-8 rounded bg-gradient-to-br from-indigo-500/20 to-rose-500/20 border border-slate-700">
            <Shield className="w-4 h-4 text-rose-500" />
            <span className="absolute top-1 right-1 w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
          </div>
          <span>PRISM</span>
        </a>
        <div className="hidden sm:flex items-center gap-2 text-xs text-slate-500 border-l border-slate-800 pl-3">
          <span className="font-mono text-emerald-400 font-medium">SOC READY</span>
          <span aria-hidden="true">·</span>
          <span className="font-mono text-slate-400 uppercase">{responseMode} MODE</span>
        </div>
      </div>

      {/* Zone 2: 4-6 clean text navigation links */}
      <nav className="hidden lg:flex items-center gap-6 text-sm font-medium text-slate-400">
        <button
          onClick={() => onSelectTab('dashboard')}
          className={`transition-colors py-1 ${
            currentTab === 'dashboard' 
              ? 'text-white border-b-2 border-rose-500 font-semibold' 
              : 'hover:text-slate-200'
          }`}
        >
          Dashboard
        </button>

        <button
          onClick={() => onSelectTab('simulator')}
          className={`transition-colors py-1 flex items-center gap-1.5 ${
            currentTab === 'simulator' 
              ? 'text-rose-400 border-b-2 border-rose-500 font-semibold' 
              : 'hover:text-slate-200'
          }`}
        >
          <AlertTriangle className="w-3.5 h-3.5 text-rose-500" />
          <span>Attack Simulator</span>
        </button>

        <button
          onClick={() => onSelectTab('alerts')}
          className={`transition-colors py-1 ${
            currentTab === 'alerts' 
              ? 'text-white border-b-2 border-rose-500 font-semibold' 
              : 'hover:text-slate-200'
          }`}
        >
          Live Alerts
        </button>

        <button
          onClick={() => onSelectTab('incidents')}
          className={`transition-colors py-1 ${
            currentTab === 'incidents' 
              ? 'text-white border-b-2 border-rose-500 font-semibold' 
              : 'hover:text-slate-200'
          }`}
        >
          Incidents
        </button>

        <button
          onClick={() => onSelectTab('ioc')}
          className={`transition-colors py-1 ${
            currentTab === 'ioc' 
              ? 'text-white border-b-2 border-rose-500 font-semibold' 
              : 'hover:text-slate-200'
          }`}
        >
          Threat Intel
        </button>

        <button
          onClick={() => onSelectTab('cve')}
          className={`transition-colors py-1 ${
            currentTab === 'cve' 
              ? 'text-white border-b-2 border-rose-500 font-semibold' 
              : 'hover:text-slate-200'
          }`}
        >
          CVEs
        </button>

        <button
          onClick={() => onSelectTab('responses')}
          className={`transition-colors py-1 ${
            currentTab === 'responses' 
              ? 'text-white border-b-2 border-rose-500 font-semibold' 
              : 'hover:text-slate-200'
          }`}
        >
          Audit Log
        </button>
      </nav>

      {/* Zone 3: 1-2 primary actions */}
      <div className="flex items-center gap-2.5">
        {/* Demo Mode Toggle */}
        <button
          onClick={onToggleDemo}
          title={isDemoActive ? "Pause simulated background traffic stream" : "Start simulated background attacks every 5s"}
          className={`flex items-center gap-2 px-3 py-1.5 text-xs font-mono font-medium rounded border transition-colors ${
            isDemoActive
              ? 'bg-rose-950/60 border-rose-700/60 text-rose-300 animate-pulse'
              : 'bg-slate-900 border-slate-700 text-slate-300 hover:bg-slate-800'
          }`}
        >
          {isDemoActive ? (
            <>
              <Pause className="w-3.5 h-3.5 text-rose-400" />
              <span>Demo Feed: ON</span>
            </>
          ) : (
            <>
              <Play className="w-3.5 h-3.5 text-emerald-400" />
              <span>Demo Feed: OFF</span>
            </>
          )}
        </button>

        {/* Quick Launch Simulator Button */}
        <button
          onClick={onLaunchSimulator}
          className="flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-medium text-white bg-rose-600 hover:bg-rose-500 rounded transition-colors whitespace-nowrap shadow-sm shadow-rose-900/20"
        >
          <Activity className="w-3.5 h-3.5" />
          <span>Simulate Attack</span>
        </button>
      </div>
    </header>
  );
};
