import React from 'react';
import { SeverityLevel } from '../types';

interface ThreatScoreBadgeProps {
  score: number;
  severity?: SeverityLevel;
  size?: 'sm' | 'md' | 'lg';
  showLabel?: boolean;
}

export const ThreatScoreBadge: React.FC<ThreatScoreBadgeProps> = ({
  score,
  severity,
  size = 'md',
  showLabel = true
}) => {
  // Determine severity if not provided
  let sev: SeverityLevel = severity || 'LOW';
  if (!severity) {
    if (score >= 80) sev = 'CRITICAL';
    else if (score >= 60) sev = 'HIGH';
    else if (score >= 30) sev = 'MEDIUM';
    else sev = 'LOW';
  }

  const getColorConfig = () => {
    switch (sev) {
      case 'CRITICAL':
        return {
          stroke: '#DC2626',
          bg: 'bg-rose-950/40 border-rose-800/40 text-rose-400',
          text: 'text-rose-400',
          labelBg: 'bg-rose-500/10 text-rose-300 border-rose-500/30'
        };
      case 'HIGH':
        return {
          stroke: '#EA580C',
          bg: 'bg-amber-950/40 border-amber-800/40 text-amber-400',
          text: 'text-amber-400',
          labelBg: 'bg-amber-500/10 text-amber-300 border-amber-500/30'
        };
      case 'MEDIUM':
        return {
          stroke: '#D97706',
          bg: 'bg-yellow-950/30 border-yellow-800/40 text-yellow-400',
          text: 'text-yellow-400',
          labelBg: 'bg-yellow-500/10 text-yellow-300 border-yellow-500/30'
        };
      case 'LOW':
      default:
        return {
          stroke: '#16A34A',
          bg: 'bg-emerald-950/30 border-emerald-800/40 text-emerald-400',
          text: 'text-emerald-400',
          labelBg: 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30'
        };
    }
  };

  const config = getColorConfig();

  if (size === 'sm') {
    return (
      <div className="flex items-center gap-1.5 font-mono tabular-nums">
        <span className={`px-1.5 py-0.5 text-xs font-semibold rounded border ${config.bg}`}>
          {score}
        </span>
        {showLabel && (
          <span className={`text-[11px] font-medium tracking-wide uppercase ${config.text}`}>
            {sev}
          </span>
        )}
      </div>
    );
  }

  // Circular gauge for medium & large sizes
  const radius = size === 'lg' ? 44 : 28;
  const strokeWidth = size === 'lg' ? 6 : 4;
  const viewBoxSize = (radius + strokeWidth) * 2;
  const circumference = 2 * Math.PI * radius;
  const dashoffset = circumference - (Math.min(score, 100) / 100) * circumference;

  return (
    <div className="flex items-center gap-3">
      <div className="relative flex items-center justify-center">
        <svg
          width={size === 'lg' ? 96 : 64}
          height={size === 'lg' ? 96 : 64}
          viewBox={`0 0 ${viewBoxSize} ${viewBoxSize}`}
          className="-rotate-90"
        >
          {/* Background circle */}
          <circle
            cx={viewBoxSize / 2}
            cy={viewBoxSize / 2}
            r={radius}
            stroke="#1e293b"
            strokeWidth={strokeWidth}
            fill="transparent"
          />
          {/* Progress circle */}
          <circle
            cx={viewBoxSize / 2}
            cy={viewBoxSize / 2}
            r={radius}
            stroke={config.stroke}
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={dashoffset}
            strokeLinecap="round"
            fill="transparent"
            className="transition-all duration-700 ease-out"
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={`font-mono font-bold tabular-nums ${size === 'lg' ? 'text-2xl' : 'text-base'} text-slate-100`}>
            {score}
          </span>
        </div>
      </div>

      {showLabel && (
        <div className="flex flex-col">
          <span className={`text-xs font-semibold tracking-wider uppercase ${config.text}`}>
            {sev}
          </span>
          <span className="text-[11px] text-slate-500 font-mono">
            {score}/100 Risk Score
          </span>
        </div>
      )}
    </div>
  );
};
