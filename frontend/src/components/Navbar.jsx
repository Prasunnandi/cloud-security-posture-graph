import React from 'react';
import { 
  ShieldAlert, 
  RefreshCw, 
  AlertTriangle, 
  CheckCircle, 
  Cloud,
  Terminal,
  Activity
} from 'lucide-react';

export default function Navbar({ onRefresh, loading, summary }) {
  return (
    <header className="h-16 bg-slate-900 border-b border-slate-800 px-6 flex items-center justify-between shrink-0">
      <div className="flex items-center space-x-6">
        <div className="flex items-center space-x-2 text-xs text-slate-400">
          <Cloud className="w-3.5 h-3.5 text-rose-400" />
          <span className="text-slate-300 font-mono">AWS: 129840192841 (Prod-US-East-1)</span>
          <span className="text-slate-600">|</span>
          <span className="text-emerald-400 flex items-center space-x-1">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
            <span>IaC Policy Guard Active</span>
          </span>
        </div>
      </div>

      <div className="flex items-center space-x-4">
        {summary && (
          <div className="hidden lg:flex items-center space-x-4 px-3 py-1.5 rounded-lg bg-slate-950/60 border border-slate-800 text-xs">
            <div className="flex items-center space-x-1.5 text-slate-300">
              <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
              <span>Critical Findings:</span>
              <span className="font-semibold text-rose-400">{summary.critical}</span>
            </div>
            <div className="w-px h-3 bg-slate-700" />
            <div className="flex items-center space-x-1.5 text-slate-300">
              <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
              <span>Toxic Combos:</span>
              <span className="font-semibold text-amber-400">{summary.toxicCombinations}</span>
            </div>
            <div className="w-px h-3 bg-slate-700" />
            <div className="flex items-center space-x-1.5 text-slate-300">
              <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
              <span>Remediated:</span>
              <span className="font-semibold text-emerald-400">{summary.resolved}</span>
            </div>
          </div>
        )}

        <button
          onClick={onRefresh}
          disabled={loading}
          className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-rose-400' : ''}`} />
          <span>Rescan Posture</span>
        </button>

        <div className="w-8 h-8 rounded-full bg-gradient-to-tr from-rose-600 to-amber-600 flex items-center justify-center text-white font-bold text-xs ring-2 ring-rose-500/30">
          Sec
        </div>
      </div>
    </header>
  );
}
