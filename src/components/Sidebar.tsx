/**
 * SOL-MATE — Main Navigation Sidebar
 * Product Identity: SOL-MATE (Built by Sandeep Kumar Sahoo)
 * Navigation for active investigation, real-time live monitoring, deep state storage, and monitored accounts.
 */

import React from 'react';
import {
  ShieldAlert,
  Search,
  Activity,
  Layers,
  Database,
  Users,
  Settings,
  Sparkles,
  ExternalLink,
  Clock,
  Compass,
} from 'lucide-react';
import { SavedInvestigationSummary } from '../services/deepStorage';

export type ActiveTab = 'search' | 'investigation' | 'monitoring' | 'saved' | 'monitored-accounts' | 'settings';

interface SidebarProps {
  activeTab: ActiveTab;
  onTabChange: (tab: ActiveTab) => void;
  hasActiveTransaction: boolean;
  activeSignature?: string;
  savedInvestigations: SavedInvestigationSummary[];
  onSelectSavedTx: (sig: string) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onTabChange,
  hasActiveTransaction,
  activeSignature,
  savedInvestigations,
  onSelectSavedTx,
}) => {
  return (
    <aside className="w-64 bg-[#07090e] border-r border-slate-800/80 flex flex-col justify-between shrink-0 h-screen sticky top-0 z-40 select-none">
      {/* Brand Header */}
      <div>
        <div className="p-4 border-b border-slate-800/80">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-cyan-600 via-cyan-500 to-blue-500 p-0.5 shadow-lg shadow-cyan-500/20 flex items-center justify-center">
              <div className="w-full h-full bg-[#090b10] rounded-[10px] flex items-center justify-center">
                <ShieldAlert className="w-5 h-5 text-cyan-400" />
              </div>
            </div>
            <div>
              <div className="flex items-center gap-1.5">
                <span className="font-extrabold text-base tracking-wider text-white">SOL-MATE</span>
                <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                  v1.0
                </span>
              </div>
              <p className="text-[10px] text-slate-400 tracking-tight font-medium">
                Every Transaction. Every Account.
              </p>
            </div>
          </div>
        </div>

        {/* Primary Navigation Items */}
        <nav className="p-3 space-y-1">
          <button
            onClick={() => onTabChange('search')}
            className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs font-semibold transition ${
              activeTab === 'search'
                ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
            }`}
          >
            <Search className="w-4 h-4 text-cyan-400" />
            <span>New Investigation</span>
          </button>

          {hasActiveTransaction && (
            <button
              onClick={() => onTabChange('investigation')}
              className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-semibold transition ${
                activeTab === 'investigation'
                  ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              <div className="flex items-center gap-2.5 overflow-hidden">
                <Layers className="w-4 h-4 text-emerald-400 shrink-0" />
                <span className="truncate">Active Case: {activeSignature?.slice(0, 6)}...</span>
              </div>
              <span className="w-2 h-2 rounded-full bg-emerald-400 shrink-0 animate-pulse"></span>
            </button>
          )}

          <button
            onClick={() => onTabChange('monitoring')}
            className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-semibold transition ${
              activeTab === 'monitoring'
                ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
            }`}
          >
            <div className="flex items-center gap-2.5">
              <Activity className="w-4 h-4 text-cyan-400" />
              <span>Live Blockchain Feeds</span>
            </div>
            <span className="text-[10px] bg-slate-800 text-cyan-300 px-1.5 py-0.2 rounded font-mono">
              WSS
            </span>
          </button>

          <button
            onClick={() => onTabChange('saved')}
            className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-semibold transition ${
              activeTab === 'saved'
                ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
            }`}
          >
            <div className="flex items-center gap-2.5">
              <Database className="w-4 h-4 text-violet-400" />
              <span>Saved Investigations</span>
            </div>
            <span className="text-[10px] bg-slate-800 text-slate-300 px-1.5 py-0.2 rounded font-mono">
              {savedInvestigations.length}
            </span>
          </button>

          <button
            onClick={() => onTabChange('monitored-accounts')}
            className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs font-semibold transition ${
              activeTab === 'monitored-accounts'
                ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
            }`}
          >
            <Users className="w-4 h-4 text-blue-400" />
            <span>Monitored Wallets</span>
          </button>

          <button
            onClick={() => onTabChange('settings')}
            className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs font-semibold transition ${
              activeTab === 'settings'
                ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
            }`}
          >
            <Settings className="w-4 h-4 text-slate-400" />
            <span>Forensics Config</span>
          </button>
        </nav>

        {/* Recent Cases Section */}
        {savedInvestigations.length > 0 && (
          <div className="px-3 pt-3">
            <div className="px-3 pb-1 text-[10px] font-bold text-slate-500 uppercase tracking-wider flex items-center justify-between">
              <span>Recent Cases</span>
              <Clock className="w-3 h-3" />
            </div>
            <div className="space-y-1 max-h-48 overflow-y-auto pr-1">
              {savedInvestigations.slice(0, 5).map((item) => (
                <button
                  key={item.signature}
                  onClick={() => onSelectSavedTx(item.signature)}
                  className="w-full text-left p-2 rounded-lg bg-[#0e131b] hover:bg-slate-800/70 border border-slate-800/60 transition group"
                >
                  <div className="flex items-center justify-between text-[11px]">
                    <span className="font-mono text-cyan-300 group-hover:text-cyan-200 font-semibold truncate max-w-[120px]">
                      {item.signature.slice(0, 8)}...{item.signature.slice(-4)}
                    </span>
                    <span
                      className={`text-[9px] px-1 py-0.2 rounded font-bold ${
                        item.status === 'success'
                          ? 'bg-emerald-500/20 text-emerald-300'
                          : 'bg-rose-500/20 text-rose-300'
                      }`}
                    >
                      {item.status.toUpperCase()}
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-[10px] text-slate-500 mt-1">
                    <span>Slot {item.slot.toLocaleString()}</span>
                    <span>Risk: {item.riskScore}/100</span>
                  </div>
                </button>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Built by Sandeep Kumar Sahoo Badge */}
      <div className="p-3 border-t border-slate-800/80 bg-[#090b10]">
        <div className="bg-gradient-to-r from-slate-900 to-[#0e141f] border border-cyan-500/20 rounded-xl p-3 shadow-inner">
          <div className="flex items-center gap-1.5 text-cyan-400 text-[11px] font-bold">
            <Sparkles className="w-3.5 h-3.5" />
            <span>SOL-MATE FORENSICS</span>
          </div>
          <p className="text-[10px] text-slate-400 mt-0.5 leading-snug">
            Built by <span className="text-white font-semibold">Sandeep Kumar Sahoo</span>
          </p>
          <div className="mt-2 pt-2 border-t border-slate-800/80 flex items-center justify-between text-[10px] text-slate-500">
            <span>3x Parallel Pool</span>
            <span className="text-emerald-400 font-mono">Helius • PublicNode • OnFinality</span>
          </div>
        </div>
      </div>
    </aside>
  );
};
