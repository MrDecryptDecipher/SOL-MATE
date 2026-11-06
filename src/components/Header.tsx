/**
 * SOL-MATE — Forensic Command Header & Connected Google Account Console
 * Real-time RPC telemetry meters, Ease Mode vs. Pro Mode switcher,
 * IST clock, and Top-Right Interactive Connected Google Account Console
 * (Profile & IP Telemetry, Searchable Activity Audit Log in IST, and Knowledge Graph Ledger).
 */

import React, { useState, useEffect, useMemo } from 'react';
import {
  Wifi,
  WifiOff,
  Pause,
  Settings as SettingsIcon,
  Search,
  TrendingUp,
  TrendingDown,
  LogOut,
  Database,
  Clock,
  ChevronDown,
  Sparkles,
  Home,
  X,
  Download,
  ShieldCheck,
  ArrowRight,
} from 'lucide-react';
import { rpcClient, RpcTelemetry } from '../services/rpcClient';
import { wsClient, WsConnectionStatus } from '../services/wsClient';
import { tokenPriceService } from '../services/tokenPrices';
import { TokenPriceFeed } from '../types/forensics';
import { SolanaCluster } from '../types/solana';
import {
  ConnectedUserProfile,
  UserActivityRecord,
  WorkspaceMode,
} from '../services/firebaseService';
import { PersistentKnowledgeGraphState } from '../services/knowledgeGraphService';
import { formatToIST, getISTGreeting } from '../utils/istTime';

interface HeaderProps {
  currentCluster: SolanaCluster;
  onClusterChange: (cluster: SolanaCluster) => void;
  onOpenSettings: () => void;
  onSearchSignature: (sig: string) => void;
  isInvestigating?: boolean;
  connectedUser?: ConnectedUserProfile | null;
  workspaceMode?: WorkspaceMode;
  onWorkspaceModeChange?: (mode: WorkspaceMode) => void;
  userActivities?: UserActivityRecord[];
  persistentKg?: PersistentKnowledgeGraphState;
  onViewPublicHomepage?: () => void;
  onSignOut?: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  currentCluster,
  onClusterChange,
  onOpenSettings,
  onSearchSignature,
  connectedUser,
  workspaceMode = 'ease',
  onWorkspaceModeChange,
  userActivities = [],
  persistentKg,
  onViewPublicHomepage,
  onSignOut,
}) => {
  const [telemetry, setTelemetry] = useState<RpcTelemetry>(rpcClient.getTelemetry());
  const [wsStatus, setWsStatus] = useState<WsConnectionStatus>(wsClient.getStatus());
  const [solPrice, setSolPrice] = useState<TokenPriceFeed | null>(null);
  const [headerSearch, setHeaderSearch] = useState('');
  const [isAccountMenuOpen, setIsAccountMenuOpen] = useState(false);
  const [accountTab, setAccountTab] = useState<'profile' | 'activities' | 'kg'>('profile');
  const [activityFilter, setActivityFilter] = useState<string>('ALL');
  const [liveIST, setLiveIST] = useState<string>(() => formatToIST(Date.now()));

  useEffect(() => {
    wsClient.connect();
    const unsubTelemetry = rpcClient.subscribeTelemetry((t) => setTelemetry(t));
    const unsubWs = wsClient.subscribeStatus((s) => setWsStatus(s));
    const unsubPrice = tokenPriceService.subscribe((prices) => {
      if (prices['SOL']) setSolPrice(prices['SOL']);
    });
    const clockTimer = setInterval(() => {
      setLiveIST(formatToIST(Date.now()));
    }, 1000);

    return () => {
      unsubTelemetry();
      unsubWs();
      unsubPrice();
      clearInterval(clockTimer);
    };
  }, []);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (headerSearch.trim()) {
      onSearchSignature(headerSearch.trim());
      setHeaderSearch('');
    }
  };

  const toggleWsPause = () => {
    if (wsClient.isStreamPaused()) {
      wsClient.resume();
    } else {
      wsClient.pause();
    }
  };

  const getHealthColor = () => {
    switch (telemetry.providerHealth) {
      case 'healthy':
        return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
      case 'rate-limited':
        return 'text-amber-400 bg-amber-500/10 border-amber-500/30';
      case 'degraded':
      case 'offline':
        return 'text-rose-400 bg-rose-500/10 border-rose-500/30';
      default:
        return 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30';
    }
  };

  const filteredActivities = useMemo(() => {
    if (activityFilter === 'ALL') return userActivities;
    return userActivities.filter((a) => a.actionType === activityFilter);
  }, [userActivities, activityFilter]);

  const handleExportAuditJson = () => {
    if (!connectedUser) return;
    const payload = {
      exportedAtIST: formatToIST(Date.now()),
      connectedUser,
      userActivities,
      persistentKnowledgeGraphSummary: {
        lastTrainedIST: persistentKg?.lastTrainedIST,
        nodesCount: persistentKg?.nodes.length || 0,
        edgesCount: persistentKg?.edges.length || 0,
        transactionsCount: persistentKg?.transactions.length || 0,
        transactions: persistentKg?.transactions || [],
      },
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `solmate-audit-${connectedUser.uid.slice(0, 8)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const greeting = getISTGreeting(connectedUser?.name);

  return (
    <header className="h-16 border-b border-slate-800/80 bg-[#090b10]/95 backdrop-blur-md px-3 sm:px-5 flex items-center justify-between gap-2 sticky top-0 z-30">
      {/* Left: Ease vs Pro Mode Switcher, Quick Search & Cluster Selector */}
      <div className="flex items-center gap-2 min-w-0">
        {onWorkspaceModeChange && (
          <div
            className="flex items-center bg-[#111722] p-0.5 rounded-xl border border-cyan-500/30 shrink-0"
            role="group"
            aria-label="Workspace Mode Switcher"
          >
            <button
              type="button"
              onClick={() => onWorkspaceModeChange('ease')}
              className={`px-2.5 py-1 rounded-lg text-[11px] font-extrabold transition cursor-pointer ${
                workspaceMode === 'ease'
                  ? 'bg-cyan-500 text-slate-950 shadow-sm'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              EASE MODE
            </button>
            <button
              type="button"
              onClick={() => onWorkspaceModeChange('instant')}
              className={`px-2.5 py-1 rounded-lg text-[11px] font-extrabold transition cursor-pointer flex items-center gap-1 ${
                workspaceMode === 'instant'
                  ? 'bg-amber-400 text-slate-950 shadow-sm'
                  : 'text-amber-400 hover:text-amber-300'
              }`}
            >
              <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-ping" />
              <span>INSTANT MODE</span>
            </button>
            <button
              type="button"
              onClick={() => onWorkspaceModeChange('pro')}
              className={`px-2.5 py-1 rounded-lg text-[11px] font-extrabold transition cursor-pointer ${
                workspaceMode === 'pro'
                  ? 'bg-blue-500 text-slate-950 shadow-sm'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              PRO MODE
            </button>
          </div>
        )}

        <form onSubmit={handleSearchSubmit} className="relative hidden md:block w-52 lg:w-64">
          <input
            type="text"
            value={headerSearch}
            onChange={(e) => setHeaderSearch(e.target.value)}
            placeholder="Search signature, 0x hash, mint, or wallet..."
            className="w-full bg-[#111722] border border-slate-700/60 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500/80 focus:ring-1 focus:ring-cyan-500/50 font-mono transition"
          />
          <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
        </form>

        <div className="hidden lg:flex items-center bg-[#111722] border border-slate-700/60 rounded-lg px-2 py-1 text-xs whitespace-nowrap">
          <span className="text-slate-400 mr-1.5 text-[10px] font-medium">NET</span>
          <select
            value={currentCluster}
            onChange={(e) => onClusterChange(e.target.value as SolanaCluster)}
            aria-label="Select Solana Cluster"
            className="bg-transparent text-cyan-400 font-semibold focus:outline-none cursor-pointer text-xs"
          >
            <option value="mainnet" className="bg-[#111722] text-slate-200">
              Mainnet-Beta (6x)
            </option>
            <option value="devnet" className="bg-[#111722] text-slate-200">
              Solana Devnet (2x)
            </option>
            <option value="testnet" className="bg-[#111722] text-slate-200">
              Solana Testnet
            </option>
            <option value="custom" className="bg-[#111722] text-slate-200">
              Custom Endpoint
            </option>
          </select>
        </div>
      </div>

      {/* Center: Live SOL Price & IST Clock */}
      <div className="hidden xl:flex items-center gap-2 shrink-0">
        {solPrice && (
          <div className="flex items-center gap-2 bg-[#111722]/80 border border-slate-800 rounded-lg px-2.5 py-1 text-xs whitespace-nowrap">
            <span className="font-bold text-slate-300 flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-cyan-400"></span>
              SOL
            </span>
            <span className="font-mono font-semibold text-white">
              ${solPrice.priceUsd.toFixed(2)}
            </span>
            <span
              className={`flex items-center text-[11px] font-mono font-medium ${
                solPrice.change24h >= 0 ? 'text-emerald-400' : 'text-rose-400'
              }`}
            >
              {solPrice.change24h >= 0 ? (
                <TrendingUp className="w-3 h-3 mr-0.5 inline" />
              ) : (
                <TrendingDown className="w-3 h-3 mr-0.5 inline" />
              )}
              {solPrice.change24h >= 0 ? '+' : ''}
              {solPrice.change24h.toFixed(2)}%
            </span>
          </div>
        )}

        <div className="flex items-center gap-1.5 bg-[#111722]/80 border border-slate-800 rounded-lg px-2.5 py-1 text-[11px] font-mono text-amber-300">
          <Clock className="w-3 h-3 text-amber-400" />
          <span>{liveIST}</span>
        </div>
      </div>

      {/* Right: RPC Health, WSS, Settings & Top-Right Connected Google Account Console */}
      <div className="flex items-center gap-2 shrink-0 whitespace-nowrap relative">
        <div
          title={`Last fulfilled by: ${telemetry.lastWinningProvider}`}
          className={`hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-lg border text-[11px] font-medium capitalize ${getHealthColor()}`}
        >
          <span
            className={`w-2 h-2 rounded-full shrink-0 ${
              telemetry.providerHealth === 'healthy' ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'
            }`}
          ></span>
          <span>RPC: {telemetry.providerHealth}</span>
        </div>

        <button
          onClick={toggleWsPause}
          title={wsStatus === 'paused' ? 'Resume WebSocket Stream' : 'Pause WebSocket Stream'}
          className={`hidden md:flex items-center gap-1.5 px-2.5 py-1 rounded-lg border text-[11px] font-medium transition cursor-pointer ${
            wsStatus === 'connected'
              ? 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30 hover:bg-cyan-500/20'
              : wsStatus === 'paused'
              ? 'text-amber-400 bg-amber-500/10 border-amber-500/30'
              : 'text-slate-400 bg-slate-800/40 border-slate-700/60'
          }`}
        >
          {wsStatus === 'connected' ? (
            <>
              <Wifi className="w-3 h-3 text-cyan-400 animate-pulse" />
              <span className="hidden lg:inline">WSS LIVE</span>
            </>
          ) : wsStatus === 'paused' ? (
            <>
              <Pause className="w-3 h-3 text-amber-400" />
              <span className="hidden lg:inline">PAUSED</span>
            </>
          ) : (
            <>
              <WifiOff className="w-3 h-3 text-slate-400" />
              <span className="hidden lg:inline">WSS SYNC</span>
            </>
          )}
        </button>

        <button
          onClick={onOpenSettings}
          title="RPC & Forensic Configuration"
          className="p-1.5 text-slate-400 hover:text-white bg-[#111722] hover:bg-slate-800 border border-slate-700/60 rounded-lg transition cursor-pointer"
          aria-label="Settings"
        >
          <SettingsIcon className="w-4 h-4" />
        </button>

        {/* TOP-RIGHT CONNECTED GOOGLE ACCOUNT BUTTON & INTERACTIVE 3-TAB CONSOLE */}
        {connectedUser && (
          <div className="relative">
            <button
              type="button"
              onClick={() => setIsAccountMenuOpen((prev) => !prev)}
              className="flex items-center gap-2 pl-2 pr-2.5 py-1 rounded-xl bg-gradient-to-r from-[#111927] to-[#152033] hover:from-[#162133] hover:to-[#1c2b44] border border-cyan-500/40 text-left transition cursor-pointer"
              aria-label="Connected Google Account Menu"
            >
              {connectedUser.photoURL ? (
                <img
                  src={connectedUser.photoURL}
                  alt={connectedUser.name}
                  className="w-7 h-7 rounded-lg object-cover border border-cyan-400/50 shrink-0"
                  referrerPolicy="no-referrer"
                />
              ) : (
                <div className="w-7 h-7 rounded-lg bg-cyan-500 text-slate-950 font-extrabold text-xs flex items-center justify-center relative shrink-0">
                  {connectedUser.name.charAt(0).toUpperCase()}
                  <span className="w-2 h-2 rounded-full bg-emerald-400 border border-slate-950 absolute -bottom-0.5 -right-0.5" />
                </div>
              )}
              <div className="hidden sm:block leading-tight">
                <div className="text-[11px] font-extrabold text-white flex items-center gap-1">
                  <span>{connectedUser.name.split(' ')[0]}</span>
                  <span className="text-[9px] font-mono px-1 rounded bg-emerald-500/20 text-emerald-300">
                    VERIFIED
                  </span>
                </div>
                <div className="text-[10px] font-mono text-cyan-300 truncate max-w-[140px]">
                  {connectedUser.email}
                </div>
              </div>
              <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
            </button>

            {/* Interactive Connected Account & Database Audit Console */}
            {isAccountMenuOpen && (
              <div className="absolute right-0 mt-2 w-80 sm:w-[430px] rounded-2xl bg-[#0c121e] border border-cyan-500/40 shadow-2xl shadow-black/90 p-4 z-50 space-y-3.5 text-xs whitespace-normal">
                {/* Console Header */}
                <div className="flex items-start justify-between gap-2 border-b border-slate-800 pb-3">
                  <div className="flex items-center gap-2.5 min-w-0">
                    {connectedUser.photoURL ? (
                      <img
                        src={connectedUser.photoURL}
                        alt={connectedUser.name}
                        className="w-10 h-10 rounded-xl object-cover border border-cyan-400/50 shrink-0"
                        referrerPolicy="no-referrer"
                      />
                    ) : (
                      <div className="w-10 h-10 rounded-xl bg-cyan-500 text-slate-950 font-extrabold text-sm flex items-center justify-center shrink-0">
                        {connectedUser.name.charAt(0).toUpperCase()}
                      </div>
                    )}
                    <div className="min-w-0">
                      <div className="text-[10px] font-mono font-bold text-emerald-400 flex items-center gap-1">
                        <Sparkles className="w-3 h-3 shrink-0" /> {greeting.salutation}
                      </div>
                      <div className="text-sm font-extrabold text-white truncate">
                        {connectedUser.name}
                      </div>
                      <div className="text-[11px] font-mono text-cyan-300 truncate">
                        {connectedUser.email}
                      </div>
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => setIsAccountMenuOpen(false)}
                    className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 cursor-pointer"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>

                {/* 3-Tab Switcher inside Account Console */}
                <div className="grid grid-cols-3 gap-1 bg-[#080c14] p-1 rounded-xl border border-slate-800 font-mono text-[10px]">
                  <button
                    type="button"
                    onClick={() => setAccountTab('profile')}
                    className={`py-1.5 rounded-lg font-bold transition cursor-pointer ${
                      accountTab === 'profile'
                        ? 'bg-cyan-500 text-slate-950'
                        : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    1. Profile & IP
                  </button>
                  <button
                    type="button"
                    onClick={() => setAccountTab('activities')}
                    className={`py-1.5 rounded-lg font-bold transition cursor-pointer ${
                      accountTab === 'activities'
                        ? 'bg-cyan-500 text-slate-950'
                        : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    2. Audit Log ({userActivities.length})
                  </button>
                  <button
                    type="button"
                    onClick={() => setAccountTab('kg')}
                    className={`py-1.5 rounded-lg font-bold transition cursor-pointer ${
                      accountTab === 'kg'
                        ? 'bg-cyan-500 text-slate-950'
                        : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    3. KG Ledger ({persistentKg?.nodes.length || 0})
                  </button>
                </div>

                {/* TAB 1: PROFILE, IP & WORKSPACE MODE */}
                {accountTab === 'profile' && (
                  <div className="space-y-3">
                    <div className="p-3 rounded-xl bg-[#080c14] border border-slate-800 space-y-1.5 font-mono text-[11px]">
                      <div className="flex items-center justify-between text-[10px] font-bold text-slate-400 uppercase">
                        <span>Firestore Identity & IP Audit Record</span>
                        <span className="text-emerald-400 flex items-center gap-1">
                          <ShieldCheck className="w-3 h-3" />
                          {connectedUser.firestoreSynced ? 'FIRESTORE SYNCED' : 'ACTIVE SESSION'}
                        </span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-slate-400">Google UID:</span>
                        <span className="text-slate-200">{connectedUser.uid.slice(0, 18)}...</span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-slate-400">Client IP:</span>
                        <span className="text-emerald-400 font-bold">
                          {connectedUser.ipAddress}
                        </span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-slate-400">Network Route:</span>
                        <span className="text-slate-300 truncate max-w-[200px]">
                          {connectedUser.ipDetails}
                        </span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-slate-400">Connected (IST):</span>
                        <span className="text-slate-200">{connectedUser.connectedAtIST}</span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-slate-400">Last Active (IST):</span>
                        <span className="text-amber-300">{connectedUser.lastActiveIST}</span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-slate-400">Persistent KG:</span>
                        <span className="text-cyan-300 font-bold">
                          {persistentKg?.nodes.length || 0} Nodes • {persistentKg?.edges.length || 0}{' '}
                          Edges
                        </span>
                      </div>
                    </div>

                    {onWorkspaceModeChange && (
                      <div className="space-y-1.5">
                        <div className="text-[10px] font-mono uppercase text-slate-400">
                          Switch Active Forensic Experience Mode
                        </div>
                        <div className="grid grid-cols-2 gap-2">
                          <button
                            type="button"
                            onClick={() => {
                              onWorkspaceModeChange('ease');
                              setIsAccountMenuOpen(false);
                            }}
                            className={`py-2 px-3 rounded-xl border font-bold text-xs cursor-pointer ${
                              workspaceMode === 'ease'
                                ? 'bg-cyan-500 text-slate-950 border-cyan-400'
                                : 'bg-[#080c14] text-slate-300 border-slate-800'
                            }`}
                          >
                            Ease Mode (A-B-C-D)
                          </button>
                          <button
                            type="button"
                            onClick={() => {
                              onWorkspaceModeChange('pro');
                              setIsAccountMenuOpen(false);
                            }}
                            className={`py-2 px-3 rounded-xl border font-bold text-xs cursor-pointer ${
                              workspaceMode === 'pro'
                                ? 'bg-blue-500 text-slate-950 border-blue-400'
                                : 'bg-[#080c14] text-slate-300 border-slate-800'
                            }`}
                          >
                            Pro Mode (9-Tab)
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* TAB 2: STORED USER ACTIVITY LOG (IST) */}
                {accountTab === 'activities' && (
                  <div className="space-y-2.5">
                    <div className="flex items-center justify-between gap-2">
                      <select
                        value={activityFilter}
                        onChange={(e) => setActivityFilter(e.target.value)}
                        className="bg-[#080c14] border border-slate-800 rounded-lg px-2 py-1 text-[11px] font-mono text-cyan-300 focus:outline-none"
                      >
                        <option value="ALL">All Actions ({userActivities.length})</option>
                        <option value="TX_INVESTIGATION">Tx Investigations</option>
                        <option value="KNOWLEDGE_GRAPH_TRAINED">KG Training</option>
                        <option value="ADDRESS_INSPECTION">Address Inspections</option>
                        <option value="WHITELIST_UPDATED">Whitelist Updates</option>
                        <option value="MODE_SWITCH">Mode Switches</option>
                      </select>

                      <button
                        type="button"
                        onClick={handleExportAuditJson}
                        className="px-2.5 py-1 rounded-lg bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/40 text-emerald-300 font-mono text-[10px] font-bold flex items-center gap-1 cursor-pointer"
                      >
                        <Download className="w-3 h-3" />
                        <span>Export JSON</span>
                      </button>
                    </div>

                    <div className="max-h-56 overflow-y-auto space-y-1.5 pr-1">
                      {filteredActivities.slice(0, 20).map((act) => (
                        <div
                          key={act.id}
                          className="p-2.5 rounded-lg bg-[#080c14] border border-slate-800/80 space-y-1"
                        >
                          <div className="flex items-center justify-between text-[10px] font-mono">
                            <span className="text-cyan-400 font-bold">{act.actionType}</span>
                            <span className="text-amber-300">{act.timestampIST}</span>
                          </div>
                          <div className="text-[11px] text-slate-100 font-semibold">
                            {act.actionTitle}
                          </div>
                          <div className="text-[10px] text-slate-400 line-clamp-1">
                            {act.details}
                          </div>
                          {act.targetId && act.targetId.length > 25 && (
                            <button
                              type="button"
                              onClick={() => {
                                onSearchSignature(act.targetId!);
                                setIsAccountMenuOpen(false);
                              }}
                              className="text-[10px] font-mono text-emerald-300 hover:underline flex items-center gap-1 cursor-pointer"
                            >
                              <span>Inspect {act.targetId.slice(0, 18)}...</span>
                              <ArrowRight className="w-2.5 h-2.5" />
                            </button>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* TAB 3: TRAINED SOLANA KNOWLEDGE GRAPH LEDGER (IST) */}
                {accountTab === 'kg' && (
                  <div className="space-y-2.5">
                    <div className="p-2.5 rounded-xl bg-[#080c14] border border-slate-800 flex items-center justify-between font-mono text-[11px]">
                      <span className="text-slate-400 flex items-center gap-1.5">
                        <Database className="w-3.5 h-3.5 text-cyan-400" /> Last Trained (IST):
                      </span>
                      <span className="text-amber-300 font-bold">
                        {persistentKg?.lastTrainedIST}
                      </span>
                    </div>

                    <div className="max-h-56 overflow-y-auto space-y-1.5 pr-1">
                      {persistentKg?.transactions.map((t) => (
                        <div
                          key={t.txId}
                          className="p-2.5 rounded-lg bg-[#080c14] border border-slate-800/90 space-y-1"
                        >
                          <div className="flex items-center justify-between text-[10px] font-mono">
                            <span className="text-emerald-400 font-bold">{t.alertCategory}</span>
                            <span className="text-amber-300">{t.trainedAtIST}</span>
                          </div>
                          <div className="text-[11px] font-bold text-white">{t.valueInvolved}</div>
                          <div className="text-[10px] text-slate-400">{t.tokenInvolved}</div>
                          <button
                            type="button"
                            onClick={() => {
                              onSearchSignature(t.signature);
                              setIsAccountMenuOpen(false);
                            }}
                            className="text-[10px] font-mono text-cyan-300 hover:underline flex items-center gap-1 cursor-pointer"
                          >
                            <span>Load Tx {t.signature.slice(0, 18)}...</span>
                            <ArrowRight className="w-2.5 h-2.5" />
                          </button>
                        </div>
                      ))}

                      {persistentKg?.nodes.slice(0, 8).map((n) => (
                        <div
                          key={n.nodeId}
                          className="p-2 rounded-lg bg-[#080c14] border border-slate-800/70 flex items-center justify-between gap-2"
                        >
                          <div className="min-w-0">
                            <div className="text-[11px] font-bold text-slate-200 truncate">
                              {n.label}
                            </div>
                            <div className="text-[10px] font-mono text-slate-400">
                              {n.lastTrainedIST} • {n.observationCount}x
                            </div>
                          </div>
                          <button
                            type="button"
                            onClick={() => {
                              onSearchSignature(n.address);
                              setIsAccountMenuOpen(false);
                            }}
                            className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 font-mono text-[10px] shrink-0 cursor-pointer"
                          >
                            Inspect
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Footer Actions: View Public Homepage & Disconnect */}
                <div className="pt-2 border-t border-slate-800 flex items-center justify-between gap-2">
                  {onViewPublicHomepage && (
                    <button
                      type="button"
                      onClick={() => {
                        setIsAccountMenuOpen(false);
                        onViewPublicHomepage();
                      }}
                      className="flex-1 py-2 px-3 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 font-bold text-xs flex items-center justify-center gap-1.5 cursor-pointer"
                    >
                      <Home className="w-3.5 h-3.5 text-cyan-400" />
                      <span>SOL-MATE Homepage</span>
                    </button>
                  )}

                  {onSignOut && (
                    <button
                      type="button"
                      onClick={() => {
                        setIsAccountMenuOpen(false);
                        onSignOut();
                      }}
                      className="py-2 px-3 rounded-xl bg-rose-500/15 hover:bg-rose-500/25 border border-rose-500/30 text-rose-300 font-bold text-xs flex items-center justify-center gap-1.5 cursor-pointer"
                    >
                      <LogOut className="w-3.5 h-3.5" />
                      <span>Sign Out</span>
                    </button>
                  )}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </header>
  );
};
