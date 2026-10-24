/**
 * SOL-MATE — Forensic Command Header
 * Real-time RPC telemetry meters (rate limit, queue depth, latency),
 * cluster selector, live token ticker, and WebSocket stream pulse.
 */

import React, { useState, useEffect } from 'react';
import {
  Activity,
  Wifi,
  WifiOff,
  Pause,
  Play,
  Settings as SettingsIcon,
  Search,
  ExternalLink,
  ShieldCheck,
  TrendingUp,
  TrendingDown,
  Layers,
} from 'lucide-react';
import { rpcClient, RpcTelemetry } from '../services/rpcClient';
import { wsClient, WsConnectionStatus } from '../services/wsClient';
import { tokenPriceService } from '../services/tokenPrices';
import { TokenPriceFeed } from '../types/forensics';
import { SolanaCluster } from '../types/solana';

interface HeaderProps {
  currentCluster: SolanaCluster;
  onClusterChange: (cluster: SolanaCluster) => void;
  onOpenSettings: () => void;
  onSearchSignature: (sig: string) => void;
  isInvestigating?: boolean;
}

export const Header: React.FC<HeaderProps> = ({
  currentCluster,
  onClusterChange,
  onOpenSettings,
  onSearchSignature,
  isInvestigating,
}) => {
  const [telemetry, setTelemetry] = useState<RpcTelemetry>(rpcClient.getTelemetry());
  const [wsStatus, setWsStatus] = useState<WsConnectionStatus>(wsClient.getStatus());
  const [solPrice, setSolPrice] = useState<TokenPriceFeed | null>(null);
  const [headerSearch, setHeaderSearch] = useState('');

  useEffect(() => {
    wsClient.connect();
    const unsubTelemetry = rpcClient.subscribeTelemetry((t) => setTelemetry(t));
    const unsubWs = wsClient.subscribeStatus((s) => setWsStatus(s));
    const unsubPrice = tokenPriceService.subscribe((prices) => {
      if (prices['SOL']) setSolPrice(prices['SOL']);
    });

    return () => {
      unsubTelemetry();
      unsubWs();
      unsubPrice();
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

  return (
    <header className="h-16 border-b border-slate-800/80 bg-[#090b10]/95 backdrop-blur-md px-4 sm:px-5 flex items-center justify-between gap-2 sticky top-0 z-30">
      {/* Left: Quick search & cluster selector */}
      <div className="flex items-center gap-2.5 min-w-0">
        <form onSubmit={handleSearchSubmit} className="relative hidden md:block w-60 lg:w-72">
          <input
            type="text"
            value={headerSearch}
            onChange={(e) => setHeaderSearch(e.target.value)}
            placeholder="Inspect transaction signature (Base58)..."
            className="w-full bg-[#111722] border border-slate-700/60 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500/80 focus:ring-1 focus:ring-cyan-500/50 font-mono transition"
          />
          <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
        </form>

        <div className="flex items-center bg-[#111722] border border-slate-700/60 rounded-lg px-2 py-1 text-xs whitespace-nowrap">
          <span className="text-slate-400 mr-1.5 text-[10px] font-medium hidden sm:inline">NETWORK</span>
          <select
            value={currentCluster}
            onChange={(e) => onClusterChange(e.target.value as SolanaCluster)}
            aria-label="Select Solana Cluster"
            className="bg-transparent text-cyan-400 font-semibold focus:outline-none cursor-pointer text-xs"
          >
            <option value="mainnet" className="bg-[#111722] text-slate-200">
              Mainnet-Beta (6x Parallel)
            </option>
            <option value="devnet" className="bg-[#111722] text-slate-200">
              Solana Devnet (2x Parallel)
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

      {/* Center: Live Token Price Feed */}
      {solPrice && (
        <div className="hidden xl:flex items-center gap-2 bg-[#111722]/80 border border-slate-800 rounded-lg px-2.5 py-1 text-xs whitespace-nowrap shrink-0">
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

      {/* Right: RPC Telemetry, WebSocket Status & Settings */}
      <div className="flex items-center gap-2 shrink-0 whitespace-nowrap">
        {/* RPC Rate Limiter Telemetry Meter */}
        <div className="hidden lg:flex items-center gap-1.5 bg-[#111722] border border-slate-800 rounded-lg px-2.5 py-1 text-[11px]">
          <Activity className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
          <span className="font-mono font-semibold text-emerald-400">
            {telemetry.activePoolCount}x Pool
          </span>
          <span className="text-slate-600">|</span>
          <span className="font-mono font-semibold text-slate-200">
            {telemetry.requestsInWindow}/5 rps
          </span>
          <span className="text-slate-600">|</span>
          <span className="font-mono text-cyan-400">{telemetry.averageLatencyMs}ms</span>
        </div>

        {/* RPC Provider Health Badge */}
        <div
          title={`Last fulfilled by: ${telemetry.lastWinningProvider}`}
          className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg border text-[11px] font-medium capitalize ${getHealthColor()}`}
        >
          <span className={`w-2 h-2 rounded-full shrink-0 ${telemetry.providerHealth === 'healthy' ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'}`}></span>
          <span className="hidden sm:inline">RPC:</span>
          <span>{telemetry.providerHealth}</span>
        </div>

        {/* WebSocket Stream Control */}
        <button
          onClick={toggleWsPause}
          title={wsStatus === 'paused' ? 'Resume WebSocket Stream' : 'Pause WebSocket Stream'}
          className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg border text-[11px] font-medium transition ${
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
              <span className="hidden md:inline">WSS LIVE (3x)</span>
            </>
          ) : wsStatus === 'paused' ? (
            <>
              <Pause className="w-3 h-3 text-amber-400" />
              <span className="hidden md:inline">STREAM PAUSED</span>
            </>
          ) : (
            <>
              <WifiOff className="w-3 h-3 text-slate-400" />
              <span className="hidden md:inline">WSS CONNECTING</span>
            </>
          )}
        </button>

        {/* Settings Button */}
        <button
          onClick={onOpenSettings}
          title="RPC & Forensic Configuration"
          className="p-1.5 text-slate-400 hover:text-white bg-[#111722] hover:bg-slate-800 border border-slate-700/60 rounded-lg transition"
          aria-label="Settings"
        >
          <SettingsIcon className="w-4 h-4" />
        </button>
      </div>
    </header>
  );
};
