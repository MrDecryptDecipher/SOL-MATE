/**
 * SOL-MATE — Live Blockchain Real-Time Streaming & Alert Lifecycle Command Center
 * Real-time parallel WebSocket subscriptions with controlled cadence buffering,
 * automatic error-spam suppression, live Client Onboarding detection,
 * and Correlated Lifecycle (Previous -> Current -> Next) vs. Independent Alert classification.
 */

import React, { useState, useEffect, useRef, useMemo } from 'react';
import {
  Activity,
  Wifi,
  WifiOff,
  Pause,
  Play,
  Terminal,
  Zap,
  TrendingUp,
  TrendingDown,
  ShieldAlert,
  ArrowRight,
  CheckCircle2,
  UserCheck,
  GitBranch,
  Layers,
  Gauge,
} from 'lucide-react';
import { wsClient, LiveSlotNotification, LiveLogNotification, WsConnectionStatus } from '../services/wsClient';
import { tokenPriceService, KNOWN_MINTS } from '../services/tokenPrices';
import { TokenPriceFeed } from '../types/forensics';
import { isValidSolanaAddress } from '../services/transactionParser';

interface LiveMonitoringProps {
  onInvestigateSignature: (sig: string) => void;
  onSelectAddress: (addr: string) => void;
}

interface ClassifiedLiveAlert {
  raw: LiveLogNotification;
  receivedAt: number;
  alertCategory: 'CORRELATED_LIFECYCLE' | 'INDEPENDENT_ALERT';
  isClientOnboarded: boolean;
  alertTypeCode: string;
  alertTitle: string;
  tokenInvolved: string;
  previousCorrelatedAlert?: string;
  nextPossibleAlert?: string;
  independentReason?: string;
}

function classifyLiveLogEvent(item: LiveLogNotification, watchedAddress: string): ClassifiedLiveAlert {
  const logsText = (item.logs || []).join(' ');
  const isSuccess = item.err === null;

  // Detect token / onboarding instructions in logs
  const hasCreateAta =
    logsText.includes('Create') ||
    logsText.includes('InitializeAccount') ||
    logsText.includes('InitializeImmutableOwner');
  const hasMintTo = logsText.includes('Instruction: MintTo') || logsText.includes('MintToChecked');
  const hasTransfer = logsText.includes('Instruction: Transfer') || logsText.includes('TransferChecked');
  const hasSwap = logsText.includes('Instruction: Route') || logsText.includes('Swap') || logsText.includes('whirlpool');
  const hasBurn = logsText.includes('Instruction: Burn');

  let tokenInvolved = 'Solana SPL / Token-2022 Asset';
  if (watchedAddress.startsWith('J4cT') || logsText.includes('J4cT')) {
    tokenInvolved = 'J.P. Morgan JLTXX Institutional Token (JLTXX)';
  } else if (watchedAddress.startsWith('EToD') || logsText.includes('EToD')) {
    tokenInvolved = 'J.P. Morgan MONY Institutional Token (MONY)';
  } else if (watchedAddress.startsWith('9rdASs') || logsText.includes('9rdASs')) {
    tokenInvolved = 'J.P. Morgan FACT Institutional Token Suite (JLTXX / MONY)';
  } else if (watchedAddress === 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb') {
    tokenInvolved = 'Solana Token-2022 Extension Asset';
  } else if (watchedAddress === 'JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4') {
    tokenInvolved = 'Jupiter Aggregator Routed SPL Pair (SOL / USDC / SPL)';
  }

  if (!isSuccess) {
    return {
      raw: item,
      receivedAt: Date.now(),
      alertCategory: 'INDEPENDENT_ALERT',
      isClientOnboarded: false,
      alertTypeCode: 'INDEPENDENT_RUNTIME_REVERT',
      alertTitle: 'Independent Runtime Execution Revert (Slippage / Guard Failure)',
      tokenInvolved,
      independentReason:
        'Standalone aborted transaction — state changes were rolled back by the Solana runtime VM; no downstream lifecycle state was created.',
    };
  }

  if (hasCreateAta || hasMintTo) {
    return {
      raw: item,
      receivedAt: Date.now(),
      alertCategory: 'CORRELATED_LIFECYCLE',
      isClientOnboarded: true,
      alertTypeCode: 'CLIENT_ONBOARDING_AND_PROVISIONING',
      alertTitle: hasMintTo
        ? 'Client Token Onboarding & Initial Supply Issuance'
        : 'Client Associated Token Account (ATA) Onboarding Initialized',
      tokenInvolved,
      previousCorrelatedAlert: 'Stage 1: Token Mint & Controller Authority Initialization',
      nextPossibleAlert: 'Stage 3: Institutional Settlement Transfer or Secondary Allocation',
    };
  }

  if (hasBurn) {
    return {
      raw: item,
      receivedAt: Date.now(),
      alertCategory: 'CORRELATED_LIFECYCLE',
      isClientOnboarded: false,
      alertTypeCode: 'TOKEN_REDEMPTION_BURN_LIFECYCLE',
      alertTitle: 'Correlated Token Supply Redemption & Burn Settlement',
      tokenInvolved,
      previousCorrelatedAlert: 'Prior Stage: Client Token Custody Holding & Settlement Approval',
      nextPossibleAlert: 'Terminal Stage: Vault Closure & Rent Lamport Reclamation',
    };
  }

  if (hasSwap || hasTransfer) {
    return {
      raw: item,
      receivedAt: Date.now(),
      alertCategory: 'CORRELATED_LIFECYCLE',
      isClientOnboarded: false,
      alertTypeCode: hasSwap ? 'CORRELATED_LIQUIDITY_SWAP' : 'CORRELATED_TOKEN_SETTLEMENT',
      alertTitle: hasSwap
        ? 'Multi-Hop Liquidity Routing & Token Settlement'
        : 'Verified SPL / Token-2022 Holder Balance Transfer',
      tokenInvolved,
      previousCorrelatedAlert: 'Prior Stage: Token Account Provisioning & Balance Funding',
      nextPossibleAlert: 'Next Possible Alert: Downstream Custody Sweep, LP Rebalance, or Redemption',
    };
  }

  return {
    raw: item,
    receivedAt: Date.now(),
    alertCategory: 'INDEPENDENT_ALERT',
    isClientOnboarded: false,
    alertTypeCode: 'INDEPENDENT_PROGRAM_INVOCATION',
    alertTitle: 'Standalone Smart Contract State / Compute Execution',
    tokenInvolved,
    independentReason:
      'Isolated program invocation without multi-stage token onboarding or custody transfer correlation.',
  };
}

export const LiveMonitoring: React.FC<LiveMonitoringProps> = ({
  onInvestigateSignature,
}) => {
  const [status, setStatus] = useState<WsConnectionStatus>(wsClient.getStatus());
  const [currentSlot, setCurrentSlot] = useState<LiveSlotNotification | null>(null);
  const [classifiedLogs, setClassifiedLogs] = useState<ClassifiedLiveAlert[]>([]);
  const [watchedAddress, setWatchedAddress] = useState<string>(
    'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb' // Default to Token-2022 Program for clean, high-signal token & onboarding events
  );
  const [customAddressInput, setCustomAddressInput] = useState('');
  const [addressError, setAddressError] = useState<string | null>(null);
  const [tokenPrices, setTokenPrices] = useState<Record<string, TokenPriceFeed>>({});
  const [isPaused, setIsPaused] = useState(wsClient.isStreamPaused());
  const [streamFilter, setStreamFilter] = useState<'success-only' | 'onboarding-alerts' | 'all' | 'errors-only'>('success-only');
  const [cadenceMs, setCadenceMs] = useState<number>(1800); // Controlled 1.8s cadence so stream never blurs

  const pendingBufferRef = useRef<ClassifiedLiveAlert[]>([]);

  useEffect(() => {
    const unsubStatus = wsClient.subscribeStatus((s) => {
      setStatus(s);
      setIsPaused(wsClient.isStreamPaused());
    });

    const unsubSlot = wsClient.subscribeSlot((slotData) => {
      setCurrentSlot(slotData);
    });

    const unsubLogs = wsClient.subscribeLogs({ mentions: [watchedAddress] }, (logData) => {
      const classified = classifyLiveLogEvent(logData, watchedAddress);
      // Buffer incoming events so UI updates smoothly at controlled cadence
      if (pendingBufferRef.current.length < 30) {
        pendingBufferRef.current.unshift(classified);
      }
    });

    const unsubPrices = tokenPriceService.subscribe((prices) => {
      setTokenPrices(prices);
    });

    return () => {
      unsubStatus();
      unsubSlot();
      unsubLogs();
      unsubPrices();
    };
  }, [watchedAddress]);

  // Controlled flush interval so the stream is calm, readable, and never floods with fast errors
  useEffect(() => {
    const timer = setInterval(() => {
      if (isPaused || pendingBufferRef.current.length === 0) return;
      const batch = pendingBufferRef.current.splice(0, 2); // Release at most 2 items per cadence tick
      setClassifiedLogs((prev) => [...batch, ...prev].slice(0, 40));
    }, cadenceMs);

    return () => clearInterval(timer);
  }, [cadenceMs, isPaused]);

  const handleSetWatchedAddress = (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = customAddressInput.trim();
    if (!trimmed) return;
    if (!isValidSolanaAddress(trimmed)) {
      setAddressError('Invalid Solana address format (32-44 Base58 characters).');
      return;
    }
    setAddressError(null);
    pendingBufferRef.current = [];
    setClassifiedLogs([]);
    setWatchedAddress(trimmed);
  };

  const togglePause = () => {
    if (wsClient.isStreamPaused()) {
      wsClient.resume();
    } else {
      wsClient.pause();
    }
    setIsPaused(wsClient.isStreamPaused());
  };

  const filteredItems = useMemo(() => {
    return classifiedLogs.filter((item) => {
      if (streamFilter === 'success-only') return item.raw.err === null;
      if (streamFilter === 'onboarding-alerts')
        return item.isClientOnboarded || item.alertCategory === 'CORRELATED_LIFECYCLE';
      if (streamFilter === 'errors-only') return item.raw.err !== null;
      return true;
    });
  }, [classifiedLogs, streamFilter]);

  const onboardingCount = classifiedLogs.filter((c) => c.isClientOnboarded).length;
  const correlatedCount = classifiedLogs.filter((c) => c.alertCategory === 'CORRELATED_LIFECYCLE').length;
  const independentCount = classifiedLogs.filter((c) => c.alertCategory === 'INDEPENDENT_ALERT').length;

  return (
    <div className="max-w-6xl mx-auto px-4 py-8 space-y-6">
      {/* Top Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-[#0d121c] border border-cyan-500/20 rounded-2xl p-5 shadow-xl">
        <div className="space-y-1.5">
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-pulse"></span>
            <h2 className="text-xl font-extrabold text-white">
              Live Blockchain Parallel WSS & Alert Lifecycle Stream
            </h2>
          </div>
          <p className="text-xs text-slate-400">
            Simultaneous deduplicated WebSocket feeds with automatic revert-spam filtering & lifecycle correlation:
          </p>
          <div className="flex flex-wrap items-center gap-2 pt-0.5">
            {wsClient.getConnectedProviders().map((p) => (
              <span
                key={p.name}
                className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-md text-[10px] font-mono border ${
                  p.status === 'connected'
                    ? 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30'
                    : 'bg-slate-800/80 text-slate-400 border-slate-700'
                }`}
              >
                <span
                  className={`w-1.5 h-1.5 rounded-full ${
                    p.status === 'connected' ? 'bg-emerald-400' : 'bg-amber-400'
                  }`}
                ></span>
                <span>{p.name}</span>
              </span>
            ))}
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          {/* Cadence Speed Control */}
          <div className="flex items-center gap-1.5 bg-[#090d14] border border-slate-800 px-2.5 py-1.5 rounded-xl text-xs">
            <Gauge className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-slate-400 text-[11px]">Cadence:</span>
            <select
              value={cadenceMs}
              onChange={(e) => setCadenceMs(Number(e.target.value))}
              className="bg-transparent text-cyan-300 font-mono font-bold text-xs focus:outline-none cursor-pointer"
            >
              <option value={1800} className="bg-[#090d14]">Controlled (1.8s)</option>
              <option value={3200} className="bg-[#090d14]">Calm Inspection (3.2s)</option>
              <option value={800} className="bg-[#090d14]">Fast (0.8s)</option>
            </select>
          </div>

          <div
            className={`flex items-center gap-2 px-3 py-1.5 rounded-xl border text-xs font-bold ${
              status === 'connected'
                ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                : status === 'paused'
                ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                : 'bg-rose-500/10 text-rose-400 border-rose-500/30'
            }`}
          >
            {status === 'connected' ? <Wifi className="w-3.5 h-3.5" /> : <WifiOff className="w-3.5 h-3.5" />}
            <span className="uppercase">{status}</span>
          </div>

          <button
            onClick={togglePause}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 border border-slate-700 transition cursor-pointer"
          >
            {isPaused ? <Play className="w-3.5 h-3.5 text-emerald-400" /> : <Pause className="w-3.5 h-3.5 text-amber-400" />}
            <span>{isPaused ? 'Resume Stream' : 'Pause Stream'}</span>
          </button>
        </div>
      </div>

      {/* Metrics Row: Slot Tracker & Live Token Market Feeds */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-[#0f1522] border border-slate-800 rounded-2xl p-5 space-y-3">
          <div className="flex items-center justify-between text-xs">
            <span className="font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
              <Zap className="w-3.5 h-3.5 text-cyan-400" /> Current Slot Height
            </span>
            <span className="text-[10px] text-emerald-400 font-mono font-bold animate-pulse">LIVE WSS</span>
          </div>

          <div className="text-2xl sm:text-3xl font-mono font-extrabold text-white">
            {currentSlot ? currentSlot.slot.toLocaleString() : 'Syncing Slot...'}
          </div>

          <div className="flex items-center justify-between text-[11px] text-slate-400 pt-2 border-t border-slate-800/80">
            <span>
              Root Slot:{' '}
              <strong className="text-slate-200 font-mono">{currentSlot?.root.toLocaleString() || '---'}</strong>
            </span>
            <span>
              Parent:{' '}
              <strong className="text-slate-200 font-mono">{currentSlot?.parent.toLocaleString() || '---'}</strong>
            </span>
          </div>
        </div>

        {/* Live Token Prices Cards */}
        <div className="bg-[#0f1522] border border-slate-800 rounded-2xl p-5 space-y-3 md:col-span-2">
          <div className="flex items-center justify-between text-xs">
            <span className="font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
              <Activity className="w-3.5 h-3.5 text-cyan-400" /> Live Token Market Feeds & Institutional Mints
            </span>
            <span className="text-[10px] text-slate-500">Auto-refresh 20s</span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-1">
            {Object.entries(KNOWN_MINTS)
              .slice(0, 4)
              .map(([mint, info]) => {
                const price = tokenPrices[info.symbol] || tokenPrices[mint];
                return (
                  <div key={mint} className="bg-[#090d14] p-3 rounded-xl border border-slate-800/80">
                    <div className="flex items-center justify-between text-xs font-bold text-slate-300">
                      <span>{info.symbol}</span>
                      <span className="text-[10px] text-slate-500">{info.name.split(' ')[0]}</span>
                    </div>
                    <div className="text-base font-mono font-bold text-white mt-1">
                      {price ? `$${price.priceUsd.toFixed(price.priceUsd < 1 ? 4 : 2)}` : 'Live...'}
                    </div>
                    {price && price.change24h !== 0 && (
                      <div
                        className={`text-[10px] font-mono mt-0.5 flex items-center gap-0.5 ${
                          price.change24h >= 0 ? 'text-emerald-400' : 'text-rose-400'
                        }`}
                      >
                        {price.change24h >= 0 ? (
                          <TrendingUp className="w-3 h-3" />
                        ) : (
                          <TrendingDown className="w-3 h-3" />
                        )}
                        <span>
                          {price.change24h > 0 ? '+' : ''}
                          {price.change24h.toFixed(2)}%
                        </span>
                      </div>
                    )}
                  </div>
                );
              })}
          </div>
        </div>
      </div>

      {/* Live Alert Lifecycle Summary Counters */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="p-4 rounded-2xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-between">
          <div>
            <span className="text-[11px] font-bold uppercase tracking-wider text-emerald-300 block">
              Client Token Onboarding Alerts
            </span>
            <p className="text-[11px] text-slate-300 mt-0.5">
              New ATA / 0→Positive Balance Client Provisioning
            </p>
          </div>
          <span className="text-2xl font-mono font-extrabold text-emerald-300">{onboardingCount}</span>
        </div>

        <div className="p-4 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-between">
          <div>
            <span className="text-[11px] font-bold uppercase tracking-wider text-cyan-300 block">
              Correlated Lifecycle Alerts
            </span>
            <p className="text-[11px] text-slate-300 mt-0.5">
              Linked to Previous & Next Predicted Stages
            </p>
          </div>
          <span className="text-2xl font-mono font-extrabold text-cyan-300">{correlatedCount}</span>
        </div>

        <div className="p-4 rounded-2xl bg-violet-500/10 border border-violet-500/30 flex items-center justify-between">
          <div>
            <span className="text-[11px] font-bold uppercase tracking-wider text-violet-300 block">
              Independent Standalone Alerts
            </span>
            <p className="text-[11px] text-slate-300 mt-0.5">
              Isolated Invocations & Filtered Arbitrage Reverts
            </p>
          </div>
          <span className="text-2xl font-mono font-extrabold text-violet-300">{independentCount}</span>
        </div>
      </div>

      {/* Real-time Address Log & Alert Lifecycle Stream */}
      <div className="bg-[#0f1522] border border-slate-800 rounded-2xl p-5 space-y-4">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-cyan-400" />
              <h3 className="font-bold text-sm text-white">
                Live Program Invocation, Client Onboarding & Alert Lifecycle Stream
              </h3>
            </div>
            <p className="text-xs text-slate-400 break-all">
              Monitoring Target Address: <code className="text-cyan-300 font-mono">{watchedAddress}</code>
            </p>
          </div>

          <form onSubmit={handleSetWatchedAddress} className="flex items-center gap-2">
            <input
              type="text"
              value={customAddressInput}
              onChange={(e) => setCustomAddressInput(e.target.value)}
              placeholder="Watch specific program or mint address..."
              className="w-64 sm:w-80 bg-[#090d14] border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-100 placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-400"
            />
            <button
              type="submit"
              className="px-3.5 py-1.5 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs rounded-lg transition cursor-pointer"
            >
              Watch
            </button>
          </form>
        </div>

        {addressError && (
          <p className="text-xs text-rose-400 bg-rose-500/10 border border-rose-500/30 p-2 rounded-lg">
            {addressError}
          </p>
        )}

        {/* Quick Presets & Stream Filter Bar */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-1 border-t border-slate-800/80">
          <div className="flex flex-wrap items-center gap-1.5 text-xs">
            <span className="text-slate-500 text-[11px] mr-1">Quick Watch:</span>
            {[
              { label: 'Token-2022 Program (Recommended)', addr: 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb' },
              { label: 'J.P. Morgan FACT Program', addr: '9rdASsDUnrw2EsDARtfqjabqcjfXYFKu45kZ31wF74dg' },
              { label: 'SPL Token Program', addr: 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA' },
              { label: 'Jupiter DEX v6', addr: 'JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4' },
              { label: 'Raydium AMM', addr: '675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8' },
            ].map((p) => (
              <button
                key={p.addr}
                onClick={() => {
                  pendingBufferRef.current = [];
                  setClassifiedLogs([]);
                  setWatchedAddress(p.addr);
                }}
                className={`px-2.5 py-1 rounded-lg border font-mono text-[11px] transition cursor-pointer ${
                  watchedAddress === p.addr
                    ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40 font-bold'
                    : 'bg-slate-800/80 text-slate-400 border-slate-700 hover:text-white'
                }`}
              >
                {p.label}
              </button>
            ))}
          </div>

          {/* Filter Mode Buttons (Defaults to Verified Success Only so fast errors don't spam!) */}
          <div className="flex items-center gap-1 bg-[#090d14] p-1 rounded-xl border border-slate-800 text-[11px]">
            {[
              { id: 'success-only', label: 'Verified Success (No Errors)' },
              { id: 'onboarding-alerts', label: 'Onboarding & Lifecycle' },
              { id: 'all', label: 'All Events' },
              { id: 'errors-only', label: 'Reverts Only' },
            ].map((f) => (
              <button
                key={f.id}
                onClick={() => setStreamFilter(f.id as any)}
                className={`px-2.5 py-1 rounded-lg font-semibold transition cursor-pointer ${
                  streamFilter === f.id
                    ? 'bg-cyan-500 text-slate-950 font-bold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {f.label}
              </button>
            ))}
          </div>
        </div>

        {/* Live Classified Alert & Log Cards */}
        <div className="bg-[#080b11] border border-slate-800/90 rounded-xl p-4 font-mono text-xs max-h-[540px] overflow-y-auto space-y-3">
          {filteredItems.length === 0 ? (
            <div className="text-center py-12 text-slate-400 space-y-2">
              <Activity className="w-6 h-6 mx-auto text-cyan-400 animate-pulse" />
              <p className="font-sans font-semibold text-slate-300">
                Streaming verified on-chain events for {watchedAddress}...
              </p>
              <p className="text-[11px] text-slate-500 font-sans">
                Failed arbitrage reverts are automatically filtered out in "Verified Success" mode. New events arrive at a calm {cadenceMs / 1000}s cadence.
              </p>
            </div>
          ) : (
            filteredItems.map((entry, idx) => {
              const item = entry.raw;
              const sig = item.signature || '';
              return (
                <div
                  key={`${sig}-${idx}`}
                  className={`p-4 rounded-xl border transition space-y-2.5 ${
                    entry.isClientOnboarded
                      ? 'bg-emerald-950/20 border-emerald-500/40'
                      : entry.alertCategory === 'CORRELATED_LIFECYCLE'
                      ? 'bg-[#0d1422] border-cyan-500/30'
                      : 'bg-[#0d121c] border-slate-800'
                  }`}
                >
                  {/* Top Row: Status + Alert Type + Client Onboarding Badge + Investigate CTA */}
                  <div className="flex flex-wrap items-center justify-between gap-2 text-[11px]">
                    <div className="flex flex-wrap items-center gap-2">
                      <span
                        className={`px-2 py-0.5 rounded font-bold text-[10px] ${
                          item.err === null
                            ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                            : 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                        }`}
                      >
                        {item.err === null ? 'VERIFIED SUCCESS' : 'REVERTED'}
                      </span>

                      <span
                        className={`px-2 py-0.5 rounded font-bold text-[10px] ${
                          entry.alertCategory === 'CORRELATED_LIFECYCLE'
                            ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                            : 'bg-violet-500/20 text-violet-300 border border-violet-500/30'
                        }`}
                      >
                        {entry.alertCategory === 'CORRELATED_LIFECYCLE'
                          ? 'CORRELATED LIFECYCLE ALERT'
                          : 'INDEPENDENT STANDALONE ALERT'}
                      </span>

                      {entry.isClientOnboarded && (
                        <span className="px-2 py-0.5 rounded bg-emerald-500 text-slate-950 font-extrabold text-[10px] flex items-center gap-1">
                          <UserCheck className="w-3 h-3" /> CLIENT ONBOARDED FOR TOKEN
                        </span>
                      )}
                    </div>

                    <button
                      onClick={() => onInvestigateSignature(sig)}
                      className="text-[11px] font-bold text-slate-950 bg-cyan-400 hover:bg-cyan-300 flex items-center gap-1 px-3 py-1 rounded-lg transition cursor-pointer"
                    >
                      <span>Investigate Full Case</span>
                      <ArrowRight className="w-3 h-3" />
                    </button>
                  </div>

                  {/* Alert Title & Full Signature */}
                  <div className="space-y-1 font-sans">
                    <div className="font-bold text-sm text-white">{entry.alertTitle}</div>
                    <div className="text-xs text-slate-300">
                      Token / Context Involved: <strong className="text-cyan-300">{entry.tokenInvolved}</strong>
                    </div>
                    <div className="text-[11px] font-mono text-slate-400 break-all">
                      Signature: <span className="text-cyan-300 select-all">{sig}</span>
                    </div>
                  </div>

                  {/* Lifecycle Correlation Chain OR Independent Alert Explanation */}
                  {entry.alertCategory === 'CORRELATED_LIFECYCLE' ? (
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-2 pt-1 font-sans text-[11px]">
                      <div className="p-2.5 rounded-lg bg-[#090d14] border border-slate-800">
                        <span className="text-[9px] font-mono uppercase text-slate-400 block">
                          1. Previous Related Alert
                        </span>
                        <span className="text-slate-200 font-semibold">{entry.previousCorrelatedAlert}</span>
                      </div>
                      <div className="p-2.5 rounded-lg bg-cyan-500/10 border border-cyan-500/40">
                        <span className="text-[9px] font-mono uppercase text-cyan-300 block">
                          2. Current Active Alert
                        </span>
                        <span className="text-white font-bold">{entry.alertTitle}</span>
                      </div>
                      <div className="p-2.5 rounded-lg bg-[#090d14] border border-slate-800">
                        <span className="text-[9px] font-mono uppercase text-amber-300 block">
                          3. Next Predicted Alert
                        </span>
                        <span className="text-slate-200 font-semibold">{entry.nextPossibleAlert}</span>
                      </div>
                    </div>
                  ) : (
                    <div className="p-2.5 rounded-lg bg-violet-500/10 border border-violet-500/25 font-sans text-[11px] text-slate-300">
                      <strong className="text-violet-300">Independent Alert Classification:</strong>{' '}
                      {entry.independentReason}
                    </div>
                  )}

                  {/* Raw Execution Logs Preview */}
                  <div className="text-[11px] text-slate-400 space-y-0.5 pl-2.5 border-l-2 border-slate-800 pt-1">
                    {(item.logs || []).slice(0, 4).map((log, lIdx) => (
                      <div key={lIdx} className="text-slate-300 break-all">
                        {log}
                      </div>
                    ))}
                    {(item.logs || []).length > 4 && (
                      <div className="text-[10px] text-slate-500">
                        + {item.logs.length - 4} more program execution logs (click "Investigate Full Case" for complete trace)
                      </div>
                    )}
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
};
