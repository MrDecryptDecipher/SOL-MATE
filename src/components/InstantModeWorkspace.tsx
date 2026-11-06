/**
 * SOL-MATE — Instant Mode Dedicated Workspace
 * High-cadence 1-second continuous scanner strictly monitoring institutional whitelisted addresses.
 * Excludes generic public infrastructure so only verified institutional entities are tracked.
 * 
 * Instantly identifies:
 * 1. METHOD BEING USED: Full range of decompiled method IDs (Token-2022 opcodes 0-43, Anchor sighashes, FACT methods, EVM selectors)
 * 2. AUTHORITY INVOLVED: Mint Authority PDA, Freeze Authority, Token Admin, Tokenization Agent, EOA Signer
 * 3. ADDRESSES INVOLVED: Target, Authority, Onboarded Client Vaults, Counterparty Signers
 * 
 * All telemetry strictly timestamped in authentic Indian Date and TIME (IST / Asia/Kolkata).
 */

import React, { useState, useEffect, useMemo } from 'react';
import {
  Zap,
  Pause,
  Play,
  RotateCcw,
  Search,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  ShieldCheck,
  Copy,
  Check,
  Clock,
  Radio,
  Layers,
  KeyRound,
  Activity,
  Code2,
} from 'lucide-react';
import {
  instantScannerService,
  InstantActivityAlert,
} from '../services/instantScannerService';
import { InstitutionalEntityMeta } from '../services/protocolIntelligence';
import { formatToIST } from '../utils/istTime';

interface InstantModeWorkspaceProps {
  onInvestigateSignature: (sig: string) => void;
  onSelectAddress: (addr: string) => void;
  onSwitchToEaseMode: () => void;
  onSwitchToProMode: () => void;
}

export const InstantModeWorkspace: React.FC<InstantModeWorkspaceProps> = ({
  onInvestigateSignature,
  onSelectAddress,
  onSwitchToEaseMode,
  onSwitchToProMode,
}) => {
  const [isRunning, setIsRunning] = useState<boolean>(() =>
    instantScannerService.isScannerRunning()
  );
  const [alerts, setAlerts] = useState<InstantActivityAlert[]>(() =>
    instantScannerService.getAlerts()
  );

  // Strictly whitelisted institutional entities
  const whitelistedEntities = useMemo(
    () => instantScannerService.getWhitelistedAddresses(),
    []
  );

  const [status, setStatus] = useState({
    isRunning: instantScannerService.isScannerRunning(),
    scanCount: 0,
    alertsCount: instantScannerService.getAlerts().length,
    lastScannedIST: formatToIST(Date.now()),
    currentAddressIndex: 0,
    totalAddresses: whitelistedEntities.length,
    ratePerSec: 1,
  });

  const [selectedAlert, setSelectedAlert] = useState<InstantActivityAlert | null>(
    () => instantScannerService.getAlerts()[0] || null
  );
  const [filterCategory, setFilterCategory] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  useEffect(() => {
    // Start scanner automatically when entering Instant Mode
    if (!instantScannerService.isScannerRunning()) {
      instantScannerService.start();
      setIsRunning(true);
    }

    const unsubAlerts = instantScannerService.subscribeAlerts((newAlert) => {
      setAlerts((prev) => [newAlert, ...prev]);
      setSelectedAlert(newAlert);
    });

    const unsubStatus = instantScannerService.subscribeStatus((newStatus) => {
      setStatus(newStatus);
      setIsRunning(newStatus.isRunning);
    });

    return () => {
      unsubAlerts();
      unsubStatus();
    };
  }, []);

  const toggleScanner = () => {
    if (isRunning) {
      instantScannerService.stop();
      setIsRunning(false);
    } else {
      instantScannerService.start();
      setIsRunning(true);
    }
  };

  const handleSimulateTrigger = (targetMeta?: InstitutionalEntityMeta, method?: string) => {
    const newAlert = instantScannerService.triggerTestActivity(targetMeta, method);
    setSelectedAlert(newAlert);
  };

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard?.writeText(text);
    setCopiedId(id);
    setTimeout(() => {
      setCopiedId((prev) => (prev === id ? null : prev));
    }, 2000);
  };

  const filteredAlerts = useMemo(() => {
    return alerts.filter((a) => {
      if (filterCategory !== 'ALL' && a.category !== filterCategory) {
        return false;
      }
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        return (
          a.methodUsed.toLowerCase().includes(q) ||
          a.targetAddress.toLowerCase().includes(q) ||
          a.signature.toLowerCase().includes(q) ||
          a.authority.address.toLowerCase().includes(q) ||
          a.authority.label.toLowerCase().includes(q) ||
          a.summary.toLowerCase().includes(q) ||
          (a.subsystem && a.subsystem.toLowerCase().includes(q)) ||
          (a.opcodeOrSighash && a.opcodeOrSighash.toLowerCase().includes(q)) ||
          a.addressesInvolved.some(
            (inv) =>
              inv.address.toLowerCase().includes(q) ||
              inv.role.toLowerCase().includes(q)
          )
        );
      }
      return true;
    });
  }, [alerts, filterCategory, searchQuery]);

  // Current address being scanned right now in 1s cycle
  const currentScannedEntity =
    whitelistedEntities[status.currentAddressIndex % Math.max(1, whitelistedEntities.length)];

  const methodFilterCategories = [
    'ALL',
    'MINT',
    'BURN',
    'STOPCODES',
    'ACCOUNT_INIT',
    'AUTHORITY',
    'TRANSFER_HOOK',
    'GOVERNANCE',
    'SECURITY_CIRCUIT_BREAKER',
    'TRANSFER',
  ];

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 py-6 space-y-6">
      {/* =====================================================================
          HEADER SECTION: INSTANT MODE TELEMETRY, 1-SEC CYCLE METERS & CONTROLS
         ===================================================================== */}
      <section className="bg-[#0d1320] border border-cyan-500/40 rounded-2xl p-5 sm:p-6 shadow-2xl relative overflow-hidden">
        <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-amber-400 via-cyan-400 to-emerald-400" />

        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 mb-4">
          <div className="space-y-1">
            <div className="inline-flex items-center gap-2 text-xs font-mono font-bold text-amber-400">
              <Zap className="w-4 h-4 text-amber-400 animate-pulse" />
              <span>INSTANT MODE • 1-SECOND CONTINUOUS WHITELIST SCANNER</span>
            </div>
            <h1 className="text-xl sm:text-2xl font-extrabold text-white">
              Continuous Real-Time Whitelist Activity &amp; Method/Authority Detector
            </h1>
            <p className="text-xs text-slate-300 max-w-3xl">
              Continuously scans every second across all <strong className="text-emerald-400">{whitelistedEntities.length} pre-trained institutional whitelisted addresses</strong>. When any on-chain activity or state mutation occurs, SOL-MATE immediately classifies the <strong className="text-cyan-300">method being used</strong>, highlights the <strong className="text-amber-300">authority involved</strong>, and verifies all <strong className="text-emerald-300">addresses involved</strong>.
            </p>
          </div>

          {/* Quick Scanner Action Controls */}
          <div className="flex flex-wrap items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={toggleScanner}
              className={`px-4 py-2.5 rounded-xl font-mono text-xs font-extrabold flex items-center gap-2 transition cursor-pointer shadow-lg ${
                isRunning
                  ? 'bg-amber-500 text-slate-950 hover:bg-amber-400 shadow-amber-500/20'
                  : 'bg-emerald-500 text-slate-950 hover:bg-emerald-400 shadow-emerald-500/20'
              }`}
            >
              {isRunning ? (
                <>
                  <Pause className="w-4 h-4 fill-current" />
                  <span>PAUSE SCANNER (1s ACTIVE)</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-current" />
                  <span>RESUME CONTINUOUS SCAN</span>
                </>
              )}
            </button>

            <button
              type="button"
              onClick={() => handleSimulateTrigger()}
              className="px-3.5 py-2.5 rounded-xl bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-400/50 text-cyan-300 font-mono text-xs font-bold flex items-center gap-1.5 transition cursor-pointer"
              title="Test the 1-second instant alert triggering"
            >
              <Zap className="w-3.5 h-3.5 text-cyan-400" />
              <span>Trigger Test Alert</span>
            </button>

            <button
              type="button"
              onClick={() => instantScannerService.clearAlerts()}
              className="px-3 py-2.5 rounded-xl bg-[#080c14] hover:bg-slate-800 border border-slate-700 text-slate-400 hover:text-white font-mono text-xs transition cursor-pointer"
              title="Clear alerts list"
            >
              <RotateCcw className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Live 1-Second Continuous Telemetry Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-3 border-t border-slate-800">
          <div className="p-3 rounded-xl bg-[#080c14] border border-slate-800 space-y-1">
            <div className="flex items-center justify-between text-slate-400 text-[11px] font-mono">
              <span>SCANNER STATUS</span>
              <span className={`w-2 h-2 rounded-full ${isRunning ? 'bg-emerald-400 animate-ping' : 'bg-slate-600'}`} />
            </div>
            <div className="text-base font-extrabold font-mono text-white flex items-center gap-1.5">
              <span className={isRunning ? 'text-emerald-400' : 'text-slate-400'}>
                {isRunning ? '1-SEC ACTIVE' : 'PAUSED'}
              </span>
            </div>
            <div className="text-[10px] text-slate-500 font-mono">
              Cadence: 1,000ms • Strict Whitelist
            </div>
          </div>

          <div className="p-3 rounded-xl bg-[#080c14] border border-slate-800 space-y-1">
            <div className="text-slate-400 text-[11px] font-mono">MONITORED WHITELIST</div>
            <div className="text-base font-extrabold font-mono text-cyan-400">
              {whitelistedEntities.length} Entities
            </div>
            <div className="text-[10px] text-slate-400 font-mono truncate">
              {currentScannedEntity?.shortLabel || 'Scanning Whitelist...'}
            </div>
          </div>

          <div className="p-3 rounded-xl bg-[#080c14] border border-slate-800 space-y-1">
            <div className="text-slate-400 text-[11px] font-mono">ACTIVITY ALERTS DETECTED</div>
            <div className="text-base font-extrabold font-mono text-amber-400">
              {alerts.length} Instant Alerts
            </div>
            <div className="text-[10px] text-slate-500 font-mono">
              Total Scans: {status.scanCount.toLocaleString()}
            </div>
          </div>

          <div className="p-3 rounded-xl bg-[#080c14] border border-slate-800 space-y-1">
            <div className="text-slate-400 text-[11px] font-mono">INDIAN DATE &amp; TIME (IST)</div>
            <div className="text-xs font-extrabold font-mono text-emerald-300 truncate" title={status.lastScannedIST}>
              {status.lastScannedIST || formatToIST(Date.now())}
            </div>
            <div className="text-[10px] text-slate-500 font-mono">
              Asia/Kolkata (UTC+05:30)
            </div>
          </div>
        </div>

        {/* Live scanning progress ticker line */}
        <div className="mt-3 pt-2 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono text-slate-400">
          <div className="flex items-center gap-2">
            <Radio className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
            <span>
              Actively checking whitelisted address: <strong className="text-slate-200">{currentScannedEntity?.address}</strong> ({currentScannedEntity?.shortLabel})
            </span>
          </div>
          <span className="text-emerald-400 font-bold">
            Strict Institutional Whitelist Only • 0-Delay Alerting
          </span>
        </div>
      </section>

      {/* =====================================================================
          MAIN SPLIT VIEW: LEFT (INSTANT ALERTS STREAM) & RIGHT (DEEP ALERT INSPECTION)
         ===================================================================== */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left 5 Cols: Incoming Instant Activity Alerts List */}
        <div className="lg:col-span-5 space-y-3">
          <div className="p-3.5 rounded-xl bg-[#0c121e] border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono font-bold text-white flex items-center gap-2">
                <Activity className="w-4 h-4 text-cyan-400" />
                Live Whitelist Alert Feed ({filteredAlerts.length})
              </span>
              <span className="text-[10px] font-mono text-slate-400">
                Sorted by most recent
              </span>
            </div>

            {/* Filter Categories for all method ranges */}
            <div className="flex flex-wrap items-center gap-1">
              {methodFilterCategories.map((cat) => (
                <button
                  key={cat}
                  type="button"
                  onClick={() => setFilterCategory(cat)}
                  className={`px-2 py-1 rounded-md text-[10px] font-mono font-bold transition cursor-pointer ${
                    filterCategory === cat
                      ? 'bg-cyan-500 text-slate-950'
                      : 'bg-[#080c14] text-slate-400 hover:text-white border border-slate-800'
                  }`}
                >
                  {cat}
                </button>
              ))}
            </div>

            {/* Search filter input */}
            <div className="relative">
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search method, address, authority, signature..."
                className="w-full bg-[#080c14] border border-slate-700/80 rounded-lg pl-8 pr-3 py-1.5 text-xs text-white placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-400"
              />
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2.5" />
            </div>
          </div>

          {/* Alert cards stream */}
          <div className="space-y-2.5 max-h-[640px] overflow-y-auto pr-1">
            {filteredAlerts.length === 0 ? (
              <div className="p-8 text-center rounded-xl bg-[#080c14] border border-slate-800 space-y-2">
                <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto" />
                <div className="text-sm font-bold text-white">No Unacknowledged Whitelist Alerts</div>
                <p className="text-xs text-slate-400">
                  Continuous 1-second scanner is monitoring verified institutional addresses. Click &quot;Trigger Test Alert&quot; to test instant detection.
                </p>
              </div>
            ) : (
              filteredAlerts.map((alert, idx) => {
                const isSelected = selectedAlert?.id === alert.id;
                return (
                  <div
                    key={`${alert.id}-${idx}`}
                    onClick={() => setSelectedAlert(alert)}
                    className={`p-3.5 rounded-xl border transition cursor-pointer space-y-2 text-left ${
                      isSelected
                        ? 'bg-cyan-950/30 border-cyan-400 shadow-md shadow-cyan-950/40'
                        : alert.severity === 'critical'
                        ? 'bg-rose-950/20 hover:bg-rose-950/30 border-rose-500/40'
                        : alert.severity === 'high'
                        ? 'bg-amber-950/20 hover:bg-amber-950/30 border-amber-500/40'
                        : 'bg-[#0c121e] hover:bg-[#111928] border-slate-800'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-[10px] font-mono font-extrabold px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-cyan-300">
                        {alert.category}
                      </span>
                      <span className="text-[10px] font-mono text-cyan-400/90 font-bold" title="Indian Standard Time">
                        {alert.timestampIST}
                      </span>
                    </div>

                    <div>
                      <div className="text-xs font-extrabold text-white leading-snug">
                        {alert.methodUsed}
                      </div>
                      <div className="text-[11px] text-slate-300 font-mono truncate mt-0.5">
                        Target: <span className="text-emerald-400 font-bold">{alert.targetMeta?.shortLabel || alert.targetAddress.slice(0, 14)}...</span>
                      </div>
                    </div>

                    <div className="p-2 rounded-lg bg-[#080c14]/80 border border-slate-800/90 text-[10px] font-mono space-y-1">
                      <div className="text-slate-400 truncate">
                        Authority: <span className="text-amber-300 font-bold">{alert.authority.label}</span>
                      </div>
                      <div className="text-slate-500 truncate">
                        Addresses Involved: <span className="text-slate-300 font-bold">{alert.addressesInvolved.length} addresses</span>
                      </div>
                    </div>

                    <div className="flex items-center justify-between pt-1 border-t border-slate-800/60 text-[10px] font-mono">
                      <span className="text-slate-500 truncate max-w-[190px]">
                        {alert.signature.slice(0, 16)}...
                      </span>
                      <span className="text-cyan-400 hover:underline flex items-center gap-1 font-bold">
                        Inspect Alert →
                      </span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right 7 Cols: Deep Whitelist Activity Details, Method, Authority & Involved Addresses */}
        <div className="lg:col-span-7">
          {selectedAlert ? (
            <div className="bg-[#0c121e] border border-cyan-500/40 rounded-2xl p-5 sm:p-6 shadow-xl space-y-5">
              {/* Alert Title Bar */}
              <div className="pb-3 border-b border-slate-800 space-y-1">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-md bg-amber-500/15 border border-amber-500/40 text-amber-300 font-mono text-xs font-extrabold">
                    <Zap className="w-3.5 h-3.5 text-amber-400" />
                    INSTANT WHITELIST ALERT: {selectedAlert.category}
                  </span>

                  <span className="text-xs font-mono text-cyan-300 font-bold flex items-center gap-1.5 bg-[#080c14] px-2.5 py-1 rounded-lg border border-slate-800">
                    <Clock className="w-3.5 h-3.5 text-cyan-400" />
                    {selectedAlert.timestampIST}
                  </span>
                </div>

                <h2 className="text-lg sm:text-xl font-extrabold text-white mt-1">
                  {selectedAlert.methodUsed}
                </h2>
                <p className="text-xs text-slate-300 leading-relaxed">
                  {selectedAlert.summary}
                </p>
              </div>

              {/* 3 Core Forensics Pillars: 1. Method Used | 2. Authority Involved | 3. Target Address */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                {/* 1. Method Used */}
                <div className="p-3.5 rounded-xl bg-[#080c14] border border-slate-800 space-y-1">
                  <div className="text-[10px] font-mono uppercase text-cyan-400 font-bold flex items-center gap-1">
                    <Code2 className="w-3 h-3 text-cyan-400" />
                    1. METHOD BEING USED
                  </div>
                  <div className="text-xs font-extrabold text-white font-mono break-all">
                    {selectedAlert.methodUsed}
                  </div>
                  <div className="text-[10px] font-mono text-slate-400 pt-1 space-y-0.5">
                    <div>Category: <span className="text-emerald-300 font-bold">{selectedAlert.category}</span></div>
                    {selectedAlert.opcodeOrSighash && (
                      <div className="text-[10px] text-slate-400 truncate">Sighash/ID: <span className="text-cyan-300">{selectedAlert.opcodeOrSighash}</span></div>
                    )}
                    {selectedAlert.subsystem && (
                      <div className="text-[9px] text-slate-500 truncate">{selectedAlert.subsystem}</div>
                    )}
                  </div>
                </div>

                {/* 2. Authority Involved */}
                <div className="p-3.5 rounded-xl bg-[#080c14] border border-slate-800 space-y-1">
                  <div className="text-[10px] font-mono uppercase text-amber-400 font-bold flex items-center gap-1">
                    <KeyRound className="w-3 h-3 text-amber-400" />
                    2. AUTHORITY INVOLVED
                  </div>
                  <div className="text-xs font-extrabold text-white truncate" title={selectedAlert.authority.label}>
                    {selectedAlert.authority.label}
                  </div>
                  <div className="text-[10px] font-mono text-amber-300/90 font-semibold truncate">
                    Role: {selectedAlert.authority.role}
                  </div>
                  <button
                    type="button"
                    onClick={() => onSelectAddress(selectedAlert.authority.address)}
                    className="text-[10px] font-mono text-cyan-300 hover:underline truncate block max-w-full text-left cursor-pointer pt-0.5"
                    title={selectedAlert.authority.address}
                  >
                    {selectedAlert.authority.address}
                  </button>
                </div>

                {/* 3. Monitored Whitelisted Address */}
                <div className="p-3.5 rounded-xl bg-[#080c14] border border-slate-800 space-y-1">
                  <div className="text-[10px] font-mono uppercase text-emerald-400 font-bold flex items-center gap-1">
                    <ShieldCheck className="w-3 h-3 text-emerald-400" />
                    3. WHITELISTED ENTITY
                  </div>
                  <div className="text-xs font-extrabold text-white truncate">
                    {selectedAlert.targetMeta?.shortLabel || 'Whitelisted Address'}
                  </div>
                  <div className="text-[10px] font-mono text-emerald-300 truncate">
                    {selectedAlert.targetMeta?.roleTitle || 'Institutional Entity'}
                  </div>
                  <button
                    type="button"
                    onClick={() => onSelectAddress(selectedAlert.targetAddress)}
                    className="text-[10px] font-mono text-cyan-300 hover:underline truncate block max-w-full text-left cursor-pointer pt-0.5"
                    title={selectedAlert.targetAddress}
                  >
                    {selectedAlert.targetAddress}
                  </button>
                </div>
              </div>

              {/* Table of ALL Addresses Involved */}
              <div className="space-y-2.5">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">
                    <Layers className="w-3.5 h-3.5 text-cyan-400" />
                    Addresses Involved in This Activity ({selectedAlert.addressesInvolved.length})
                  </h3>
                  <span className="text-[10px] font-mono text-emerald-400 font-bold">
                    Institutional Whitelist Provenance
                  </span>
                </div>

                <div className="overflow-x-auto rounded-xl border border-slate-800 bg-[#080c14]">
                  <table className="w-full text-left text-xs">
                    <thead>
                      <tr className="border-b border-slate-800 text-[10px] font-mono uppercase text-slate-400 bg-[#0b101b]">
                        <th className="py-2.5 px-3">Address</th>
                        <th className="py-2.5 px-3">Role &amp; Context</th>
                        <th className="py-2.5 px-3">Whitelist Status</th>
                        <th className="py-2.5 px-3 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/80">
                      {selectedAlert.addressesInvolved.map((inv) => (
                        <tr key={inv.address} className="hover:bg-slate-900/60 transition">
                          <td className="py-2.5 px-3 font-mono text-[11px]">
                            <button
                              type="button"
                              onClick={() => onSelectAddress(inv.address)}
                              className="text-cyan-300 hover:underline cursor-pointer text-left block"
                              title={inv.address}
                            >
                              {inv.address.length > 28 ? `${inv.address.slice(0, 16)}...${inv.address.slice(-6)}` : inv.address}
                            </button>
                            <span className="text-[10px] text-slate-400 font-sans">
                              {inv.meta?.label || 'Transaction Participant'}
                            </span>
                          </td>
                          <td className="py-2.5 px-3 text-[11px] text-slate-200">
                            <span className="font-semibold">{inv.role}</span>
                          </td>
                          <td className="py-2.5 px-3">
                            {inv.isWhitelisted ? (
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-emerald-500/15 border border-emerald-500/30 text-emerald-300 text-[10px] font-mono font-bold">
                                <ShieldCheck className="w-3 h-3 text-emerald-400" />
                                WHITELISTED
                              </span>
                            ) : (
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300 text-[10px] font-mono">
                                COUNTERPARTY
                              </span>
                            )}
                          </td>
                          <td className="py-2.5 px-3 text-right">
                            <button
                              type="button"
                              onClick={() => onSelectAddress(inv.address)}
                              className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 font-mono text-[10px] cursor-pointer"
                            >
                              Inspect RPC
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Transaction Signature Handoff & Quick Actions */}
              <div className="p-4 rounded-xl bg-[#080c14] border border-cyan-500/30 space-y-3">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div>
                    <span className="text-[10px] font-mono text-slate-400 uppercase font-bold">
                      TRANSACTION SIGNATURE
                    </span>
                    <div className="text-xs font-mono text-cyan-300 break-all select-all font-bold">
                      {selectedAlert.signature}
                    </div>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      type="button"
                      onClick={() => handleCopy(selectedAlert.signature, 'sig')}
                      className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono flex items-center gap-1 cursor-pointer"
                    >
                      {copiedId === 'sig' ? (
                        <>
                          <Check className="w-3 h-3 text-emerald-400" />
                          <span className="text-emerald-300">Copied!</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3 h-3" />
                          <span>Copy Sig</span>
                        </>
                      )}
                    </button>

                    <button
                      type="button"
                      onClick={() => onInvestigateSignature(selectedAlert.signature)}
                      className="px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-extrabold text-xs flex items-center gap-1.5 shadow-lg shadow-cyan-500/20 cursor-pointer"
                    >
                      <span>Deep Forensic Analysis</span>
                      <ArrowRight className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>

                <div className="text-[11px] text-slate-400 flex flex-wrap items-center gap-4 pt-2 border-t border-slate-800/80 font-mono">
                  {selectedAlert.slot && (
                    <span>Slot: <strong className="text-slate-200">#{selectedAlert.slot.toLocaleString()}</strong></span>
                  )}
                  {selectedAlert.computeUnits && (
                    <span>Compute Units: <strong className="text-slate-200">{selectedAlert.computeUnits.toLocaleString()} CU</strong></span>
                  )}
                  <span>Detection Source: <strong className="text-cyan-400">{selectedAlert.source}</strong></span>
                  <span>Indian Timezone: <strong className="text-emerald-400">Asia/Kolkata (IST)</strong></span>
                </div>
              </div>

              {/* Quick 1-Click Simulation Triggers covering the entire range of method IDs */}
              <div className="space-y-2 pt-2 border-t border-slate-800">
                <div className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center justify-between">
                  <span>Quick-Test Method Range on Whitelisted Addresses:</span>
                  <span className="font-mono text-[10px] text-cyan-400">All Method Ranges</span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
                  <button
                    type="button"
                    onClick={() =>
                      handleSimulateTrigger(
                        whitelistedEntities.find((e) => e.address === 'J4cTuCH6frt4AnEmKfMS2k8hsUf7K94PV62sjUJno8Cz'),
                        'FACT::MintToChecked (Supply Issuance)'
                      )
                    }
                    className="p-2.5 rounded-xl bg-[#080c14] hover:bg-slate-800 border border-slate-800 hover:border-cyan-500/40 text-left transition cursor-pointer"
                  >
                    <div className="text-[10px] font-mono text-emerald-400">MINT METHOD</div>
                    <div className="text-xs font-bold text-white">FACT::MintToChecked</div>
                    <div className="text-[10px] text-slate-400 font-mono">Token Mint Authority PDA</div>
                  </button>

                  <button
                    type="button"
                    onClick={() =>
                      handleSimulateTrigger(
                        whitelistedEntities.find((e) => e.address === 'EdE9ccPTU8UkrhAVg6pjEa9sVJgq9JaWfs2fYA3b4qPZ'),
                        'FACT::SetStopCodes (Compliance Restriction)'
                      )
                    }
                    className="p-2.5 rounded-xl bg-[#080c14] hover:bg-slate-800 border border-slate-800 hover:border-amber-500/40 text-left transition cursor-pointer"
                  >
                    <div className="text-[10px] font-mono text-amber-400">STOPCODES METHOD</div>
                    <div className="text-xs font-bold text-white">FACT::SetStopCodes</div>
                    <div className="text-[10px] text-slate-400 font-mono">Compliance Operator Key</div>
                  </button>

                  <button
                    type="button"
                    onClick={() =>
                      handleSimulateTrigger(
                        whitelistedEntities.find((e) => e.address === 'J4cTuCH6frt4AnEmKfMS2k8hsUf7K94PV62sjUJno8Cz'),
                        'FACT::BurnApprove (Redemption Approval)'
                      )
                    }
                    className="p-2.5 rounded-xl bg-[#080c14] hover:bg-slate-800 border border-slate-800 hover:border-rose-500/40 text-left transition cursor-pointer"
                  >
                    <div className="text-[10px] font-mono text-rose-400">BURN METHOD</div>
                    <div className="text-xs font-bold text-white">FACT::BurnApprove</div>
                    <div className="text-[10px] text-slate-400 font-mono">Redemption Agent Signer</div>
                  </button>

                  <button
                    type="button"
                    onClick={() =>
                      handleSimulateTrigger(
                        whitelistedEntities.find((e) => e.address === 'HAfaMsQFvoDYNSBdHUhkEHLWxcTnmWCXE6nk2aMufVmD'),
                        'TransferHook::UpdateExtraAccountMetaList'
                      )
                    }
                    className="p-2.5 rounded-xl bg-[#080c14] hover:bg-slate-800 border border-slate-800 hover:border-purple-500/40 text-left transition cursor-pointer"
                  >
                    <div className="text-[10px] font-mono text-purple-400">TRANSFER HOOK</div>
                    <div className="text-xs font-bold text-white">ExtraAccountMetaList</div>
                    <div className="text-[10px] text-slate-400 font-mono">Transfer Hook Authority PDA</div>
                  </button>
                </div>
              </div>
            </div>
          ) : (
            <div className="p-12 text-center rounded-2xl bg-[#0c121e] border border-slate-800 space-y-3">
              <Zap className="w-10 h-10 text-cyan-400 mx-auto animate-pulse" />
              <h3 className="text-base font-bold text-white">Select Any Whitelist Alert on the Left</h3>
              <p className="text-xs text-slate-400 max-w-md mx-auto">
                Select an alert from the real-time feed or trigger a test event to inspect the method being used, authority involved, and all addresses involved with Indian Date and Time.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
