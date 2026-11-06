/**
 * SOL-MATE — Asset, Program, Burn Workflow State Machine & Stop-Code Explorer
 * Implements Phase 5, Phase 6, and Phase 10.2:
 * - Deep coverage for Solana JLTXX & MONY (Token-2022), FACT Controller, and EVM Diamond/Proxy contracts
 * - Token identity tuple (mintAddress, chain, tokenProgram) — never relying on symbol alone
 * - Stateful Burn Workflow Integrity Explorer (prepare_burn -> BurnApprove -> BurnChecked + supply reduction check)
 * - Custom Stop-Code Compliance Matrix (stop_transfer_to, stop_transfer_from, stop_redemption_from, stop_subscription_to)
 * - Transfer Hook & Extra Account Meta List PDA inspection
 */

import React, { useState } from 'react';
import {
  ShieldCheck,
  AlertTriangle,
  Flame,
  Lock,
  Unlock,
  Layers,
  Cpu,
  CheckCircle2,
  XCircle,
  ArrowRight,
  ExternalLink,
  Sliders,
} from 'lucide-react';
import { AssetProgramProfile, StopCodeFlags } from '../types/universalIntel';
import {
  evaluateBurnWorkflowIntegrity,
  getMonitoredAssetProgramProfiles,
} from '../services/universalDetectionEngine';

interface AssetProgramExplorerProps {
  onSelectAddress: (address: string) => void;
  onInvestigateTransaction: (txId: string) => void;
}

export const AssetProgramExplorer: React.FC<AssetProgramExplorerProps> = ({
  onSelectAddress,
  onInvestigateTransaction,
}) => {
  const [profiles, setProfiles] = useState<AssetProgramProfile[]>(() =>
    getMonitoredAssetProgramProfiles()
  );
  const [selectedIdentifier, setSelectedIdentifier] = useState<string>(
    profiles[0]?.identifier || ''
  );

  // Interactive Burn State Machine Simulator state
  const [simRequestedUi, setSimRequestedUi] = useState<number>(50);
  const [simApprovedUi, setSimApprovedUi] = useState<number>(50);
  const [simBurnedUi, setSimBurnedUi] = useState<number>(50);
  const [simSupplyReduced, setSimSupplyReduced] = useState<boolean>(true);
  const [simHasPrepare, setSimHasPrepare] = useState<boolean>(true);
  const [simHasApprove, setSimHasApprove] = useState<boolean>(true);

  const activeProfile =
    profiles.find((p) => p.identifier === selectedIdentifier) || profiles[0];

  const simulatedBurnResult = evaluateBurnWorkflowIntegrity({
    workflowId: 'interactive-burn-test',
    mintAddress: activeProfile.identifier,
    tokenSymbol: activeProfile.symbol,
    governingProgramId:
      activeProfile.governingControllerProgram || activeProfile.identifier,
    holderWallet: 'DwWsjJsCic4xF7MPgqSxT7WZGancjGtumbmVVYFK1zXR',
    holderTokenAccount: 'CUNnRnBZT7sjAb911toVo7UQzfQ1PdVEUDjLGQsmzPcj',
    burnRequestPda: 'BurnReqSimPDA111111111111111111111111111111',
    hasPrepareBurnRequest: simHasPrepare,
    requestedAmountRaw: BigInt(Math.round(simRequestedUi * 100)),
    hasBurnApproval: simHasApprove,
    approvedAmountRaw: BigInt(Math.round(simApprovedUi * 100)),
    approverAuthority: '4tm6TUNqJqnxUoD3ocknd8MfK4DC2tBezaXJFTVyZK1D',
    hasBurnExecution: true,
    burnedAmountRaw: BigInt(Math.round(simBurnedUi * 100)),
    supplyBeforeRaw: 1000000n,
    supplyAfterRaw: simSupplyReduced
      ? 1000000n - BigInt(Math.round(simBurnedUi * 100))
      : 1000000n,
    decimals: 2,
  });

  const handleToggleStopCode = (flagKey: keyof StopCodeFlags) => {
    setProfiles((prev) =>
      prev.map((p) => {
        if (p.identifier !== activeProfile.identifier || !p.stopCodeState) return p;
        return {
          ...p,
          stopCodeState: {
            ...p.stopCodeState,
            [flagKey]: !p.stopCodeState[flagKey],
          },
        };
      })
    );
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 py-6 space-y-6">
      {/* Top Banner */}
      <div className="bg-gradient-to-r from-[#0d131f] via-[#0f172a] to-[#0d131f] border border-cyan-500/30 rounded-2xl p-5 shadow-xl">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="px-2.5 py-0.5 rounded-md text-[10px] font-extrabold uppercase tracking-wider bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                Asset & Program Intelligence Explorer
              </span>
              <span className="px-2.5 py-0.5 rounded-md text-[10px] font-bold uppercase bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                JLTXX • MONY • FACT Controller • EVM Diamond
              </span>
            </div>
            <h1 className="text-xl font-extrabold text-white tracking-tight">
              Token-2022, Custom Program, Burn State Machine & Stop-Code Explorer
            </h1>
            <p className="text-xs text-slate-400 max-w-3xl">
              Identifies assets by full cryptographic tuple{' '}
              <code className="text-cyan-300">(mintAddress, chain, tokenProgram)</code> rather than symbol alone.
              Inspects Token-2022 extensions, Transfer Hook PDAs, custom <code className="text-cyan-300">SetStopCodes</code>{' '}
              states, and stateful <code className="text-cyan-300">prepare_burn -&gt; BurnApprove -&gt; BurnChecked</code>{' '}
              workflows.
            </p>
          </div>
        </div>

        {/* Asset / Program Selector Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 mt-4 pt-4 border-t border-slate-800/80">
          {profiles.map((prof) => {
            const isSelected = prof.identifier === activeProfile.identifier;
            return (
              <button
                key={prof.identifier}
                onClick={() => setSelectedIdentifier(prof.identifier)}
                className={`text-left p-3.5 rounded-xl border transition cursor-pointer ${
                  isSelected
                    ? 'bg-[#121c31] border-cyan-400 shadow-lg shadow-cyan-500/10'
                    : 'bg-[#090d16] border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs font-extrabold text-cyan-300">{prof.symbol}</span>
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                    {prof.chain}
                  </span>
                </div>
                <div className="text-xs font-bold text-white mt-1 truncate">{prof.name}</div>
                <div className="text-[10px] font-mono text-slate-400 mt-1 truncate">
                  {prof.identifier}
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Main Profile Inspection Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left 7 Columns: Cryptographic Identity, Authorities,PDAs & Extensions */}
        <div className="lg:col-span-7 space-y-6">
          <div className="bg-[#0b0f19] border border-slate-800 rounded-2xl p-5 space-y-4">
            <div className="flex items-center justify-between flex-wrap gap-2 border-b border-slate-800 pb-3">
              <div>
                <span className="text-[10px] font-mono uppercase text-cyan-400">
                  {activeProfile.entityType}
                </span>
                <h2 className="text-base font-extrabold text-white">{activeProfile.name}</h2>
              </div>
              <span className="px-3 py-1 rounded-lg bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 text-xs font-bold font-mono">
                Supply: {activeProfile.currentSupplyUi}
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
              <div className="p-3 rounded-xl bg-[#070a12] border border-slate-800/80">
                <div className="text-[10px] text-slate-400 uppercase font-sans font-bold">
                  Mint / Contract Address
                </div>
                <button
                  onClick={() => onSelectAddress(activeProfile.identifier)}
                  className="text-cyan-300 hover:underline break-all text-left mt-0.5 cursor-pointer"
                >
                  {activeProfile.identifier}
                </button>
              </div>

              <div className="p-3 rounded-xl bg-[#070a12] border border-slate-800/80">
                <div className="text-[10px] text-slate-400 uppercase font-sans font-bold">
                  Token Program / Implementation
                </div>
                <button
                  onClick={() => onSelectAddress(activeProfile.tokenProgramOrImplementation)}
                  className="text-emerald-300 hover:underline break-all text-left mt-0.5 cursor-pointer"
                >
                  {activeProfile.tokenProgramOrImplementation}
                </button>
              </div>

              <div className="p-3 rounded-xl bg-[#070a12] border border-slate-800/80">
                <div className="text-[10px] text-slate-400 uppercase font-sans font-bold">
                  Mint Authority / Minter Role
                </div>
                <div className="text-slate-200 break-all mt-0.5">
                  {activeProfile.mintAuthority || 'Revoked (None)'}
                </div>
              </div>

              <div className="p-3 rounded-xl bg-[#070a12] border border-slate-800/80">
                <div className="text-[10px] text-slate-400 uppercase font-sans font-bold">
                  Freeze / Pause Authority
                </div>
                <div className="text-slate-200 break-all mt-0.5">
                  {activeProfile.freezeAuthority || 'None'}
                </div>
              </div>

              {activeProfile.transferHookProgramId && (
                <div className="p-3 rounded-xl bg-[#070a12] border border-slate-800/80">
                  <div className="text-[10px] text-amber-400 uppercase font-sans font-bold">
                    Token-2022 Transfer Hook Program
                  </div>
                  <div className="text-amber-200 break-all mt-0.5">
                    {activeProfile.transferHookProgramId}
                  </div>
                </div>
              )}

              {activeProfile.extraAccountMetaListPda && (
                <div className="p-3 rounded-xl bg-[#070a12] border border-slate-800/80">
                  <div className="text-[10px] text-violet-400 uppercase font-sans font-bold">
                    ExtraAccountMetaList Validation PDA
                  </div>
                  <div className="text-violet-200 break-all mt-0.5">
                    {activeProfile.extraAccountMetaListPda}
                  </div>
                </div>
              )}
            </div>

            {/* Extensions or Diamond Facets */}
            <div>
              <div className="text-[11px] font-bold uppercase text-slate-400 mb-2">
                Active Extensions / Custom Instructions / Diamond Facets
              </div>
              <div className="flex flex-wrap gap-2">
                {activeProfile.extensionsOrFacets.map((ext, i) => (
                  <span
                    key={i}
                    className="px-2.5 py-1 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-200 text-xs font-mono"
                  >
                    {ext}
                  </span>
                ))}
              </div>
            </div>
          </div>

          {/* Stateful Burn Workflow Integrity State Machine (Phase 5.3) */}
          <div className="bg-[#0b0f19] border border-slate-800 rounded-2xl p-5 space-y-4">
            <div className="flex items-center justify-between flex-wrap gap-2 border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Flame className="w-5 h-5 text-amber-400" />
                <div>
                  <h3 className="text-sm font-extrabold text-white">
                    Stateful Burn Workflow Integrity State Machine
                  </h3>
                  <p className="text-[11px] text-slate-400">
                    Tracks <code className="text-cyan-300">prepare_burn</code> (Request) -&gt;{' '}
                    <code className="text-cyan-300">BurnApprove</code> (Approval) -&gt;{' '}
                    <code className="text-cyan-300">BurnChecked</code> (Verified Supply Contraction)
                  </p>
                </div>
              </div>
            </div>

            {/* Recorded Burn Workflows */}
            {activeProfile.activeBurnWorkflows.length > 0 ? (
              <div className="space-y-3">
                {activeProfile.activeBurnWorkflows.map((bw) => {
                  const isAnomalous = bw.anomaliesDetected.length > 0;
                  return (
                    <div
                      key={bw.workflowId}
                      className={`p-4 rounded-xl border ${
                        isAnomalous
                          ? 'bg-rose-500/10 border-rose-500/40'
                          : 'bg-emerald-500/10 border-emerald-500/30'
                      }`}
                    >
                      <div className="flex items-center justify-between flex-wrap gap-2">
                        <span className="font-mono text-xs font-bold text-white">
                          Workflow: {bw.workflowId}
                        </span>
                        <span
                          className={`px-2.5 py-0.5 rounded text-[10px] font-extrabold uppercase ${
                            isAnomalous
                              ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                              : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                          }`}
                        >
                          {bw.stage}
                        </span>
                      </div>

                      <div className="grid grid-cols-3 gap-2 mt-3 text-xs font-mono">
                        <div className="p-2 rounded bg-[#070a12] border border-slate-800">
                          <div className="text-[10px] text-slate-400">1. prepare_burn</div>
                          <div className="text-cyan-300 font-bold">
                            {bw.requestedAmountUi} {bw.tokenSymbol}
                          </div>
                        </div>
                        <div className="p-2 rounded bg-[#070a12] border border-slate-800">
                          <div className="text-[10px] text-slate-400">2. BurnApprove</div>
                          <div
                            className={`font-bold ${
                              (bw.approvedAmountUi ?? 0) > bw.requestedAmountUi
                                ? 'text-rose-400'
                                : 'text-emerald-300'
                            }`}
                          >
                            {bw.approvedAmountUi ?? 0} {bw.tokenSymbol}
                          </div>
                        </div>
                        <div className="p-2 rounded bg-[#070a12] border border-slate-800">
                          <div className="text-[10px] text-slate-400">3. Supply Reduced</div>
                          <div
                            className={`font-bold ${
                              bw.verifiedSupplyReduced ? 'text-emerald-400' : 'text-rose-400'
                            }`}
                          >
                            {bw.verifiedSupplyReduced ? 'VERIFIED YES' : 'NO (INVARIANT BROKEN)'}
                          </div>
                        </div>
                      </div>

                      {bw.anomaliesDetected.length > 0 && (
                        <div className="mt-2.5 text-xs text-rose-200 space-y-1">
                          {bw.anomaliesDetected.map((anom, idx) => (
                            <div key={idx} className="flex items-start gap-1.5">
                              <AlertTriangle className="w-3.5 h-3.5 text-rose-400 shrink-0 mt-0.5" />
                              <span>{anom}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="text-xs text-slate-400 p-3 rounded-xl bg-[#070a12] border border-slate-800">
                No active multi-step burn workflows recorded for {activeProfile.symbol}. Use the
                interactive validator below to test burn invariants.
              </div>
            )}

            {/* Interactive Burn Invariant Tester */}
            <div className="p-4 rounded-xl bg-[#070a12] border border-slate-800 space-y-3">
              <div className="text-xs font-extrabold uppercase text-cyan-400 flex items-center gap-1.5">
                <Sliders className="w-3.5 h-3.5" />
                <span>Interactive Burn State-Machine Invariant Validator</span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
                <div>
                  <label className="block text-[10px] text-slate-400 uppercase font-bold mb-1">
                    Requested (prepare_burn)
                  </label>
                  <input
                    type="number"
                    aria-label="Requested prepare_burn amount"
                    value={simRequestedUi}
                    onChange={(e) => setSimRequestedUi(Number(e.target.value) || 0)}
                    className="w-full bg-[#0b101d] border border-slate-700 rounded-lg px-2.5 py-1.5 text-white font-mono"
                  />
                </div>
                <div>
                  <label className="block text-[10px] text-slate-400 uppercase font-bold mb-1">
                    Approved (BurnApprove)
                  </label>
                  <input
                    type="number"
                    aria-label="Approved BurnApprove amount"
                    value={simApprovedUi}
                    onChange={(e) => setSimApprovedUi(Number(e.target.value) || 0)}
                    className="w-full bg-[#0b101d] border border-slate-700 rounded-lg px-2.5 py-1.5 text-white font-mono"
                  />
                </div>
                <div>
                  <label className="block text-[10px] text-slate-400 uppercase font-bold mb-1">
                    Executed (BurnChecked)
                  </label>
                  <input
                    type="number"
                    aria-label="Executed BurnChecked amount"
                    value={simBurnedUi}
                    onChange={(e) => setSimBurnedUi(Number(e.target.value) || 0)}
                    className="w-full bg-[#0b101d] border border-slate-700 rounded-lg px-2.5 py-1.5 text-white font-mono"
                  />
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-4 text-xs pt-1">
                <label className="flex items-center gap-1.5 text-slate-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={simHasPrepare}
                    onChange={(e) => setSimHasPrepare(e.target.checked)}
                  />
                  <span>Has prepare_burn Request</span>
                </label>
                <label className="flex items-center gap-1.5 text-slate-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={simHasApprove}
                    onChange={(e) => setSimHasApprove(e.target.checked)}
                  />
                  <span>Has BurnApprove</span>
                </label>
                <label className="flex items-center gap-1.5 text-slate-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={simSupplyReduced}
                    onChange={(e) => setSimSupplyReduced(e.target.checked)}
                  />
                  <span>On-Chain Mint Supply Reduced</span>
                </label>
              </div>

              <div
                className={`p-3 rounded-lg border text-xs ${
                  simulatedBurnResult.anomaliesDetected.length === 0
                    ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-200'
                    : 'bg-rose-500/15 border-rose-500/40 text-rose-200'
                }`}
              >
                <div className="font-bold">
                  State Machine Result: {simulatedBurnResult.stage}
                </div>
                {simulatedBurnResult.anomaliesDetected.length === 0 ? (
                  <p className="text-[11px] mt-0.5">
                    All 3 stages verified: prepare_burn ({simRequestedUi}) == BurnApprove ({simApprovedUi}) ==
                    BurnChecked ({simBurnedUi}) with confirmed on-chain supply contraction.
                  </p>
                ) : (
                  <ul className="mt-1 list-disc list-inside text-[11px]">
                    {simulatedBurnResult.anomaliesDetected.map((a, i) => (
                      <li key={i}>{a}</li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Right 5 Columns: Custom Stop-Code Compliance State & Monitoring Coverage */}
        <div className="lg:col-span-5 space-y-6">
          {/* Custom Stop-Code State Matrix (Phase 5.4) */}
          <div className="bg-[#0b0f19] border border-slate-800 rounded-2xl p-5 space-y-4">
            <div className="border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Lock className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-extrabold text-white">
                  Custom Stop-Code Configuration State (SetStopCodes)
                </h3>
              </div>
              <p className="text-[11px] text-slate-400 mt-1">
                Token configuration PDA compliance flags governing inbound/outbound transfers,
                subscriptions, and redemptions. Click any flag to simulate a <code className="text-cyan-300">SetStopCodes</code> transition.
              </p>
            </div>

            {activeProfile.stopCodeState ? (
              <div className="grid grid-cols-1 gap-2.5">
                {(
                  [
                    {
                      key: 'stop_transfer_to',
                      title: 'stop_transfer_to',
                      desc: 'Blocks inbound token transfers to restricted or non-whitelisted recipient vaults.',
                    },
                    {
                      key: 'stop_transfer_from',
                      title: 'stop_transfer_from',
                      desc: 'Blocks outbound token transfers from the target holder custody account.',
                    },
                    {
                      key: 'stop_redemption_from',
                      title: 'stop_redemption_from',
                      desc: 'Halts prepare_burn and redemption execution from the target holder account.',
                    },
                    {
                      key: 'stop_subscription_to',
                      title: 'stop_subscription_to',
                      desc: 'Halts new MintTo subscription allocations to the target token account.',
                    },
                  ] as { key: keyof StopCodeFlags; title: string; desc: string }[]
                ).map((item) => {
                  const isActive = activeProfile.stopCodeState![item.key];
                  return (
                    <button
                      key={item.key}
                      onClick={() => handleToggleStopCode(item.key)}
                      className={`w-full text-left p-3.5 rounded-xl border transition cursor-pointer ${
                        isActive
                          ? 'bg-rose-500/15 border-rose-500/40'
                          : 'bg-[#070a12] border-slate-800 hover:border-slate-700'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-xs font-extrabold text-white">
                          {item.title}
                        </span>
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-extrabold uppercase ${
                            isActive
                              ? 'bg-rose-500/30 text-rose-200 border border-rose-400/40'
                              : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                          }`}
                        >
                          {isActive ? 'TRUE (RESTRICTED)' : 'FALSE (PERMITTED)'}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-400 mt-1">{item.desc}</p>
                    </button>
                  );
                })}
              </div>
            ) : (
              <div className="p-4 rounded-xl bg-[#070a12] border border-slate-800 text-xs text-slate-400">
                This contract uses EVM AccessControl / ComplianceStoplistFacet roles rather than
                Solana PDA stop-code flags.
              </div>
            )}
          </div>

          {/* Monitoring Coverage Matrix */}
          <div className="bg-[#0b0f19] border border-slate-800 rounded-2xl p-5 space-y-4">
            <div className="border-b border-slate-800 pb-3">
              <h3 className="text-sm font-extrabold text-white flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                <span>Active Detection Coverage Matrix</span>
              </h3>
            </div>

            <div className="space-y-2 text-xs">
              {[
                {
                  label: 'Mint & Supply Expansion / Contraction',
                  covered: activeProfile.monitoringCoverage.mintBurnCovered,
                },
                {
                  label: 'Mint, Freeze, Upgrade & Role Authority Handovers',
                  covered: activeProfile.monitoringCoverage.authorityChangesCovered,
                },
                {
                  label: 'Custom Stop-Code / Pause / Stoplist State Transitions',
                  covered: activeProfile.monitoringCoverage.stopCodesCovered,
                },
                {
                  label: 'Stateful Burn Workflow Invariant Verification',
                  covered: activeProfile.monitoringCoverage.burnStateMachineCovered,
                },
                {
                  label: 'Zero-Drop Unknown Instruction Byte Fallback',
                  covered: activeProfile.monitoringCoverage.unknownInstructionFallback,
                },
              ].map((row, idx) => (
                <div
                  key={idx}
                  className="flex items-center justify-between p-2.5 rounded-lg bg-[#070a12] border border-slate-800"
                >
                  <span className="text-slate-200">{row.label}</span>
                  <span className="text-emerald-400 font-bold text-[11px] flex items-center gap-1">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    ACTIVE
                  </span>
                </div>
              ))}
            </div>

            <div>
              <div className="text-[10px] font-bold uppercase text-slate-400 mb-2">
                Bound Detection Rules ({activeProfile.monitoringCoverage.activeRuleIds.length})
              </div>
              <div className="flex flex-wrap gap-1.5">
                {activeProfile.monitoringCoverage.activeRuleIds.map((id) => (
                  <span
                    key={id}
                    className="px-2 py-0.5 rounded bg-slate-800 text-cyan-300 font-mono text-[11px] border border-slate-700"
                  >
                    {id}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
