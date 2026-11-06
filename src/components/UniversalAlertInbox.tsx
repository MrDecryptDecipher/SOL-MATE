/**
 * SOL-MATE — Universal Alert Inbox & Multi-Event Incident Correlation View
 * Implements Phase 7, 8, 9, and 10.1:
 * - Multi-chain & protocol-aware alert triage (Solana SPL/Token-2022/FACT & EVM Proxy/Diamond/ERC-20)
 * - Independent Severity and Detection Confidence badges + Epistemic Provenance status
 * - Full 10-Part Analyst Explanation panel
 * - Interactive Analyst Disposition workflow (Expected/Authorised, False Positive, Suspicious, Confirmed Unauthorised, Escalated)
 * - Multi-Event Incident Correlation timeline (Mint -> Distribution, prepare_burn -> BurnApprove -> BurnChecked, StopCodes)
 */

import React, { useState, useMemo } from 'react';
import {
  ShieldAlert,
  Filter,
  CheckCircle2,
  AlertTriangle,
  Layers,
  ExternalLink,
  Search,
  CheckSquare,
  FileText,
  GitBranch,
  SlidersHorizontal,
  ArrowRight,
  Lock,
  Sparkles,
} from 'lucide-react';
import {
  AlertSeverity,
  AnalystDisposition,
  DetectionConfidence,
  IncidentRecord,
  UniversalAlertRecord,
} from '../types/universalIntel';
import { TransactionRecord } from '../types/forensics';

interface UniversalAlertInboxProps {
  alerts: UniversalAlertRecord[];
  incidents: IncidentRecord[];
  activeTransaction: TransactionRecord | null;
  onUpdateDisposition: (alertId: string, disposition: AnalystDisposition, notes?: string) => void;
  onInvestigateTransaction: (txId: string) => void;
  onSelectAddress: (address: string) => void;
}

const SEVERITY_STYLES: Record<AlertSeverity, string> = {
  critical: 'bg-rose-500/20 text-rose-300 border-rose-500/40',
  high: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
  medium: 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40',
  low: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40',
  info: 'bg-slate-700/40 text-slate-300 border-slate-600/40',
};

const CONFIDENCE_STYLES: Record<DetectionConfidence, string> = {
  confirmed: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
  high: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30',
  medium: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
  low: 'bg-orange-500/15 text-orange-300 border-orange-500/30',
  heuristic: 'bg-violet-500/15 text-violet-300 border-violet-500/30',
};

const DISPOSITION_LABELS: Record<AnalystDisposition, { label: string; badgeClass: string }> = {
  UNREVIEWED: { label: 'Unreviewed', badgeClass: 'bg-slate-800 text-slate-300 border-slate-700' },
  EXPECTED_AUTHORISED: {
    label: 'Expected / Authorised',
    badgeClass: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40',
  },
  FALSE_POSITIVE: {
    label: 'False Positive',
    badgeClass: 'bg-slate-700/40 text-slate-400 border-slate-600/40',
  },
  SUSPICIOUS_INVESTIGATION_REQUIRED: {
    label: 'Suspicious • Investigation Required',
    badgeClass: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
  },
  CONFIRMED_UNAUTHORISED_ACTIVITY: {
    label: 'Confirmed Unauthorised Activity',
    badgeClass: 'bg-rose-500/25 text-rose-200 border-rose-500/50',
  },
  ESCALATED: {
    label: 'Escalated to Incident Response',
    badgeClass: 'bg-fuchsia-500/20 text-fuchsia-300 border-fuchsia-500/40',
  },
  INSUFFICIENT_EVIDENCE: {
    label: 'Insufficient Evidence',
    badgeClass: 'bg-slate-800 text-slate-400 border-slate-700',
  },
};

export const UniversalAlertInbox: React.FC<UniversalAlertInboxProps> = ({
  alerts,
  incidents,
  activeTransaction,
  onUpdateDisposition,
  onInvestigateTransaction,
  onSelectAddress,
}) => {
  const [viewMode, setViewMode] = useState<'alerts' | 'incidents'>('alerts');
  const [chainFilter, setChainFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [confidenceFilter, setConfidenceFilter] = useState<string>('ALL');
  const [assetFilter, setAssetFilter] = useState<string>('ALL');
  const [dispositionFilter, setDispositionFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedAlertId, setSelectedAlertId] = useState<string>(alerts[0]?.alertId || '');
  const [noteInput, setNoteInput] = useState<string>('');

  // Merge activeTransaction universalAlerts if not already in alerts list
  const combinedAlerts = useMemo(() => {
    const map = new Map<string, UniversalAlertRecord>();
    if (activeTransaction?.universalAlerts) {
      for (const a of activeTransaction.universalAlerts) {
        map.set(a.deduplicationKey, a);
      }
    }
    for (const a of alerts) {
      if (!map.has(a.deduplicationKey)) {
        map.set(a.deduplicationKey, a);
      }
    }
    return Array.from(map.values());
  }, [alerts, activeTransaction]);

  const filteredAlerts = useMemo(() => {
    return combinedAlerts.filter((a) => {
      if (chainFilter !== 'ALL' && a.chain !== chainFilter) return false;
      if (severityFilter !== 'ALL' && a.severity !== severityFilter) return false;
      if (confidenceFilter !== 'ALL' && a.confidence !== confidenceFilter) return false;
      if (dispositionFilter !== 'ALL' && a.disposition !== dispositionFilter) return false;
      if (assetFilter !== 'ALL' && (a.assetSymbol || 'NONE') !== assetFilter) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const hay = `${a.title} ${a.summary} ${a.ruleId} ${a.transactionId} ${a.actorAddress} ${a.assetSymbol || ''} ${a.programOrContractId}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [combinedAlerts, chainFilter, severityFilter, confidenceFilter, dispositionFilter, assetFilter, searchQuery]);

  const selectedAlert = useMemo(() => {
    return (
      filteredAlerts.find((a) => a.alertId === selectedAlertId) ||
      filteredAlerts[0] ||
      combinedAlerts[0] ||
      null
    );
  }, [filteredAlerts, selectedAlertId, combinedAlerts]);

  const criticalCount = combinedAlerts.filter((a) => a.severity === 'critical').length;
  const confirmedConfidenceCount = combinedAlerts.filter((a) => a.confidence === 'confirmed').length;
  const onboardingRelatedCount = combinedAlerts.filter((a) => a.isClientOnboardingRelated).length;

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 py-6 space-y-6">
      {/* Header Banner */}
      <div className="bg-gradient-to-r from-[#0d131f] via-[#0f172a] to-[#0d131f] border border-cyan-500/30 rounded-2xl p-5 shadow-xl">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="px-2.5 py-0.5 rounded-md text-[10px] font-extrabold uppercase tracking-wider bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                Universal Alert Intelligence Engine
              </span>
              <span className="px-2.5 py-0.5 rounded-md text-[10px] font-bold uppercase bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                Client-Onboarding Independent
              </span>
              <span className="px-2.5 py-0.5 rounded-md text-[10px] font-bold uppercase bg-violet-500/15 text-violet-300 border border-violet-500/30">
                Solana SVM + EVM Unified
              </span>
            </div>
            <h1 className="text-xl font-extrabold text-white tracking-tight">
              Universal Security Alert Inbox & Multi-Event Incident Correlator
            </h1>
            <p className="text-xs text-slate-400 max-w-3xl">
              Every alert separates <strong className="text-slate-200">Severity (Impact)</strong> from{' '}
              <strong className="text-slate-200">Detection Confidence (Decoder/State Certainty)</strong>, labels epistemic
              provenance, and provides a 10-part technical forensic explanation without requiring prior client onboarding.
            </p>
          </div>

          {/* View Switcher */}
          <div className="flex items-center gap-2 shrink-0">
            <button
              onClick={() => setViewMode('alerts')}
              className={`px-4 py-2 rounded-xl text-xs font-bold flex items-center gap-2 transition cursor-pointer ${
                viewMode === 'alerts'
                  ? 'bg-cyan-500 text-slate-950 shadow-lg shadow-cyan-500/20'
                  : 'bg-slate-800/80 text-slate-300 hover:bg-slate-700'
              }`}
            >
              <ShieldAlert className="w-4 h-4" />
              <span>Alert Inbox ({combinedAlerts.length})</span>
            </button>
            <button
              onClick={() => setViewMode('incidents')}
              className={`px-4 py-2 rounded-xl text-xs font-bold flex items-center gap-2 transition cursor-pointer ${
                viewMode === 'incidents'
                  ? 'bg-cyan-500 text-slate-950 shadow-lg shadow-cyan-500/20'
                  : 'bg-slate-800/80 text-slate-300 hover:bg-slate-700'
              }`}
            >
              <GitBranch className="w-4 h-4" />
              <span>Correlated Incidents ({incidents.length})</span>
            </button>
          </div>
        </div>

        {/* Telemetry Summary Strip */}
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 mt-4 pt-4 border-t border-slate-800/80">
          <div className="bg-[#090d16] border border-slate-800/80 rounded-xl p-3">
            <div className="text-[10px] font-bold uppercase text-slate-400">Total Deduplicated Alerts</div>
            <div className="text-lg font-extrabold text-white mt-0.5">{combinedAlerts.length}</div>
            <div className="text-[10px] text-cyan-400">Zero duplicate emissions</div>
          </div>
          <div className="bg-[#090d16] border border-slate-800/80 rounded-xl p-3">
            <div className="text-[10px] font-bold uppercase text-slate-400">Critical Severity</div>
            <div className="text-lg font-extrabold text-rose-400 mt-0.5">{criticalCount}</div>
            <div className="text-[10px] text-slate-400">Burn / Authority / DiamondCut</div>
          </div>
          <div className="bg-[#090d16] border border-slate-800/80 rounded-xl p-3">
            <div className="text-[10px] font-bold uppercase text-slate-400">Confirmed Confidence</div>
            <div className="text-lg font-extrabold text-emerald-400 mt-0.5">{confirmedConfidenceCount}</div>
            <div className="text-[10px] text-slate-400">Verified on-chain state proof</div>
          </div>
          <div className="bg-[#090d16] border border-slate-800/80 rounded-xl p-3">
            <div className="text-[10px] font-bold uppercase text-slate-400">Correlated Incidents</div>
            <div className="text-lg font-extrabold text-violet-400 mt-0.5">{incidents.length}</div>
            <div className="text-[10px] text-slate-400">Multi-tx lifecycle chains</div>
          </div>
          <div className="bg-[#090d16] border border-slate-800/80 rounded-xl p-3">
            <div className="text-[10px] font-bold uppercase text-slate-400">Onboarding-Independent</div>
            <div className="text-lg font-extrabold text-amber-300 mt-0.5">
              {combinedAlerts.length - onboardingRelatedCount} / {combinedAlerts.length}
            </div>
            <div className="text-[10px] text-slate-400">{onboardingRelatedCount} with 0-&gt;+balance onboarding</div>
          </div>
        </div>
      </div>

      {viewMode === 'alerts' ? (
        <>
          {/* Filter Bar */}
          <div className="bg-[#0c111d] border border-slate-800 rounded-xl p-4 flex flex-wrap items-center gap-3">
            <div className="flex items-center gap-1.5 text-xs font-bold text-slate-300">
              <Filter className="w-3.5 h-3.5 text-cyan-400" />
              <span>Filters:</span>
            </div>

            <div className="relative flex-1 min-w-[200px]">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                aria-label="Search alerts by signature, mint, program, or rule"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search signature, mint, program, rule ID..."
                className="w-full bg-[#070a12] border border-slate-700/80 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <select
              aria-label="Filter by Chain"
              value={chainFilter}
              onChange={(e) => setChainFilter(e.target.value)}
              className="bg-[#070a12] border border-slate-700/80 rounded-lg px-2.5 py-1.5 text-xs text-slate-200"
            >
              <option value="ALL">All Chains (Solana + EVM)</option>
              <option value="solana-mainnet">Solana Mainnet</option>
              <option value="ethereum-mainnet">Ethereum / EVM Mainnet</option>
            </select>

            <select
              aria-label="Filter by Token or Asset"
              value={assetFilter}
              onChange={(e) => setAssetFilter(e.target.value)}
              className="bg-[#070a12] border border-slate-700/80 rounded-lg px-2.5 py-1.5 text-xs text-slate-200"
            >
              <option value="ALL">All Assets (JLTXX, MONY, EVM, Custom)</option>
              <option value="JLTXX">JLTXX (Token-2022)</option>
              <option value="MONY">MONY (Token-2022)</option>
              <option value="NONE">Program / Contract Level</option>
            </select>

            <select
              aria-label="Filter by Severity"
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-[#070a12] border border-slate-700/80 rounded-lg px-2.5 py-1.5 text-xs text-slate-200"
            >
              <option value="ALL">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>

            <select
              aria-label="Filter by Confidence"
              value={confidenceFilter}
              onChange={(e) => setConfidenceFilter(e.target.value)}
              className="bg-[#070a12] border border-slate-700/80 rounded-lg px-2.5 py-1.5 text-xs text-slate-200"
            >
              <option value="ALL">All Confidence Levels</option>
              <option value="confirmed">Confirmed</option>
              <option value="high">High</option>
              <option value="heuristic">Heuristic (Fallback)</option>
            </select>

            <select
              aria-label="Filter by Analyst Disposition"
              value={dispositionFilter}
              onChange={(e) => setDispositionFilter(e.target.value)}
              className="bg-[#070a12] border border-slate-700/80 rounded-lg px-2.5 py-1.5 text-xs text-slate-200"
            >
              <option value="ALL">All Dispositions</option>
              <option value="UNREVIEWED">Unreviewed</option>
              <option value="EXPECTED_AUTHORISED">Expected / Authorised</option>
              <option value="SUSPICIOUS_INVESTIGATION_REQUIRED">Suspicious</option>
              <option value="CONFIRMED_UNAUTHORISED_ACTIVITY">Confirmed Unauthorised</option>
              <option value="FALSE_POSITIVE">False Positive</option>
              <option value="ESCALATED">Escalated</option>
            </select>
          </div>

          {/* Master-Detail Split: Left Alert Queue, Right 10-Part Analyst Forensic Explanation */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* Left Column: Alert List */}
            <div className="lg:col-span-5 space-y-3">
              {filteredAlerts.map((alert) => {
                const isSelected = selectedAlert?.alertId === alert.alertId;
                const dispInfo = DISPOSITION_LABELS[alert.disposition];
                return (
                  <button
                    key={alert.alertId}
                    onClick={() => setSelectedAlertId(alert.alertId)}
                    className={`w-full text-left p-4 rounded-xl border transition cursor-pointer ${
                      isSelected
                        ? 'bg-[#11192b] border-cyan-500/60 shadow-lg shadow-cyan-500/10'
                        : 'bg-[#0b0f19] border-slate-800/80 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2 flex-wrap">
                      <div className="flex items-center gap-1.5">
                        <span
                          className={`text-[10px] font-extrabold uppercase px-2 py-0.5 rounded border ${
                            SEVERITY_STYLES[alert.severity]
                          }`}
                        >
                          SEV: {alert.severity}
                        </span>
                        <span
                          className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded border ${
                            CONFIDENCE_STYLES[alert.confidence]
                          }`}
                        >
                          CONF: {alert.confidence}
                        </span>
                      </div>
                      <span className="text-[10px] font-mono text-slate-400">
                        {alert.ruleId} (v{alert.ruleVersion})
                      </span>
                    </div>

                    <h3 className="text-xs font-bold text-white mt-2 leading-snug">{alert.title}</h3>
                    <p className="text-[11px] text-slate-400 mt-1 line-clamp-2">{alert.summary}</p>

                    <div className="mt-3 pt-2.5 border-t border-slate-800/80 flex items-center justify-between gap-2 flex-wrap text-[10px]">
                      <div className="flex items-center gap-1.5">
                        <span className="px-1.5 py-0.5 rounded bg-slate-800 text-cyan-300 font-mono">
                          {alert.chain}
                        </span>
                        {alert.assetSymbol && (
                          <span className="px-1.5 py-0.5 rounded bg-cyan-500/15 text-cyan-200 font-bold">
                            {alert.assetSymbol}
                          </span>
                        )}
                      </div>
                      <span className={`px-2 py-0.5 rounded border font-semibold ${dispInfo.badgeClass}`}>
                        {dispInfo.label}
                      </span>
                    </div>
                  </button>
                );
              })}
            </div>

            {/* Right Column: 10-Part Analyst Explanation & Disposition Controls */}
            <div className="lg:col-span-7">
              {selectedAlert ? (
                <div className="bg-[#0b0f19] border border-slate-800 rounded-2xl p-5 space-y-5">
                  {/* Alert Header */}
                  <div className="border-b border-slate-800 pb-4 space-y-3">
                    <div className="flex items-center justify-between flex-wrap gap-2">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span
                          className={`text-xs font-extrabold uppercase px-2.5 py-0.5 rounded border ${
                            SEVERITY_STYLES[selectedAlert.severity]
                          }`}
                        >
                          Severity: {selectedAlert.severity}
                        </span>
                        <span
                          className={`text-xs font-bold uppercase px-2.5 py-0.5 rounded border ${
                            CONFIDENCE_STYLES[selectedAlert.confidence]
                          }`}
                        >
                          Confidence: {selectedAlert.confidence}
                        </span>
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                          Provenance: {selectedAlert.epistemicStatus}
                        </span>
                      </div>

                      {selectedAlert.chain.startsWith('solana') &&
                        selectedAlert.transactionId.length >= 60 && (
                          <button
                            onClick={() => onInvestigateTransaction(selectedAlert.transactionId)}
                            className="px-3 py-1.5 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 text-xs font-bold flex items-center gap-1.5 cursor-pointer"
                          >
                            <span>Inspect Full Transaction</span>
                            <ExternalLink className="w-3.5 h-3.5" />
                          </button>
                        )}
                    </div>

                    <h2 className="text-base font-extrabold text-white">{selectedAlert.title}</h2>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] bg-[#070a12] p-3 rounded-xl border border-slate-800/80 font-mono">
                      <div>
                        <span className="text-slate-500">Transaction ID: </span>
                        <span className="text-cyan-300 break-all">{selectedAlert.transactionId}</span>
                      </div>
                      <div>
                        <span className="text-slate-500">Block / Slot: </span>
                        <span className="text-slate-200">#{selectedAlert.blockOrSlot.toLocaleString()}</span>
                      </div>
                      <div>
                        <span className="text-slate-500">Program / Contract: </span>
                        <button
                          onClick={() => onSelectAddress(selectedAlert.programOrContractId)}
                          className="text-cyan-400 hover:underline break-all text-left cursor-pointer"
                        >
                          {selectedAlert.programOrContractId}
                        </button>
                      </div>
                      <div>
                        <span className="text-slate-500">Actor / Signer: </span>
                        <button
                          onClick={() => onSelectAddress(selectedAlert.actorAddress)}
                          className="text-emerald-400 hover:underline break-all text-left cursor-pointer"
                        >
                          {selectedAlert.actorAddress}
                        </button>
                      </div>
                    </div>
                  </div>

                  {/* Analyst Disposition Control Bar (Phase 9.3) */}
                  <div className="bg-[#0e1525] border border-cyan-500/25 rounded-xl p-4 space-y-3">
                    <div className="flex items-center justify-between flex-wrap gap-2">
                      <span className="text-xs font-bold text-cyan-300 uppercase tracking-wider flex items-center gap-1.5">
                        <CheckSquare className="w-4 h-4" />
                        <span>Analyst Triage & Disposition Workflow</span>
                      </span>
                      <span
                        className={`text-[11px] px-2.5 py-0.5 rounded border font-bold ${
                          DISPOSITION_LABELS[selectedAlert.disposition].badgeClass
                        }`}
                      >
                        Current: {DISPOSITION_LABELS[selectedAlert.disposition].label}
                      </span>
                    </div>

                    <div className="flex flex-wrap gap-1.5">
                      {(
                        [
                          'EXPECTED_AUTHORISED',
                          'SUSPICIOUS_INVESTIGATION_REQUIRED',
                          'CONFIRMED_UNAUTHORISED_ACTIVITY',
                          'FALSE_POSITIVE',
                          'ESCALATED',
                          'INSUFFICIENT_EVIDENCE',
                        ] as AnalystDisposition[]
                      ).map((disp) => (
                        <button
                          key={disp}
                          onClick={() => onUpdateDisposition(selectedAlert.alertId, disp, noteInput)}
                          className={`px-2.5 py-1 rounded-lg text-[11px] font-semibold border transition cursor-pointer ${
                            selectedAlert.disposition === disp
                              ? 'bg-cyan-500 text-slate-950 border-cyan-400 font-bold'
                              : 'bg-[#080c14] text-slate-300 border-slate-700 hover:border-cyan-500/50'
                          }`}
                        >
                          {DISPOSITION_LABELS[disp].label}
                        </button>
                      ))}
                    </div>
                  </div>

                  {/* 10-Part Analyst Explanation Structure (Phase 8) */}
                  <div className="space-y-3">
                    <h3 className="text-xs font-extrabold uppercase tracking-wider text-cyan-400 flex items-center gap-2">
                      <FileText className="w-4 h-4" />
                      <span>10-Part Structured Technical Forensic Explanation</span>
                    </h3>

                    <div className="grid grid-cols-1 gap-3 text-xs">
                      <div className="p-3 rounded-xl bg-[#070a12] border border-slate-800/80">
                        <div className="text-[10px] font-extrabold uppercase text-cyan-400">
                          1. Observed (Verified On-Chain Facts)
                        </div>
                        <p className="text-slate-200 mt-1 leading-relaxed">
                          {selectedAlert.explanation.observed}
                        </p>
                      </div>

                      <div className="p-3 rounded-xl bg-[#070a12] border border-slate-800/80">
                        <div className="text-[10px] font-extrabold uppercase text-cyan-400">
                          2. What Happened (Plain-Language Execution Summary)
                        </div>
                        <p className="text-slate-200 mt-1 leading-relaxed">
                          {selectedAlert.explanation.whatHappened}
                        </p>
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <div className="p-3 rounded-xl bg-[#070a12] border border-slate-800/80">
                          <div className="text-[10px] font-extrabold uppercase text-amber-400">
                            3. Why The Rule Fired ({selectedAlert.ruleId} v{selectedAlert.ruleVersion})
                          </div>
                          <p className="text-slate-300 mt-1 leading-relaxed">
                            {selectedAlert.explanation.whyRuleFired}
                          </p>
                        </div>

                        <div className="p-3 rounded-xl bg-[#070a12] border border-slate-800/80">
                          <div className="text-[10px] font-extrabold uppercase text-violet-400">
                            4. Technical Interpretation (Protocol Semantics)
                          </div>
                          <p className="text-slate-300 mt-1 leading-relaxed">
                            {selectedAlert.explanation.technicalInterpretation}
                          </p>
                        </div>
                      </div>

                      <div className="p-3 rounded-xl bg-[#070a12] border border-slate-800/80">
                        <div className="text-[10px] font-extrabold uppercase text-rose-400">
                          5. Security & Operational Implications
                        </div>
                        <p className="text-slate-200 mt-1 leading-relaxed">
                          {selectedAlert.explanation.securityImplications}
                        </p>
                      </div>

                      <div className="p-3 rounded-xl bg-[#070a12] border border-slate-800/80 space-y-2">
                        <div className="text-[10px] font-extrabold uppercase text-emerald-400">
                          6. Cryptographic & State Evidence References
                        </div>
                        {selectedAlert.explanation.evidence.map((ev, idx) => (
                          <div
                            key={idx}
                            className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 p-2 rounded-lg bg-[#0b101b] border border-slate-800 font-mono text-[11px]"
                          >
                            <div>
                              <span className="text-cyan-300 font-bold">{ev.fieldPath}: </span>
                              <span className="text-slate-300">{ev.valueSummary}</span>
                            </div>
                            <span className="px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-300 text-[10px] shrink-0">
                              {ev.epistemicStatus}
                            </span>
                          </div>
                        ))}
                      </div>

                      <div className="p-3 rounded-xl bg-[#070a12] border border-slate-800/80 space-y-1">
                        <div className="text-[10px] font-extrabold uppercase text-blue-400">
                          7. Context & Optional Client Onboarding Enrichment
                        </div>
                        <p className="text-slate-300">
                          <strong className="text-slate-100">Onboarding Independence:</strong>{' '}
                          {selectedAlert.explanation.context.clientOnboardingNote}
                        </p>
                        <p className="text-slate-400">
                          <strong className="text-slate-200">Registry Provenance:</strong>{' '}
                          {selectedAlert.explanation.context.entityRegistryNote}
                        </p>
                      </div>

                      <div className="p-3 rounded-xl bg-[#070a12] border border-slate-800/80 space-y-1">
                        <div className="text-[10px] font-extrabold uppercase text-fuchsia-400">
                          8. Independent Severity vs. Detection Confidence Rationale
                        </div>
                        <p className="text-slate-300">
                          <strong className="text-rose-300">
                            Severity ({selectedAlert.explanation.severityAndConfidenceRationale.severity}):
                          </strong>{' '}
                          {selectedAlert.explanation.severityAndConfidenceRationale.severityReason}
                        </p>
                        <p className="text-slate-300">
                          <strong className="text-emerald-300">
                            Confidence ({selectedAlert.explanation.severityAndConfidenceRationale.confidence}):
                          </strong>{' '}
                          {selectedAlert.explanation.severityAndConfidenceRationale.confidenceReason}
                        </p>
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        <div className="p-3 rounded-xl bg-[#070a12] border border-slate-800/80">
                          <div className="text-[10px] font-extrabold uppercase text-cyan-400">
                            9. Analyst Investigation Checklist
                          </div>
                          <ul className="mt-1.5 space-y-1 text-slate-300 list-disc list-inside">
                            {selectedAlert.explanation.investigationChecklist.map((step, i) => (
                              <li key={i}>{step}</li>
                            ))}
                          </ul>
                        </div>

                        <div className="p-3 rounded-xl bg-[#070a12] border border-slate-800/80">
                          <div className="text-[10px] font-extrabold uppercase text-emerald-400">
                            10. Recommended Response & Containment
                          </div>
                          <ul className="mt-1.5 space-y-1 text-slate-300 list-disc list-inside">
                            {selectedAlert.explanation.recommendedResponse.map((step, i) => (
                              <li key={i}>{step}</li>
                            ))}
                          </ul>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="bg-[#0b0f19] border border-slate-800 rounded-2xl p-12 text-center text-slate-400">
                  No alerts match the current filter criteria.
                </div>
              )}
            </div>
          </div>
        </>
      ) : (
        /* Multi-Event Correlated Incidents View (Phase 7.1) */
        <div className="space-y-4">
          {incidents.map((inc) => (
            <div
              key={inc.incidentId}
              className="bg-[#0b0f19] border border-slate-800 rounded-2xl p-5 space-y-4 shadow-lg"
            >
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-slate-800 pb-4">
                <div className="space-y-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-mono text-xs font-extrabold text-cyan-400">{inc.incidentId}</span>
                    <span
                      className={`text-[10px] font-extrabold uppercase px-2 py-0.5 rounded border ${
                        SEVERITY_STYLES[inc.severity]
                      }`}
                    >
                      Severity: {inc.severity}
                    </span>
                    <span
                      className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded border ${
                        CONFIDENCE_STYLES[inc.confidence]
                      }`}
                    >
                      Confidence: {inc.confidence}
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                      Pattern: {inc.patternType}
                    </span>
                  </div>
                  <h3 className="text-base font-extrabold text-white">{inc.title}</h3>
                  <p className="text-xs text-slate-400">{inc.narrativeSummary}</p>
                </div>

                <div className="text-right shrink-0">
                  <span className="px-3 py-1 rounded-full text-xs font-bold bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">
                    Status: {inc.status}
                  </span>
                </div>
              </div>

              {/* Correlated Multi-Step Lifecycle Timeline */}
              <div className="space-y-2">
                <div className="text-[11px] font-extrabold uppercase tracking-wider text-slate-400">
                  Cross-Transaction Correlated Sequence ({inc.lifecycleTimeline.length} Stages)
                </div>
                <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
                  {inc.lifecycleTimeline.map((step) => (
                    <div
                      key={step.stepOrder}
                      className={`p-3.5 rounded-xl border ${
                        step.status === 'ACTIVE_ANOMALY'
                          ? 'bg-rose-500/10 border-rose-500/40'
                          : step.status === 'VERIFIED_COMPLETED'
                          ? 'bg-[#070a12] border-emerald-500/30'
                          : 'bg-[#070a12] border-slate-800'
                      }`}
                    >
                      <div className="flex items-center justify-between text-[10px] font-bold">
                        <span className="text-cyan-400">{step.stageLabel}</span>
                        <span
                          className={
                            step.status === 'ACTIVE_ANOMALY'
                              ? 'text-rose-400'
                              : step.status === 'VERIFIED_COMPLETED'
                              ? 'text-emerald-400'
                              : 'text-slate-400'
                          }
                        >
                          {step.status}
                        </span>
                      </div>
                      <p className="text-xs text-slate-200 mt-1.5 leading-snug">{step.actionSummary}</p>
                      <div className="mt-2 pt-2 border-t border-slate-800/80 text-[10px] font-mono text-slate-400 flex items-center justify-between">
                        <span>Slot/Block #{step.blockOrSlot.toLocaleString()}</span>
                        <span className="truncate max-w-[110px]">{step.transactionId.slice(0, 10)}...</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Recommended Playbook */}
              <div className="bg-[#070a12] border border-slate-800/80 rounded-xl p-3">
                <div className="text-[10px] font-extrabold uppercase text-emerald-400">
                  Incident Response Playbook
                </div>
                <ul className="mt-1 space-y-1 text-xs text-slate-300 list-disc list-inside">
                  {inc.recommendedPlaybook.map((item, idx) => (
                    <li key={idx}>{item}</li>
                  ))}
                </ul>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
