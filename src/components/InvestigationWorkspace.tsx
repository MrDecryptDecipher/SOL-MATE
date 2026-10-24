/**
 * SOL-MATE — Comprehensive Forensic Investigation Workspace
 * Features:
 * 1. Prominent Resolved Token Identity & Client Onboarding Certificate Banner
 * 2. Executive Overview with Economic Flows, Token Metadata, and Risk Heuristics
 * 3. Dedicated Alert Lifecycle & Client Onboarding Correlation Center (Previous -> Current -> Next vs Independent Alerts)
 * 4. Deep Execution Trace with CPI Waterfall, Hex/Base58 Byte Forensics, Anchor Sighash & Full Account Matrix
 * 5. Error-Free Untruncated Address Intelligence Registry
 * 6. Visual Authority Control Topology & Cryptographic Permission Matrix
 * 7. Exponentially Detailed State Changes with Visual Before -> After Progress Bars & Zero Truncation
 * 8. Multi-Tier Interactive Knowledge Graph
 * 9. Exponentially Detailed Evidence & Provenance Catalog with Raw JSON Inspector & Visual Distribution
 */

import React, { useState, useMemo } from 'react';
import {
  CheckCircle2,
  XCircle,
  AlertTriangle,
  ShieldAlert,
  Cpu,
  Layers,
  Coins,
  Key,
  Share2,
  FileText,
  Download,
  Copy,
  Check,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  Bookmark,
  ArrowRight,
  Terminal,
  Eye,
  Lock,
  Printer,
  Sparkles,
  Binary,
  UserCheck,
  GitBranch,
  Activity,
  Search,
  Database,
  Shield,
} from 'lucide-react';
import {
  EvidenceReference,
  InstructionRecord,
  TransactionRecord,
} from '../types/forensics';
import { KnowledgeGraph } from './KnowledgeGraph';
import { forensicsEngine } from '../services/forensicsEngine';
import { deepStorage } from '../services/deepStorage';

interface InvestigationWorkspaceProps {
  transaction: TransactionRecord;
  onSelectAddress: (address: string) => void;
  onSaveCase: () => void;
  onAddMonitoredAccount: (address: string) => void;
}

export type WorkspaceSubTab =
  | 'overview'
  | 'correlations'
  | 'trace'
  | 'accounts'
  | 'authorities'
  | 'transitions'
  | 'graph'
  | 'evidence'
  | 'report';

export const InvestigationWorkspace: React.FC<InvestigationWorkspaceProps> = ({
  transaction: tx,
  onSelectAddress,
  onSaveCase,
  onAddMonitoredAccount,
}) => {
  const [activeTab, setActiveTab] = useState<WorkspaceSubTab>('overview');
  const [copiedSig, setCopiedSig] = useState(false);
  const [copiedTextId, setCopiedTextId] = useState<string | null>(null);
  const [caseSaved, setCaseSaved] = useState(false);
  const [selectedEvidence, setSelectedEvidence] = useState<EvidenceReference | null>(null);
  const [expandedInst, setExpandedInst] = useState<Record<number, boolean>>({ 0: true, 1: true, 2: true, 3: true });
  const [accountSearch, setAccountSearch] = useState('');
  const [accountCategoryFilter, setAccountCategoryFilter] = useState<string>('all');
  const [evidenceFilter, setEvidenceFilter] = useState<string>('all');
  const [evidenceSearch, setEvidenceSearch] = useState('');

  const copyHelper = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedTextId(id);
    setTimeout(() => setCopiedTextId(null), 1800);
  };

  const copySignature = () => {
    navigator.clipboard.writeText(tx.signature || '');
    setCopiedSig(true);
    setTimeout(() => setCopiedSig(false), 2000);
  };

  const handleSaveInvestigation = async () => {
    await deepStorage.saveInvestigation(tx, ['Forensic Audit']);
    setCaseSaved(true);
    onSaveCase();
    setTimeout(() => setCaseSaved(false), 3000);
  };

  const handleExportJson = () => {
    const report = forensicsEngine.generateReport(tx);
    const jsonString = JSON.stringify(
      report,
      (_, value) => (typeof value === 'bigint' ? value.toString() : value),
      2
    );
    const blob = new Blob([jsonString], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `SOLMATE_Forensic_Report_${(tx.signature || 'tx').slice(0, 12)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleExportMarkdown = () => {
    const report = forensicsEngine.generateReport(tx);
    const tokLines = (tx.resolvedTokens || [])
      .map(
        (t) =>
          `- **${t.name} (${t.symbol})** | Mint: \`${t.mint}\` | Standard: ${t.tokenStandard} | Decimals: ${t.decimals} | Summary: ${t.operationSummary}`
      )
      .join('\n');

    const md = `# SOL-MATE Forensic Investigation Report
**Report ID:** ${report.reportId}
**Generated At:** ${new Date(report.createdAt).toISOString()}
**Analyst Engine:** ${report.analyst}
**Cluster:** ${report.cluster.toUpperCase()}
**RPC Endpoint:** ${report.rpcEndpoint}

## 1. Executive Summary
${report.executiveSummary}

## 2. Resolved Tokens Involved
${tokLines || '- Native SOL Only'}

## 3. Client Onboarding & Alert Lifecycle Intelligence
- **Primary Alert Type:** ${tx.alertIntelligence?.primaryAlertType}
- **Alert Headline:** ${tx.alertIntelligence?.primaryAlertTitle}
- **Client Onboarded:** ${tx.alertIntelligence?.clientOnboarding?.isClientOnboarded ? 'YES — CONFIRMED' : 'No new client token onboarding'}
- **Client Wallet:** \`${tx.alertIntelligence?.clientOnboarding?.clientWalletAddress}\`
- **Client Token Account:** \`${tx.alertIntelligence?.clientOnboarding?.clientTokenAccountAddress}\`
- **Provisioned Allocation:** ${tx.alertIntelligence?.clientOnboarding?.provisionedAmount}

## 4. State Transitions (${tx.stateTransitions.length})
${tx.stateTransitions.map((s) => `- **${s.account}** (${s.fieldOrAsset}): \`${s.beforeState}\` -> \`${s.afterState}\` (${s.notes})`).join('\n')}
`;
    const blob = new Blob([md], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `SOLMATE_Forensic_Report_${(tx.signature || 'tx').slice(0, 12)}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const getRiskBadgeColor = (score: number) => {
    if (score === 0) return 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40';
    if (score < 30) return 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40';
    if (score < 60) return 'bg-amber-500/20 text-amber-300 border-amber-500/40';
    return 'bg-rose-500/20 text-rose-300 border-rose-500/40';
  };

  const resolvedTokens = tx.resolvedTokens || [];
  const alertIntel = tx.alertIntelligence;
  const accountsList = useMemo(() => Object.values(tx.accountsRegistry || {}), [tx.accountsRegistry]);

  const filteredAccounts = useMemo(() => {
    return accountsList.filter((acc) => {
      const matchesCat = accountCategoryFilter === 'all' || acc.category === accountCategoryFilter;
      const q = accountSearch.trim().toLowerCase();
      if (!q) return matchesCat;
      return (
        MatchesCatAndQuery(acc, matchesCat, q)
      );
    });
  }, [accountsList, accountCategoryFilter, accountSearch]);

  const filteredEvidence = useMemo(() => {
    return (tx.evidenceCatalog || []).filter((ev) => {
      if (evidenceFilter === 'sol' && !ev.id.includes('sol-delta')) return false;
      if (evidenceFilter === 'token' && !ev.id.includes('token') && !ev.id.includes('mint')) return false;
      if (evidenceFilter === 'instructions' && !ev.id.includes('ev-inst')) return false;
      if (evidenceFilter === 'alerts' && !ev.id.includes('alert') && !ev.id.includes('auth')) return false;

      const q = evidenceSearch.trim().toLowerCase();
      if (!q) return true;
      return (
        (ev.sourceMethod || '').toLowerCase().includes(q) ||
        (ev.fieldPath || '').toLowerCase().includes(q) ||
        (ev.interpretation || '').toLowerCase().includes(q) ||
        (ev.accountAddress || '').toLowerCase().includes(q)
      );
    });
  }, [tx.evidenceCatalog, evidenceFilter, evidenceSearch]);

  return (
    <div className="max-w-7xl mx-auto px-4 py-6 space-y-6">
      {/* Top Transaction Command Bar */}
      <div className="bg-[#0d121c] border border-slate-800 rounded-2xl p-5 shadow-xl space-y-4">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="space-y-1.5 min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              {tx.success ? (
                <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-500/15 border border-emerald-500/30 text-emerald-300 text-xs font-bold">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  <span>FINALIZED SUCCESS</span>
                </span>
              ) : (
                <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-rose-500/15 border border-rose-500/30 text-rose-300 text-xs font-bold">
                  <XCircle className="w-3.5 h-3.5" />
                  <span>EXECUTION FAILED</span>
                </span>
              )}

              <span className="text-xs font-mono px-2.5 py-1 rounded-full bg-slate-800 text-slate-300 border border-slate-700">
                Version: <strong>{(tx.version || 'legacy').toUpperCase()}</strong>
              </span>

              <span className="text-xs font-mono px-2.5 py-1 rounded-full bg-slate-800 text-cyan-300 border border-slate-700">
                Slot #{tx.slot.toLocaleString()}
              </span>

              <span className="text-xs text-slate-400 font-mono">{tx.formattedTime}</span>

              {alertIntel?.clientOnboarding?.isClientOnboarded && (
                <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-emerald-500 text-slate-950 text-xs font-extrabold shadow-lg shadow-emerald-500/20">
                  <UserCheck className="w-3.5 h-3.5" />
                  <span>
                    CLIENT ONBOARDED FOR {alertIntel.clientOnboarding.tokenSymbol} ({alertIntel.clientOnboarding.provisionedAmount})
                  </span>
                </span>
              )}
            </div>

            <div className="flex items-center gap-2 pt-1">
              <code className="text-xs sm:text-sm font-mono text-slate-200 break-all select-all bg-[#080b11] px-3 py-1.5 rounded-lg border border-slate-800">
                {tx.signature}
              </code>
              <button
                onClick={copySignature}
                className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition shrink-0 cursor-pointer"
                title="Copy Full Signature"
              >
                {copiedSig ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
              </button>
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex flex-wrap items-center gap-2 shrink-0">
            <button
              onClick={handleSaveInvestigation}
              className="px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 flex items-center gap-1.5 border border-slate-700 transition cursor-pointer"
            >
              <Bookmark className={`w-3.5 h-3.5 ${caseSaved ? 'text-emerald-400 fill-emerald-400' : 'text-cyan-400'}`} />
              <span>{caseSaved ? 'Saved to Library' : 'Save Case'}</span>
            </button>

            <button
              onClick={handleExportJson}
              className="px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 flex items-center gap-1.5 border border-slate-700 transition cursor-pointer"
            >
              <Download className="w-3.5 h-3.5 text-cyan-400" />
              <span>JSON</span>
            </button>

            <button
              onClick={handleExportMarkdown}
              className="px-3 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 flex items-center gap-1.5 border border-slate-700 transition cursor-pointer"
            >
              <FileText className="w-3.5 h-3.5 text-violet-400" />
              <span>Markdown</span>
            </button>

            <button
              onClick={() => {
                setActiveTab('report');
                setTimeout(() => window.print(), 300);
              }}
              className="px-3 py-2 rounded-xl bg-cyan-500/15 hover:bg-cyan-500/25 text-xs font-bold text-cyan-300 flex items-center gap-1.5 border border-cyan-500/30 transition cursor-pointer"
            >
              <Printer className="w-3.5 h-3.5" />
              <span>Print / PDF</span>
            </button>
          </div>
        </div>

        {/* PROMINENT TOKEN INVOLVED & CLIENT ONBOARDING IDENTITY BANNER (Requirement #7 & #10) */}
        <div className="p-4 rounded-xl bg-gradient-to-r from-cyan-950/50 via-[#0b1324] to-emerald-950/40 border border-cyan-500/35 space-y-3">
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
            <div className="space-y-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-[10px] font-mono font-extrabold uppercase tracking-wider px-2.5 py-0.5 rounded bg-cyan-500 text-slate-950">
                  TOKEN INVOLVED IN TRANSACTION
                </span>
                {resolvedTokens.length > 0 ? (
                  resolvedTokens.map((tok) => (
                    <span
                      key={tok.mint}
                      className="text-sm sm:text-base font-extrabold text-white flex items-center gap-2"
                    >
                      <Coins className="w-4 h-4 text-emerald-400" />
                      <span>{tok.name}</span>
                      <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 font-mono text-xs">
                        Symbol: {tok.symbol}
                      </span>
                      <span className="px-2 py-0.5 rounded bg-violet-500/20 text-violet-300 border border-violet-500/40 font-mono text-xs">
                        {tok.tokenStandard}
                      </span>
                    </span>
                  ))
                ) : (
                  <span className="text-sm font-extrabold text-white flex items-center gap-2">
                    <Coins className="w-4 h-4 text-cyan-400" />
                    <span>Solana Native SOL (Lamports)</span>
                  </span>
                )}
              </div>

              {resolvedTokens.length > 0 && (
                <div className="flex flex-wrap items-center gap-x-5 gap-y-1 text-xs text-slate-300 pt-1">
                  <div>
                    Mint Contract Address:{' '}
                    <button
                      onClick={() => onSelectAddress(resolvedTokens[0].mint)}
                      className="font-mono text-cyan-300 hover:underline font-bold cursor-pointer"
                    >
                      {resolvedTokens[0].mint}
                    </button>
                  </div>
                  <div>
                    Issuer / Protocol: <strong className="text-emerald-300">{resolvedTokens[0].issuer}</strong>
                  </div>
                  <div>
                    Decimals: <strong className="font-mono text-white">{resolvedTokens[0].decimals}</strong>
                  </div>
                  <div>
                    Operation: <strong className="text-amber-300">{resolvedTokens[0].operationSummary}</strong>
                  </div>
                </div>
              )}
            </div>

            <button
              onClick={() => setActiveTab('correlations')}
              className="px-3.5 py-2 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-extrabold text-xs flex items-center gap-1.5 shrink-0 transition cursor-pointer shadow-lg shadow-emerald-500/20"
            >
              <GitBranch className="w-4 h-4" />
              <span>View Alert Lifecycle & Client Onboarding</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* High-Density Key Metrics Strip */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 pt-2 border-t border-slate-800/80">
          <div className="p-3 rounded-xl bg-[#090d14] border border-slate-800/80">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-400 block">
              Fee Payer (Signer #0)
            </span>
            <button
              onClick={() => onSelectAddress(tx.feePayer)}
              className="mt-1 font-mono text-[11px] font-bold text-cyan-400 hover:underline break-all text-left cursor-pointer"
            >
              {tx.feePayer}
            </button>
          </div>

          <div className="p-3 rounded-xl bg-[#090d14] border border-slate-800/80">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-400 block">
              Execution Fee
            </span>
            <div className="mt-1 font-mono text-sm font-bold text-white">
              {tx.feeSol.toFixed(6)} SOL
            </div>
            <span className="text-[10px] font-mono text-slate-500">{tx.feeLamports.toString()} lamports</span>
          </div>

          <div className="p-3 rounded-xl bg-[#090d14] border border-slate-800/80">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-400 block">
              Compute Units
            </span>
            <div className="mt-1 font-mono text-sm font-bold text-white">
              {tx.computeUnitsConsumed ? tx.computeUnitsConsumed.toLocaleString() : 'N/A'}
            </div>
            <span className="text-[10px] text-slate-500">VM Execution Cycles</span>
          </div>

          <div className="p-3 rounded-xl bg-[#090d14] border border-slate-800/80">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-400 block">
              Account Footprint
            </span>
            <div className="mt-1 font-mono text-sm font-bold text-white">
              {tx.combinedAccounts.length} Accounts
            </div>
            <span className="text-[10px] text-slate-500">
              {tx.signers.length} Signer(s) • {tx.authorities.length} Authorities
            </span>
          </div>

          <div className="p-3 rounded-xl bg-[#090d14] border border-slate-800/80">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-400 block">
              Instructions & CPIs
            </span>
            <div className="mt-1 font-mono text-sm font-bold text-white">
              {tx.outerInstructions.length} Outer / {tx.allInstructionsFlat.length - tx.outerInstructions.length} Inner
            </div>
            <span className="text-[10px] text-slate-500">{tx.allInstructionsFlat.length} Total Invocations</span>
          </div>

          <div className="p-3 rounded-xl bg-[#090d14] border border-slate-800/80">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-400 block">
              Heuristic Risk Score
            </span>
            <div className="mt-1 flex items-center gap-2">
              <span className={`text-xs font-mono font-extrabold px-2 py-0.5 rounded border ${getRiskBadgeColor(tx.heuristicRiskScore)}`}>
                {tx.heuristicRiskScore} / 100
              </span>
              <span className="text-[10px] text-slate-400">
                {tx.heuristicRiskScore === 0 ? 'Clean' : tx.heuristicRiskScore < 30 ? 'Low' : 'Elevated'}
              </span>
            </div>
          </div>
        </div>

        {/* Navigation Sub-Tabs */}
        <div className="flex items-center gap-1.5 overflow-x-auto pt-2 border-t border-slate-800/80 no-scrollbar">
          {[
            { id: 'overview', label: 'Executive Overview', icon: ShieldAlert },
            {
              id: 'correlations',
              label: `Alert Lifecycle & Onboarding (${alertIntel?.lifecycleStages?.length || 5})`,
              icon: GitBranch,
            },
            { id: 'trace', label: `Execution Trace (${tx.allInstructionsFlat.length})`, icon: Cpu },
            { id: 'accounts', label: `Address Intelligence (${tx.combinedAccounts.length})`, icon: Layers },
            { id: 'authorities', label: `Authorities (${tx.authorities.length})`, icon: Key },
            { id: 'transitions', label: `State Changes (${tx.stateTransitions.length})`, icon: Coins },
            { id: 'graph', label: `Knowledge Graph (${tx.relationships.length})`, icon: Share2 },
            { id: 'evidence', label: `Evidence Catalog (${tx.evidenceCatalog.length})`, icon: Lock },
            { id: 'report', label: 'Forensic Report', icon: FileText },
          ].map((tab) => {
            const Icon = tab.icon;
            const active = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as WorkspaceSubTab)}
                className={`px-3.5 py-2 rounded-xl text-xs font-bold flex items-center gap-2 transition whitespace-nowrap cursor-pointer ${
                  active
                    ? 'bg-cyan-500 text-slate-950 shadow-md shadow-cyan-500/20'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Selected Evidence Modal Banner */}
      {selectedEvidence && (
        <div className="bg-cyan-950/30 border border-cyan-500/40 rounded-xl p-4 flex items-start justify-between gap-4">
          <div className="space-y-1 text-xs min-w-0 flex-1">
            <div className="flex items-center gap-2 font-bold text-cyan-300">
              <Lock className="w-3.5 h-3.5" />
              <span>Verified On-Chain Evidence Provenance: {selectedEvidence.id}</span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300">
                {selectedEvidence.verificationStatus.toUpperCase()}
              </span>
            </div>
            <p className="text-slate-200">{selectedEvidence.interpretation}</p>
            <div className="text-[11px] font-mono text-slate-400">
              RPC Source: <span className="text-cyan-300">{selectedEvidence.sourceMethod}</span> | Field Path:{' '}
              <span className="text-cyan-300">{selectedEvidence.fieldPath}</span>
            </div>
            <pre className="mt-2 p-2.5 rounded-lg bg-[#070a0f] border border-slate-800 text-[10px] font-mono text-slate-300 overflow-x-auto">
              {JSON.stringify(selectedEvidence.rawValue, null, 2)}
            </pre>
          </div>
          <button
            onClick={() => setSelectedEvidence(null)}
            className="text-xs text-slate-400 hover:text-white px-2.5 py-1 rounded bg-slate-800 shrink-0 cursor-pointer"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* TAB CONTENT PANELS */}
      <div className="space-y-6">
        {/* =====================================================================
            TAB 1: EXECUTIVE OVERVIEW
           ===================================================================== */}
        {activeTab === 'overview' && (
          <div className="space-y-6">
            {/* Client Onboarding & Primary Alert Intelligence Card */}
            {alertIntel && (
              <div className="bg-[#0f1522] border border-emerald-500/35 rounded-2xl p-5 space-y-4 shadow-xl">
                <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 border-b border-slate-800 pb-4">
                  <div className="space-y-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="px-2.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 font-mono text-[11px] font-bold">
                        {alertIntel.primaryAlertType}
                      </span>
                      {alertIntel.clientOnboarding.isClientOnboarded && (
                        <span className="px-2.5 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-mono text-[11px] font-bold">
                          VERIFIED CLIENT TOKEN ONBOARDING
                        </span>
                      )}
                    </div>
                    <h3 className="text-base sm:text-lg font-extrabold text-white">
                      {alertIntel.clientOnboarding.headline}
                    </h3>
                    <p className="text-xs text-slate-300 leading-relaxed">
                      {alertIntel.clientOnboarding.explanation}
                    </p>
                  </div>

                  <button
                    onClick={() => setActiveTab('correlations')}
                    className="px-4 py-2 rounded-xl bg-cyan-500/15 hover:bg-cyan-500/25 border border-cyan-500/40 text-cyan-300 font-bold text-xs shrink-0 cursor-pointer"
                  >
                    Open Full Lifecycle Pipeline →
                  </button>
                </div>

                {/* Onboarding & Token Key Entities Grid (Untruncated) */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
                  <div className="p-3.5 rounded-xl bg-[#090d14] border border-slate-800 space-y-1">
                    <span className="text-[10px] font-bold uppercase tracking-wider text-emerald-400 block">
                      1. Token Involved (Full Identity)
                    </span>
                    <div className="font-extrabold text-white text-sm">
                      {alertIntel.clientOnboarding.tokenName} ({alertIntel.clientOnboarding.tokenSymbol})
                    </div>
                    <div className="text-[11px] text-slate-400">
                      Standard: <strong className="text-slate-200">{alertIntel.clientOnboarding.tokenStandard}</strong>
                    </div>
                    <button
                      onClick={() => onSelectAddress(alertIntel.clientOnboarding.tokenMintAddress)}
                      className="font-mono text-[11px] text-cyan-300 hover:underline break-all text-left block pt-1 cursor-pointer"
                    >
                      Mint: {alertIntel.clientOnboarding.tokenMintAddress}
                    </button>
                  </div>

                  <div className="p-3.5 rounded-xl bg-[#090d14] border border-slate-800 space-y-1">
                    <span className="text-[10px] font-bold uppercase tracking-wider text-cyan-400 block">
                      2. Onboarded Client Wallet & Custody Vault
                    </span>
                    <div className="text-[11px] text-slate-400">Client Owner Wallet:</div>
                    <button
                      onClick={() => onSelectAddress(alertIntel.clientOnboarding.clientWalletAddress)}
                      className="font-mono text-[11px] text-cyan-300 hover:underline break-all text-left font-bold block cursor-pointer"
                    >
                      {alertIntel.clientOnboarding.clientWalletAddress}
                    </button>
                    <div className="text-[11px] text-slate-400 pt-1">Provisioned Token Account:</div>
                    <button
                      onClick={() => onSelectAddress(alertIntel.clientOnboarding.clientTokenAccountAddress)}
                      className="font-mono text-[11px] text-emerald-300 hover:underline break-all text-left block cursor-pointer"
                    >
                      {alertIntel.clientOnboarding.clientTokenAccountAddress}
                    </button>
                  </div>

                  <div className="p-3.5 rounded-xl bg-[#090d14] border border-slate-800 space-y-1.5">
                    <span className="text-[10px] font-bold uppercase tracking-wider text-amber-400 block">
                      3. Onboarding Balance State Transition
                    </span>
                    <div className="flex items-center justify-between text-[11px]">
                      <span className="text-slate-400">Pre-Tx Balance:</span>
                      <span className="font-mono text-slate-200">{alertIntel.clientOnboarding.initialBalanceBefore.split('(')[0]}</span>
                    </div>
                    <div className="flex items-center justify-between text-[11px]">
                      <span className="text-slate-400">Provisioned Delta:</span>
                      <span className="font-mono font-extrabold text-emerald-400">
                        {alertIntel.clientOnboarding.provisionedAmount}
                      </span>
                    </div>
                    <div className="flex items-center justify-between text-[11px] pt-1 border-t border-slate-800">
                      <span className="text-slate-400">Post-Tx Balance:</span>
                      <span className="font-mono font-bold text-cyan-300">
                        {alertIntel.clientOnboarding.resultingBalanceAfter}
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            )}

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Left 2 Cols: Asset Flows & Balance Reconciliation */}
              <div className="lg:col-span-2 space-y-6">
                <div className="bg-[#0f1522] border border-slate-800 rounded-2xl p-5 space-y-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Share2 className="w-4 h-4 text-cyan-400" />
                      <h3 className="font-bold text-sm text-white">
                        Verified Economic Asset Flows & Token Movements (Untruncated)
                      </h3>
                    </div>
                    <span className="text-xs text-slate-400 font-mono">{tx.assetFlows.length} Flow(s)</span>
                  </div>

                  {tx.assetFlows.length === 0 ? (
                    <div className="p-6 text-center bg-[#090d14] rounded-xl border border-slate-800/80 text-xs text-slate-400">
                      No direct asset transfers outside of the {tx.feeSol.toFixed(6)} SOL network fee deduction.
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {tx.assetFlows.map((flow) => (
                        <div
                          key={flow.id}
                          className="p-4 rounded-xl bg-[#090d14] border border-slate-800/90 space-y-3"
                        >
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <div className="flex items-center gap-2">
                              <span
                                className={`px-2.5 py-0.5 rounded text-[10px] font-mono font-bold ${
                                  flow.flowNature === 'institutional-issuance-mint'
                                    ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                                    : flow.assetType === 'SOL'
                                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                                    : 'bg-pink-500/20 text-pink-300 border border-pink-500/40'
                                }`}
                              >
                                {flow.flowNature === 'institutional-issuance-mint'
                                  ? 'TOKEN MINT / CLIENT ONBOARDING ISSUANCE'
                                  : flow.flowNature === 'redemption-burn'
                                  ? 'TOKEN SUPPLY REDEMPTION / BURN'
                                  : `${flow.assetType} TRANSFER`}
                              </span>
                              <span className="text-xs font-extrabold text-white">
                                {flow.tokenName || flow.symbol} ({flow.symbol})
                              </span>
                            </div>

                            <span className="text-sm font-mono font-extrabold text-emerald-400">
                              {flow.formattedAmount} ({flow.rawAmount} raw units)
                            </span>
                          </div>

                          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                            <div className="p-2.5 rounded-lg bg-[#0d131f] border border-slate-800">
                              <span className="text-[10px] text-slate-400 uppercase block">
                                Source / Issuer ({flow.sourceLabel || 'Origin'})
                              </span>
                              <button
                                onClick={() => onSelectAddress(flow.source)}
                                className="font-mono text-[11px] text-cyan-300 hover:underline break-all text-left mt-0.5 cursor-pointer"
                              >
                                {flow.source}
                              </button>
                            </div>
                            <div className="p-2.5 rounded-lg bg-[#0d131f] border border-slate-800">
                              <span className="text-[10px] text-slate-400 uppercase block">
                                Destination / Recipient ({flow.destinationLabel || 'Target'})
                              </span>
                              <button
                                onClick={() => onSelectAddress(flow.destination)}
                                className="font-mono text-[11px] text-emerald-300 hover:underline break-all text-left mt-0.5 cursor-pointer"
                              >
                                {flow.destination}
                              </button>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Complete Balance Delta Summary */}
                <div className="bg-[#0f1522] border border-slate-800 rounded-2xl p-5 space-y-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Coins className="w-4 h-4 text-violet-400" />
                      <h3 className="font-bold text-sm text-white">
                        Exact Pre/Post Balance Deltas (SOL & SPL / Token-2022)
                      </h3>
                    </div>
                    <span className="text-[11px] text-slate-400">BigInt Exact Precision</span>
                  </div>

                  <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse text-xs">
                      <thead>
                        <tr className="border-b border-slate-800 text-[10px] text-slate-400 uppercase bg-[#090d14]">
                          <th className="p-2.5">Account / Owner (Untruncated)</th>
                          <th className="p-2.5">Token / Asset Name</th>
                          <th className="p-2.5 text-right">Pre-Balance</th>
                          <th className="p-2.5 text-right">Post-Balance</th>
                          <th className="p-2.5 text-right">Net Change</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60 font-mono">
                        {tx.tokenBalanceDeltas.map((t, idx) => (
                          <tr key={`tok-${idx}`} className="bg-emerald-950/10 hover:bg-slate-800/30 transition">
                            <td className="p-2.5">
                              <div className="font-sans font-bold text-white text-xs">
                                {tx.accountsRegistry[t.accountAddress]?.label || 'Token Custody Account'}
                              </div>
                              <button
                                onClick={() => onSelectAddress(t.accountAddress)}
                                className="text-cyan-300 hover:underline break-all text-left text-[11px] cursor-pointer"
                              >
                                Vault: {t.accountAddress}
                              </button>
                              <div className="text-[10px] text-slate-400 break-all">
                                Owner: {t.owner}
                              </div>
                            </td>
                            <td className="p-2.5 font-sans">
                              <div className="font-bold text-emerald-300">
                                {t.mintName || 'Solana Token'} ({t.mintSymbol})
                              </div>
                              <div className="font-mono text-[10px] text-slate-400 break-all">
                                Mint: {t.mint}
                              </div>
                            </td>
                            <td className="p-2.5 text-right text-slate-400">
                              {t.preUiAmount} {t.mintSymbol}
                            </td>
                            <td className="p-2.5 text-right text-slate-200">
                              {t.postUiAmount} {t.mintSymbol}
                            </td>
                            <td
                              className={`p-2.5 text-right font-bold ${
                                t.deltaRawAmount > 0n
                                  ? 'text-emerald-400'
                                  : t.deltaRawAmount < 0n
                                  ? 'text-rose-400'
                                  : 'text-slate-400'
                              }`}
                            >
                              {t.deltaUiAmount > 0 ? '+' : ''}
                              {t.deltaUiAmount} {t.mintSymbol}
                            </td>
                          </tr>
                        ))}

                        {tx.solBalanceDeltas.map((d, idx) => (
                          <tr key={`sol-${idx}`} className="hover:bg-slate-800/30 transition">
                            <td className="p-2.5">
                              <div className="font-sans font-bold text-slate-200 text-xs">
                                {tx.accountsRegistry[d.address]?.label || (d.isFeePayer ? 'Fee Payer' : 'Account')}
                              </div>
                              <button
                                onClick={() => onSelectAddress(d.address)}
                                className="text-cyan-400 hover:underline break-all text-left text-[11px] cursor-pointer"
                              >
                                {d.address}
                              </button>
                            </td>
                            <td className="p-2.5 font-sans">
                              <span className="font-bold text-slate-200">Solana Native SOL</span>
                            </td>
                            <td className="p-2.5 text-right text-slate-400">{d.preSol.toFixed(6)} SOL</td>
                            <td className="p-2.5 text-right text-slate-200">{d.postSol.toFixed(6)} SOL</td>
                            <td
                              className={`p-2.5 text-right font-bold ${
                                d.deltaLamports > 0n
                                  ? 'text-emerald-400'
                                  : d.deltaLamports < 0n
                                  ? 'text-rose-400'
                                  : 'text-slate-400'
                              }`}
                            >
                              {d.deltaLamports > 0n ? '+' : ''}
                              {d.deltaSol.toFixed(6)} SOL
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>

              {/* Right Col: Heuristic Security Findings & Quick Actions */}
              <div className="space-y-6">
                <div className="bg-[#0f1522] border border-slate-800 rounded-2xl p-5 space-y-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <ShieldAlert className="w-4 h-4 text-amber-400" />
                      <h3 className="font-bold text-sm text-white">Security & Compliance Findings</h3>
                    </div>
                    <span className="text-xs font-mono text-slate-400">{tx.riskFindings.length} Rule(s)</span>
                  </div>

                  <div className="space-y-3">
                    {tx.riskFindings.map((finding) => (
                      <div
                        key={finding.id}
                        className="p-3.5 rounded-xl bg-[#090d14] border border-slate-800/90 space-y-2"
                      >
                        <div className="flex items-start justify-between gap-2">
                          <span className="text-xs font-bold text-slate-100">{finding.title}</span>
                          <span
                            className={`text-[10px] font-mono px-2 py-0.5 rounded uppercase font-bold shrink-0 ${
                              finding.severity === 'critical' || finding.severity === 'high'
                                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                                : finding.severity === 'medium'
                                ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                                : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                            }`}
                          >
                            {finding.severity}
                          </span>
                        </div>
                        <p className="text-[11px] text-slate-300 leading-relaxed">{finding.explanation}</p>
                        <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-[10px] text-slate-400">
                          <span>Impact: {finding.observedImpact}</span>
                          <button
                            onClick={() => setSelectedEvidence(finding.evidence)}
                            className="text-cyan-400 hover:underline font-semibold cursor-pointer"
                          >
                            Inspect Proof
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="bg-[#0f1522] border border-slate-800 rounded-2xl p-5 space-y-3">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400">
                    Forensic Surveillance Actions
                  </h4>
                  <button
                    onClick={() => onAddMonitoredAccount(tx.feePayer)}
                    className="w-full py-2.5 px-4 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 flex items-center justify-between transition border border-slate-700 cursor-pointer"
                  >
                    <span>Monitor Fee Payer Wallet</span>
                    <Eye className="w-3.5 h-3.5 text-cyan-400" />
                  </button>
                  {alertIntel?.clientOnboarding?.isClientOnboarded && (
                    <button
                      onClick={() =>
                        onAddMonitoredAccount(alertIntel.clientOnboarding.clientWalletAddress)
                      }
                      className="w-full py-2.5 px-4 rounded-xl bg-emerald-500/15 hover:bg-emerald-500/25 text-xs font-semibold text-emerald-300 flex items-center justify-between transition border border-emerald-500/30 cursor-pointer"
                    >
                      <span>Monitor Onboarded Client Wallet</span>
                      <UserCheck className="w-3.5 h-3.5 text-emerald-400" />
                    </button>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* =====================================================================
            TAB 2: ALERT LIFECYCLE & CLIENT ONBOARDING CORRELATIONS (Requirement #10 & #12)
           ===================================================================== */}
        {activeTab === 'correlations' && alertIntel && (
          <div className="space-y-6">
            {/* Section 1: Client Token Onboarding Detection & Verification Certificate */}
            <div className="bg-gradient-to-br from-[#0d192b] via-[#0f1522] to-[#0a191e] border border-emerald-500/40 rounded-2xl p-6 space-y-5 shadow-2xl">
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800 pb-4">
                <div className="space-y-1.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="px-3 py-1 rounded-full bg-emerald-500 text-slate-950 font-extrabold text-xs flex items-center gap-1.5">
                      <UserCheck className="w-4 h-4" />
                      <span>
                        {alertIntel.clientOnboarding.isClientOnboarded
                          ? 'CLIENT ONBOARDING CONFIRMED ON-CHAIN'
                          : 'TOKEN HOLDER LIFECYCLE STATUS'}
                      </span>
                    </span>
                    <span className="px-3 py-1 rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 font-mono text-xs font-bold">
                      Alert Type: {alertIntel.primaryAlertType}
                    </span>
                  </div>
                  <h3 className="text-lg sm:text-xl font-extrabold text-white">
                    {alertIntel.clientOnboarding.headline}
                  </h3>
                  <p className="text-xs text-slate-300 leading-relaxed max-w-4xl">
                    {alertIntel.clientOnboarding.explanation}
                  </p>
                </div>
              </div>

              {/* 4-Column Onboarding Forensic Proof Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 text-xs">
                <div className="p-4 rounded-xl bg-[#090d14] border border-slate-800 space-y-1.5">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-emerald-400 block">
                    Token Name & Mint Identity
                  </span>
                  <div className="font-extrabold text-white text-sm">
                    {alertIntel.clientOnboarding.tokenName}
                  </div>
                  <div className="font-mono text-xs text-emerald-300 font-bold">
                    Symbol: {alertIntel.clientOnboarding.tokenSymbol} • {alertIntel.clientOnboarding.tokenStandard}
                  </div>
                  <div className="font-mono text-[11px] text-slate-400 break-all pt-1">
                    Mint: {alertIntel.clientOnboarding.tokenMintAddress}
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-[#090d14] border border-slate-800 space-y-1.5">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-cyan-400 block">
                    Onboarded Client Wallet (Owner)
                  </span>
                  <button
                    onClick={() => onSelectAddress(alertIntel.clientOnboarding.clientWalletAddress)}
                    className="font-mono text-xs font-bold text-cyan-300 hover:underline break-all text-left block cursor-pointer"
                  >
                    {alertIntel.clientOnboarding.clientWalletAddress}
                  </button>
                  <span className="text-[10px] text-slate-400 block pt-1">
                    Provisioned Token Custody Account:
                  </span>
                  <button
                    onClick={() => onSelectAddress(alertIntel.clientOnboarding.clientTokenAccountAddress)}
                    className="font-mono text-[11px] text-slate-200 hover:underline break-all text-left block cursor-pointer"
                  >
                    {alertIntel.clientOnboarding.clientTokenAccountAddress}
                  </button>
                </div>

                <div className="p-4 rounded-xl bg-[#090d14] border border-slate-800 space-y-1.5">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-amber-400 block">
                    Initial Onboarding Provisioning Proof
                  </span>
                  <div className="text-[11px] text-slate-400">
                    Before: <strong className="text-slate-200 font-mono">{alertIntel.clientOnboarding.initialBalanceBefore}</strong>
                  </div>
                  <div className="text-xs text-emerald-400 font-mono font-extrabold">
                    Allocation: {alertIntel.clientOnboarding.provisionedAmount}
                  </div>
                  <div className="text-[11px] text-cyan-300 font-mono font-bold">
                    After: {alertIntel.clientOnboarding.resultingBalanceAfter}
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-[#090d14] border border-slate-800 space-y-1.5">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-violet-400 block">
                    Governing Program & Dispatcher
                  </span>
                  <div className="font-bold text-white">{alertIntel.clientOnboarding.governingProgramName}</div>
                  <button
                    onClick={() => onSelectAddress(alertIntel.clientOnboarding.governingProgramId)}
                    className="font-mono text-[11px] text-violet-300 hover:underline break-all text-left block cursor-pointer"
                  >
                    Program: {alertIntel.clientOnboarding.governingProgramId}
                  </button>
                  <div className="font-mono text-[10px] text-slate-400 break-all pt-1">
                    Dispatcher: {alertIntel.clientOnboarding.dispatcherAuthority}
                  </div>
                </div>
              </div>

              {/* Verified Compliance Indicators */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5 pt-2">
                {alertIntel.clientOnboarding.complianceIndicators.map((ind, i) => (
                  <div
                    key={i}
                    className="p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/25 flex items-center gap-2 text-xs text-emerald-200"
                  >
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                    <span className="break-all">{ind}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Section 2: Dedicated Correlated Alert Lifecycle Pipeline (Previous -> Current -> Next) */}
            <div className="bg-[#0f1522] border border-slate-800 rounded-2xl p-6 space-y-5">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div>
                  <div className="flex items-center gap-2">
                    <GitBranch className="w-5 h-5 text-cyan-400" />
                    <h3 className="font-extrabold text-base text-white">
                      Dedicated Correlated Alert Lifecycle Pipeline (Previous → Current → Next Possible Alerts)
                    </h3>
                  </div>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Maps how this transaction alert correlates to prerequisite prior alerts and predicted downstream lifecycle stages for{' '}
                    <strong className="text-cyan-300">{alertIntel.correlatedTokenDisplay}</strong>.
                  </p>
                </div>
                <span className="px-3 py-1 rounded-xl bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 font-mono text-xs font-bold shrink-0">
                  {alertIntel.lifecycleStages.length} Connected Lifecycle Stages
                </span>
              </div>

              <div className="space-y-4">
                {alertIntel.lifecycleStages.map((stage) => {
                  const isCurrent = stage.phase === 'CURRENT_ACTIVE_ALERT';
                  const isPrev = stage.phase === 'PREVIOUS_PREREQUISITE';
                  return (
                    <div
                      key={stage.stageNumber}
                      className={`p-5 rounded-2xl border transition relative ${
                        isCurrent
                          ? 'bg-cyan-950/30 border-cyan-400 shadow-lg shadow-cyan-500/10'
                          : isPrev
                          ? 'bg-[#090d14] border-emerald-500/30'
                          : 'bg-[#090d14] border-amber-500/30'
                      }`}
                    >
                      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
                        <div className="flex flex-wrap items-center gap-2.5">
                          <span
                            className={`w-7 h-7 rounded-full flex items-center justify-center font-mono font-extrabold text-xs ${
                              isCurrent
                                ? 'bg-cyan-400 text-slate-950'
                                : isPrev
                                ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                                : 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                            }`}
                          >
                            {stage.stageNumber}
                          </span>

                          <span
                            className={`text-[10px] font-mono font-extrabold px-2.5 py-0.5 rounded uppercase ${
                              isCurrent
                                ? 'bg-cyan-400 text-slate-950'
                                : isPrev
                                ? 'bg-emerald-500/20 text-emerald-300'
                                : 'bg-amber-500/20 text-amber-300'
                            }`}
                          >
                            {isCurrent
                              ? 'CURRENT ACTIVE TRANSACTION ALERT'
                              : isPrev
                              ? 'PREVIOUS CORRELATED PREREQUISITE ALERT'
                              : 'NEXT POSSIBLE PREDICTED LIFECYCLE ALERT'}
                          </span>

                          <span className="font-mono text-xs text-slate-400">{stage.alertCode}</span>
                        </div>

                        <span className="text-xs font-semibold text-slate-300 bg-slate-800/80 px-3 py-1 rounded-lg border border-slate-700">
                          Correlation: <strong className="text-cyan-300">{stage.correlationType}</strong>
                        </span>
                      </div>

                      <h4 className="font-extrabold text-base text-white mt-3">{stage.title}</h4>
                      <p className="text-xs text-slate-300 leading-relaxed mt-1">{stage.description}</p>

                      <div className="mt-3 pt-3 border-t border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-[11px]">
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span className="text-slate-400">Correlated Entities:</span>
                          {stage.involvedEntities.map((ent, idx) => (
                            <button
                              key={idx}
                              onClick={() => ent.length <= 44 && onSelectAddress(ent)}
                              className="font-mono text-[10px] px-2 py-0.5 rounded bg-slate-800 text-cyan-300 hover:bg-slate-700 break-all cursor-pointer"
                            >
                              {ent}
                            </button>
                          ))}
                        </div>
                        <div className="text-slate-400 font-mono text-[10px]">
                          Trigger Proof: <span className="text-emerald-300">{stage.triggerIndicator}</span>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Section 3: Independent Standalone Alerts (Separated from Lifecycle Chain) */}
            <div className="bg-[#0f1522] border border-violet-500/30 rounded-2xl p-6 space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div>
                  <div className="flex items-center gap-2">
                    <Activity className="w-5 h-5 text-violet-400" />
                    <h3 className="font-extrabold text-base text-white">
                      Independent Standalone Alerts (Uncorrelated to Multi-Stage Token Lifecycle)
                    </h3>
                  </div>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Alerts and telemetry findings that operate independently within this single transaction envelope without requiring prior/next token lifecycle state.
                  </p>
                </div>
                <span className="px-3 py-1 rounded-xl bg-violet-500/15 text-violet-300 border border-violet-500/30 font-mono text-xs font-bold shrink-0">
                  {alertIntel.independentAlerts.length} Independent Alert(s)
                </span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {alertIntel.independentAlerts.map((ind) => (
                  <div
                    key={ind.id}
                    className="p-4 rounded-xl bg-[#090d14] border border-violet-500/25 space-y-2.5"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="px-2 py-0.5 rounded bg-violet-500/20 text-violet-300 font-mono text-[10px] font-bold">
                        INDEPENDENT ALERT • {ind.category.toUpperCase()}
                      </span>
                      <span className="font-mono text-[10px] text-slate-400">{ind.alertCode}</span>
                    </div>

                    <h4 className="font-bold text-sm text-white">{ind.title}</h4>
                    <p className="text-xs text-slate-300 leading-relaxed">{ind.observation}</p>

                    <div className="p-2.5 rounded-lg bg-violet-950/20 border border-violet-500/20 text-[11px] text-violet-200">
                      <strong>Why Independent:</strong> {ind.whyIndependent}
                    </div>

                    <div className="text-[10px] font-mono text-slate-400 pt-1 border-t border-slate-800 flex items-center justify-between">
                      <span>Field: {ind.verificationField}</span>
                      <span>{ind.affectedAddresses.length} Address(es)</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* =====================================================================
            TAB 3: EXECUTION TRACE (Requirement #4: Comprehensive CPI, Byte Hex, Sighash & Account Matrix)
           ===================================================================== */}
        {activeTab === 'trace' && (
          <div className="space-y-6">
            {/* Execution Summary & Compute Budget Telemetry HUD */}
            <div className="bg-[#0f1522] border border-slate-800 rounded-2xl p-5 space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div>
                  <h3 className="font-extrabold text-base text-white flex items-center gap-2">
                    <Cpu className="w-5 h-5 text-violet-400" />
                    <span>Comprehensive Instruction Execution Trace, CPI Call Stack & Byte Forensics</span>
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Complete outer instructions, nested Cross-Program Invocations (CPIs), Base58/Hex byte payloads, 8-byte Anchor sighash discriminators, and per-instruction account permission matrices.
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => {
                      const allOpen: Record<number, boolean> = {};
                      tx.outerInstructions.forEach((ix) => (allOpen[ix.index] = true));
                      setExpandedInst(allOpen);
                    }}
                    className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-cyan-300 border border-slate-700 cursor-pointer"
                  >
                    Expand All Instructions
                  </button>
                </div>
              </div>

              {/* Visual Compute & Instruction Waterfall Bar */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                <div className="p-3 rounded-xl bg-[#090d14] border border-slate-800">
                  <span className="text-[10px] text-slate-400 uppercase block">Total Invocations</span>
                  <span className="text-lg font-mono font-extrabold text-white">
                    {tx.allInstructionsFlat.length} Calls
                  </span>
                  <span className="text-[10px] text-slate-500 block">
                    {tx.outerInstructions.length} Top-Level + {tx.allInstructionsFlat.length - tx.outerInstructions.length} Inner CPIs
                  </span>
                </div>
                <div className="p-3 rounded-xl bg-[#090d14] border border-slate-800">
                  <span className="text-[10px] text-slate-400 uppercase block">Total Compute Consumed</span>
                  <span className="text-lg font-mono font-extrabold text-cyan-300">
                    {tx.computeUnitsConsumed?.toLocaleString() || 'N/A'} CU
                  </span>
                  <span className="text-[10px] text-slate-500 block">
                    {tx.deepCorrelations?.computeBudgetAnalysis?.computeEfficiencyPercent ?? 10}% of 200,000 CU Budget
                  </span>
                </div>
                <div className="p-3 rounded-xl bg-[#090d14] border border-slate-800">
                  <span className="text-[10px] text-slate-400 uppercase block">Max CPI Stack Depth</span>
                  <span className="text-lg font-mono font-extrabold text-violet-300">
                    Depth {Math.max(1, ...tx.allInstructionsFlat.map((i) => i.stackHeight))}
                  </span>
                  <span className="text-[10px] text-slate-500 block">Solana Max Allowed: Depth 4</span>
                </div>
                <div className="p-3 rounded-xl bg-[#090d14] border border-slate-800">
                  <span className="text-[10px] text-slate-400 uppercase block">Anchor Self-CPI Event</span>
                  <span className="text-lg font-mono font-extrabold text-emerald-300">
                    {tx.deepCorrelations?.token2022Summary?.invokesAnchorSelfCpiEvent ? 'DETECTED (emit_cpi!)' : 'Standard Logs'}
                  </span>
                  <span className="text-[10px] text-slate-500 block">Cryptographic Audit Log</span>
                </div>
              </div>
            </div>

            {/* Detailed Instruction Cards */}
            <div className="space-y-4">
              {tx.outerInstructions.map((inst) => {
                const isExpanded = Boolean(expandedInst[inst.index]);
                return (
                  <div
                    key={inst.index}
                    className="rounded-2xl bg-[#0f1522] border border-slate-800 overflow-hidden shadow-lg"
                  >
                    {/* Instruction Header */}
                    <div
                      onClick={() =>
                        setExpandedInst((prev) => ({ ...prev, [inst.index]: !prev[inst.index] }))
                      }
                      className="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 cursor-pointer hover:bg-slate-800/40 transition"
                    >
                      <div className="flex flex-wrap items-center gap-2.5">
                        {isExpanded ? (
                          <ChevronDown className="w-4 h-4 text-cyan-400" />
                        ) : (
                          <ChevronRight className="w-4 h-4 text-slate-400" />
                        )}
                        <span className="text-xs font-mono font-extrabold px-2.5 py-1 rounded-lg bg-violet-500/20 text-violet-300 border border-violet-500/30">
                          OUTER INSTRUCTION #{inst.index + 1} (STACK DEPTH 1)
                        </span>
                        <span className="text-sm font-extrabold text-white">{inst.programName}</span>
                        <span className="text-xs font-mono text-cyan-300 bg-cyan-500/10 px-2.5 py-0.5 rounded border border-cyan-500/30">
                          {inst.decodedName}
                        </span>
                        {inst.innerInstructions.length > 0 && (
                          <span className="text-[11px] font-mono px-2.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 font-bold">
                            +{inst.innerInstructions.length} Inner CPI Call(s)
                          </span>
                        )}
                      </div>

                      <div className="flex items-center gap-3 text-xs font-mono">
                        <span className="text-slate-400">
                          Payload: <strong className="text-white">{inst.byteForensics?.byteLength ?? 0} B</strong>
                        </span>
                        <span className="text-slate-400">
                          Accounts: <strong className="text-white">{inst.resolvedAccounts.length}</strong>
                        </span>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            onSelectAddress(inst.programId);
                          }}
                          className="text-cyan-400 hover:underline cursor-pointer"
                        >
                          {inst.programId}
                        </button>
                      </div>
                    </div>

                    {/* Expanded Deep Forensic Body */}
                    {isExpanded && (
                      <div className="p-5 pt-2 border-t border-slate-800/80 bg-[#090d14] space-y-5 text-xs">
                        {/* 1. Program ID & Byte / Sighash Forensics */}
                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 pt-2">
                          <div className="p-4 rounded-xl bg-[#0d131f] border border-slate-800 space-y-2">
                            <span className="text-[10px] font-bold uppercase tracking-wider text-violet-400 flex items-center gap-1.5">
                              <Binary className="w-3.5 h-3.5" /> Instruction Binary & Sighash Forensics
                            </span>
                            <div className="space-y-1 text-[11px]">
                              <div>
                                Invoked Program ID (Full):{' '}
                                <code className="font-mono text-cyan-300 break-all">{inst.programId}</code>
                              </div>
                              <div>
                                Encoding: <strong className="text-white font-mono">{inst.byteForensics?.rawEncoding}</strong> •
                                Length: <strong className="text-white font-mono">{inst.byteForensics?.byteLength ?? 0} bytes</strong>
                              </div>
                              {inst.byteForensics?.anchorDiscriminatorHex && (
                                <div>
                                  8-Byte Anchor Sighash Discriminator:{' '}
                                  <code className="font-mono text-emerald-300 font-bold bg-emerald-500/10 px-1.5 py-0.5 rounded">
                                    0x{inst.byteForensics.anchorDiscriminatorHex}
                                  </code>
                                </div>
                              )}
                              {inst.byteForensics?.decodedU64Values &&
                                inst.byteForensics.decodedU64Values.length > 0 && (
                                  <div>
                                    Decoded Little-Endian u64 Parameters:{' '}
                                    <span className="font-mono text-amber-300">
                                      {inst.byteForensics.decodedU64Values.join(' | ')}
                                    </span>
                                  </div>
                                )}
                            </div>
                            {inst.byteForensics?.forensicNotes && (
                              <div className="pt-2 border-t border-slate-800 space-y-1">
                                {inst.byteForensics.forensicNotes.map((n, idx) => (
                                  <div key={idx} className="text-[11px] text-slate-300">
                                    • {n}
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>

                          <div className="p-4 rounded-xl bg-[#0d131f] border border-slate-800 space-y-2">
                            <span className="text-[10px] font-bold uppercase tracking-wider text-cyan-400 block">
                              Raw Payload Data (Base58 / JSON & Hex Dump)
                            </span>
                            <div className="space-y-1.5">
                              <div className="text-[10px] text-slate-400">Raw Instruction Data:</div>
                              <pre className="p-2.5 rounded-lg bg-[#070a0f] border border-slate-800 font-mono text-[11px] text-cyan-200 overflow-x-auto whitespace-pre-wrap break-all">
                                {inst.rawData || '(empty)'}
                              </pre>
                              <div className="text-[10px] text-slate-400">Hexadecimal Byte Stream:</div>
                              <pre className="p-2.5 rounded-lg bg-[#070a0f] border border-slate-800 font-mono text-[11px] text-emerald-300 overflow-x-auto whitespace-pre-wrap break-all">
                                0x{inst.byteForensics?.hexPreview || '00'}
                              </pre>
                            </div>
                          </div>
                        </div>

                        {/* 2. Full Untruncated Account Permission Matrix for this Instruction */}
                        {inst.resolvedAccounts.length > 0 && (
                          <div className="space-y-2">
                            <span className="text-[11px] font-bold text-slate-300 uppercase tracking-wider block">
                              Instruction Account Permission Matrix ({inst.resolvedAccounts.length} Accounts — Zero Truncation)
                            </span>
                            <div className="overflow-x-auto rounded-xl border border-slate-800">
                              <table className="w-full text-left border-collapse text-xs">
                                <thead>
                                  <tr className="bg-[#0d131f] border-b border-slate-800 text-[10px] text-slate-400 uppercase">
                                    <th className="p-2.5">#</th>
                                    <th className="p-2.5">Full Account Address (Base58)</th>
                                    <th className="p-2.5">Resolved Entity / Role Hint</th>
                                    <th className="p-2.5">Permissions</th>
                                  </tr>
                                </thead>
                                <tbody className="divide-y divide-slate-800/60">
                                  {inst.resolvedAccounts.map((acc, aIdx) => (
                                    <tr key={aIdx} className="hover:bg-slate-800/30">
                                      <td className="p-2.5 font-mono text-slate-500">#{aIdx}</td>
                                      <td className="p-2.5 font-mono">
                                        <button
                                          onClick={() => onSelectAddress(acc.address)}
                                          className="text-cyan-300 hover:underline break-all text-left cursor-pointer"
                                        >
                                          {acc.address}
                                        </button>
                                      </td>
                                      <td className="p-2.5">
                                        <div className="font-semibold text-slate-200">
                                          {acc.label || acc.roleHint || 'Instruction Account'}
                                        </div>
                                        {acc.roleHint && acc.label && (
                                          <div className="text-[10px] text-slate-400">{acc.roleHint}</div>
                                        )}
                                      </td>
                                      <td className="p-2.5">
                                        <div className="flex flex-wrap gap-1">
                                          {acc.isSigner && (
                                            <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-mono text-[10px] font-bold">
                                              SIGNER
                                            </span>
                                          )}
                                          {acc.isWritable ? (
                                            <span className="px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 font-mono text-[10px] font-bold">
                                              WRITABLE
                                            </span>
                                          ) : (
                                            <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-400 font-mono text-[10px]">
                                              READ-ONLY
                                            </span>
                                          )}
                                        </div>
                                      </td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            </div>
                          </div>
                        )}

                        {/* 3. Nested Inner CPI Instructions Tree */}
                        {inst.innerInstructions.length > 0 && (
                          <div className="space-y-3 pt-2">
                            <span className="text-[11px] font-bold text-emerald-400 uppercase tracking-wider block">
                              Nested Cross-Program Invocations (CPI Call Stack — {inst.innerInstructions.length} Inner Calls)
                            </span>
                            <div className="space-y-3 pl-4 border-l-2 border-emerald-500/40">
                              {inst.innerInstructions.map((inner, cIdx) => (
                                <div
                                  key={cIdx}
                                  className="p-4 rounded-xl bg-[#0d1422] border border-emerald-500/30 space-y-3"
                                >
                                  <div className="flex flex-wrap items-center justify-between gap-2">
                                    <div className="flex flex-wrap items-center gap-2">
                                      <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-mono text-[10px] font-bold">
                                        CPI #{inst.index + 1}.{cIdx + 1} (STACK DEPTH {inner.stackHeight})
                                      </span>
                                      <span className="font-bold text-white text-sm">{inner.programName}</span>
                                      <span className="text-cyan-300 font-mono text-xs bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/30">
                                        {inner.decodedName}
                                      </span>
                                    </div>
                                    <button
                                      onClick={() => onSelectAddress(inner.programId)}
                                      className="font-mono text-[11px] text-cyan-400 hover:underline break-all cursor-pointer"
                                    >
                                      Program: {inner.programId}
                                    </button>
                                  </div>

                                  {/* Inner CPI Byte / Parsed Details */}
                                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-[11px]">
                                    <div className="p-3 rounded-lg bg-[#080b11] border border-slate-800 space-y-1">
                                      <div className="text-slate-400 font-semibold">CPI Payload & Sighash:</div>
                                      <div className="font-mono text-slate-200 break-all">
                                        Bytes: {inner.byteForensics?.byteLength ?? 0} B • Encoding:{' '}
                                        {inner.byteForensics?.rawEncoding}
                                      </div>
                                      {inner.byteForensics?.anchorDiscriminatorHex && (
                                        <div className="font-mono text-emerald-300">
                                          Discriminator: 0x{inner.byteForensics.anchorDiscriminatorHex}
                                        </div>
                                      )}
                                      {inner.byteForensics?.innerEventDiscriminatorHex && (
                                        <div className="font-mono text-amber-300">
                                          Inner Event Type Sighash: 0x{inner.byteForensics.innerEventDiscriminatorHex}
                                        </div>
                                      )}
                                    </div>

                                    <div className="p-3 rounded-lg bg-[#080b11] border border-slate-800 space-y-1">
                                      <div className="text-slate-400 font-semibold">Raw / Decoded CPI Data:</div>
                                      <pre className="font-mono text-[10px] text-cyan-200 overflow-x-auto whitespace-pre-wrap break-all">
                                        {inner.decodedDetails
                                          ? JSON.stringify(inner.decodedDetails, null, 2)
                                          : inner.rawData}
                                      </pre>
                                    </div>
                                  </div>

                                  {/* Inner CPI Accounts */}
                                  {inner.resolvedAccounts.length > 0 && (
                                    <div className="space-y-1">
                                      <span className="text-[10px] text-slate-400 uppercase block">
                                        CPI Accounts Passed ({inner.resolvedAccounts.length}):
                                      </span>
                                      <div className="flex flex-wrap gap-1.5">
                                        {inner.resolvedAccounts.map((ca, caIdx) => (
                                          <button
                                            key={caIdx}
                                            onClick={() => onSelectAddress(ca.address)}
                                            className="px-2.5 py-1 rounded bg-[#080b11] hover:bg-slate-800 border border-slate-800 font-mono text-[10px] text-cyan-300 break-all text-left cursor-pointer"
                                          >
                                            #{caIdx}: {ca.address} {ca.label ? `(${ca.label})` : ''}
                                          </button>
                                        ))}
                                      </div>
                                    </div>
                                  )}
                                </div>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* 4. Correlated Program Execution Logs */}
                        {inst.logs.length > 0 && (
                          <div className="space-y-1.5">
                            <span className="text-[10px] font-bold text-slate-400 uppercase flex items-center gap-1">
                              <Terminal className="w-3.5 h-3.5 text-cyan-400" /> Correlated Runtime Execution Logs
                            </span>
                            <div className="p-3 rounded-xl bg-[#06090e] border border-slate-800 font-mono text-[11px] text-slate-300 space-y-1 max-h-48 overflow-y-auto">
                              {inst.logs.map((l, lIdx) => (
                                <div key={lIdx} className="break-all">
                                  {l}
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* =====================================================================
            TAB 4: ADDRESS INTELLIGENCE (Requirement #1 & #8: Zero Errors, Deep Intelligence, Untruncated)
           ===================================================================== */}
        {activeTab === 'accounts' && (
          <div className="bg-[#0f1522] border border-slate-800 rounded-2xl p-5 space-y-5">
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
              <div>
                <h3 className="font-extrabold text-base text-white">
                  Deep Address Intelligence & Cryptographic Provenance Registry ({accountsList.length} Accounts)
                </h3>
                <p className="text-xs text-slate-400">
                  Full untruncated Base58 addresses, resolved protocol labels, owner programs vs. token owners, and exact balance shifts.
                </p>
              </div>

              {/* Search & Filter Controls */}
              <div className="flex flex-wrap items-center gap-2">
                <div className="relative">
                  <input
                    type="text"
                    value={accountSearch}
                    onChange={(e) => setAccountSearch(e.target.value)}
                    placeholder="Filter by address, label, or role..."
                    className="w-64 bg-[#090d14] border border-slate-700 rounded-xl pl-8 pr-3 py-1.5 text-xs text-slate-100 placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-400"
                  />
                  <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2" />
                </div>

                <select
                  value={accountCategoryFilter}
                  onChange={(e) => setAccountCategoryFilter(e.target.value)}
                  className="bg-[#090d14] border border-slate-700 rounded-xl px-3 py-1.5 text-xs text-slate-200 focus:outline-none cursor-pointer"
                >
                  <option value="all">All Categories ({accountsList.length})</option>
                  <option value="user-wallet">Wallets & Signers</option>
                  <option value="token-account">Token Custody Accounts</option>
                  <option value="token-mint">Token Mints</option>
                  <option value="program">Executable Programs</option>
                  <option value="pda">Program-Derived Addresses (PDAs)</option>
                </select>
              </div>
            </div>

            {/* Visual Category Breakdown Cards */}
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 text-xs">
              <div className="p-3 rounded-xl bg-[#090d14] border border-slate-800">
                <span className="text-[10px] text-slate-400 uppercase block">Cryptographic Signers</span>
                <span className="text-lg font-mono font-extrabold text-emerald-400">
                  {accountsList.filter((a) => a.isSigner).length}
                </span>
              </div>
              <div className="p-3 rounded-xl bg-[#090d14] border border-slate-800">
                <span className="text-[10px] text-slate-400 uppercase block">Writable State Accounts</span>
                <span className="text-lg font-mono font-extrabold text-amber-400">
                  {accountsList.filter((a) => a.isWritable).length}
                </span>
              </div>
              <div className="p-3 rounded-xl bg-[#090d14] border border-slate-800">
                <span className="text-[10px] text-slate-400 uppercase block">Token Custody & Mints</span>
                <span className="text-lg font-mono font-extrabold text-pink-400">
                  {accountsList.filter((a) => a.category === 'token-account' || a.category === 'token-mint').length}
                </span>
              </div>
              <div className="p-3 rounded-xl bg-[#090d14] border border-slate-800">
                <span className="text-[10px] text-slate-400 uppercase block">Smart Contract Programs</span>
                <span className="text-lg font-mono font-extrabold text-violet-400">
                  {accountsList.filter((a) => a.isExecutable || a.category.includes('program')).length}
                </span>
              </div>
              <div className="p-3 rounded-xl bg-[#090d14] border border-slate-800">
                <span className="text-[10px] text-slate-400 uppercase block">Verified Protocol Entities</span>
                <span className="text-lg font-mono font-extrabold text-cyan-400">
                  {accountsList.filter((a) => Boolean(a.institutionalInfo)).length}
                </span>
              </div>
            </div>

            <div className="overflow-x-auto rounded-xl border border-slate-800">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-[10px] text-slate-400 uppercase bg-[#090d14]">
                    <th className="p-3">Full Untruncated Address & Identity</th>
                    <th className="p-3">Category</th>
                    <th className="p-3">Cryptographic Roles</th>
                    <th className="p-3">Owner Program (Code Manager)</th>
                    <th className="p-3 text-right">SOL Balance & Delta</th>
                    <th className="p-3">Token Custody / Mint Details</th>
                    <th className="p-3 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {filteredAccounts.map((acc) => {
                    const safeOwnerProg = acc.ownerProgram || '11111111111111111111111111111111';
                    const tokDelta = tx.tokenBalanceDeltas.find(
                      (t) => t.accountAddress === acc.address || t.owner === acc.address
                    );

                    return (
                      <tr
                        key={acc.address}
                        onClick={() => onSelectAddress(acc.address)}
                        className="hover:bg-slate-800/40 transition cursor-pointer"
                      >
                        <td className="p-3 align-top">
                          <div className="font-bold text-white text-xs">
                            {acc.label || 'Solana Account'}
                          </div>
                          {acc.institutionalInfo && (
                            <div className="text-[10px] text-emerald-400 font-semibold">
                              {acc.institutionalInfo.institution} • {acc.institutionalInfo.roleTitle}
                            </div>
                          )}
                          <div className="flex items-center gap-1.5 mt-1">
                            <code className="font-mono text-[11px] text-cyan-300 break-all select-all">
                              {acc.address}
                            </code>
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                copyHelper(acc.address, `acc-${acc.address}`);
                              }}
                              className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white shrink-0"
                              title="Copy Full Address"
                            >
                              {copiedTextId === `acc-${acc.address}` ? (
                                <Check className="w-3 h-3 text-emerald-400" />
                              ) : (
                                <Copy className="w-3 h-3" />
                              )}
                            </button>
                          </div>
                        </td>

                        <td className="p-3 align-top">
                          <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-200 border border-slate-700 text-[10px] font-mono font-bold">
                            {(acc.category || 'unclassified').toUpperCase()}
                          </span>
                        </td>

                        <td className="p-3 align-top">
                          <div className="flex flex-wrap gap-1">
                            {acc.isFeePayer && (
                              <span className="px-1.5 py-0.5 rounded bg-cyan-500/20 text-cyan-300 text-[9px] font-bold">
                                FEE PAYER
                              </span>
                            )}
                            {acc.isSigner && (
                              <span className="px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 text-[9px] font-bold">
                                SIGNER
                              </span>
                            )}
                            {(acc.roles || []).map((r) => (
                              <span
                                key={r}
                                className="px-1.5 py-0.5 rounded bg-slate-800/90 text-slate-300 text-[9px] font-mono"
                              >
                                {r}
                              </span>
                            ))}
                          </div>
                        </td>

                        <td className="p-3 align-top font-mono text-[11px]">
                          <div className="font-sans font-semibold text-slate-200 text-xs">
                            {acc.ownerProgramLabel || 'System Program'}
                          </div>
                          <div className="text-[10px] text-slate-400 break-all">{safeOwnerProg}</div>
                        </td>

                        <td className="p-3 align-top text-right font-mono">
                          <div className="text-slate-200 font-bold">{(acc.solBalance ?? 0).toFixed(6)} SOL</div>
                          {acc.deltaSol !== undefined && acc.deltaSol !== 0 && (
                            <div
                              className={`text-[10px] font-bold ${
                                acc.deltaSol > 0 ? 'text-emerald-400' : 'text-rose-400'
                              }`}
                            >
                              {acc.deltaSol > 0 ? '+' : ''}
                              {acc.deltaSol.toFixed(6)} SOL
                            </div>
                          )}
                        </td>

                        <td className="p-3 align-top text-[11px]">
                          {acc.tokenMetadata ? (
                            <div className="space-y-0.5">
                              <div className="font-bold text-emerald-300">
                                {acc.tokenMetadata.mintName || 'Token'} ({acc.tokenMetadata.mintSymbol || 'SPL'})
                              </div>
                              {tokDelta && (
                                <div className="font-mono text-cyan-300 font-bold">
                                  Delta: {tokDelta.deltaUiAmount >= 0 ? '+' : ''}
                                  {tokDelta.deltaUiAmount} {tokDelta.mintSymbol} (Post: {tokDelta.postUiAmount})
                                </div>
                              )}
                            </div>
                          ) : tokDelta ? (
                            <div className="font-bold text-emerald-300">
                              Owner of {tokDelta.mintName} ({tokDelta.mintSymbol}) Vault
                            </div>
                          ) : (
                            <span className="text-slate-500">—</span>
                          )}
                        </td>

                        <td className="p-3 align-top text-right">
                          <button className="text-cyan-400 hover:text-cyan-300 text-xs font-bold px-2.5 py-1 rounded-lg bg-cyan-500/10 border border-cyan-500/30 cursor-pointer">
                            Inspect ({acc.roleProofs?.length || 0} Proofs)
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* =====================================================================
            TAB 5: AUTHORITIES (Requirement #3: Visual Hierarchy, Explanations & Untruncated Proofs)
           ===================================================================== */}
        {activeTab === 'authorities' && (
          <div className="space-y-6">
            {/* Visual Authority Control Topology & Architecture Explanation */}
            <div className="bg-[#0f1522] border border-slate-800 rounded-2xl p-6 space-y-5">
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
                <div>
                  <h3 className="font-extrabold text-base text-white flex items-center gap-2">
                    <Key className="w-5 h-5 text-amber-400" />
                    <span>On-Chain Authority Control Matrix & Cryptographic Permission Topology</span>
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Visualizes who holds administrative, signing, minting, freezing, and custody ownership powers across all accounts and tokens in this transaction.
                  </p>
                </div>
                <span className="px-3 py-1 rounded-xl bg-amber-500/15 text-amber-300 border border-amber-500/30 font-mono text-xs font-bold shrink-0">
                  {tx.authorities.length} Verified Authority Control Vectors
                </span>
              </div>

              {/* Educational Guide: Understanding Solana Authorities */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-3 text-xs">
                <div className="p-3.5 rounded-xl bg-[#090d14] border border-cyan-500/30 space-y-1">
                  <span className="text-[10px] font-mono font-bold text-cyan-300 uppercase block">
                    1. Token Account Owner Authority
                  </span>
                  <p className="text-[11px] text-slate-300 leading-relaxed">
                    The wallet or PDA that owns the tokens inside a Token Account vault and has permission to transfer or burn them.
                  </p>
                </div>
                <div className="p-3.5 rounded-xl bg-[#090d14] border border-pink-500/30 space-y-1">
                  <span className="text-[10px] font-mono font-bold text-pink-300 uppercase block">
                    2. Mint / Issuance Authority
                  </span>
                  <p className="text-[11px] text-slate-300 leading-relaxed">
                    The controller program or key authorized to issue new token supply and onboard client wallets on the Token Mint.
                  </p>
                </div>
                <div className="p-3.5 rounded-xl bg-[#090d14] border border-emerald-500/30 space-y-1">
                  <span className="text-[10px] font-mono font-bold text-emerald-300 uppercase block">
                    3. Dispatcher & Signer Authority
                  </span>
                  <p className="text-[11px] text-slate-300 leading-relaxed">
                    The Ed25519 private key holder that signed the transaction envelope, paid execution fees, and invoked the top-level program.
                  </p>
                </div>
                <div className="p-3.5 rounded-xl bg-[#090d14] border border-violet-500/30 space-y-1">
                  <span className="text-[10px] font-mono font-bold text-violet-300 uppercase block">
                    4. Event / Governance PDA Authority
                  </span>
                  <p className="text-[11px] text-slate-300 leading-relaxed">
                    A Program-Derived Address (PDA) that signs inner CPI instructions (`invoke_signed`) for audit logs or vault control.
                  </p>
                </div>
              </div>

              {/* Visual Directed Control Flow Diagram for Each Authority */}
              <div className="space-y-4 pt-2">
                {tx.authorities.map((auth, idx) => (
                  <div
                    key={idx}
                    className="p-5 rounded-2xl bg-[#090d14] border border-slate-800 hover:border-cyan-500/40 transition space-y-4"
                  >
                    {/* Visual 3-Stage Authority Vector Diagram */}
                    <div className="grid grid-cols-1 lg:grid-cols-11 gap-3 items-center">
                      {/* Left: Controlling Authority Entity */}
                      <div className="lg:col-span-4 p-3.5 rounded-xl bg-[#0f172a] border border-cyan-500/30 space-y-1">
                        <span className="text-[10px] font-mono uppercase text-cyan-400 font-bold block">
                          CONTROLLING AUTHORITY SOURCE
                        </span>
                        <div className="font-bold text-white text-xs">
                          {auth.authorityLabel || 'Controlling Authority'}
                        </div>
                        <button
                          onClick={() => onSelectAddress(auth.authorityAddress)}
                          className="font-mono text-[11px] text-cyan-300 hover:underline break-all text-left block cursor-pointer"
                        >
                          {auth.authorityAddress}
                        </button>
                      </div>

                      {/* Center: Permission Vector Arrow Badge */}
                      <div className="lg:col-span-3 flex flex-col items-center justify-center text-center p-2">
                        <span className="px-3 py-1 rounded-full bg-amber-500/20 text-amber-300 border border-amber-500/40 font-mono text-[10px] font-extrabold uppercase">
                          {auth.authorityType.replace(/-/g, ' ')}
                        </span>
                        <div className="flex items-center gap-1 text-cyan-400 my-1">
                          <span className="h-0.5 w-12 bg-cyan-500/50"></span>
                          <ArrowRight className="w-4 h-4" />
                          <span className="h-0.5 w-12 bg-cyan-500/50"></span>
                        </div>
                        <span className="text-[10px] font-mono text-emerald-400 font-bold uppercase">
                          STATUS: {auth.status.toUpperCase()}
                        </span>
                      </div>

                      {/* Right: Controlled Target Account / Mint */}
                      <div className="lg:col-span-4 p-3.5 rounded-xl bg-[#0f172a] border border-emerald-500/30 space-y-1">
                        <span className="text-[10px] font-mono uppercase text-emerald-400 font-bold block">
                          CONTROLLED TARGET ({auth.targetType.toUpperCase()})
                        </span>
                        <div className="font-bold text-white text-xs">
                          {auth.targetLabel || 'Controlled Target Asset'}
                        </div>
                        <button
                          onClick={() => onSelectAddress(auth.targetAddress)}
                          className="font-mono text-[11px] text-emerald-300 hover:underline break-all text-left block cursor-pointer"
                        >
                          {auth.targetAddress}
                        </button>
                      </div>
                    </div>

                    {/* Detailed Explanation & Scope */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs pt-2 border-t border-slate-800/80">
                      <div>
                        <span className="text-slate-400 font-semibold">Operational Scope: </span>
                        <span className="text-slate-200">
                          {auth.scopeDescription ||
                            `Verified ${auth.authorityType} governing ${auth.targetAddress}.`}
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-400 font-semibold">Security & Custody Impact: </span>
                        <span className="text-slate-200">
                          {auth.securityImpact ||
                            'Holds verified cryptographic control over the target state or token custody.'}
                        </span>
                      </div>
                    </div>

                    <div className="flex flex-wrap items-center justify-between gap-2 text-[10px] font-mono text-slate-400 pt-1">
                      <span>
                        RPC Provenance: {auth.evidence.sourceMethod} ({auth.evidence.fieldPath})
                      </span>
                      <button
                        onClick={() => setSelectedEvidence(auth.evidence)}
                        className="text-cyan-400 hover:underline font-bold cursor-pointer"
                      >
                        Inspect Raw Authority Proof JSON →
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* =====================================================================
            TAB 6: STATE CHANGES (Requirement #5: Exponentially In-Depth, Visuals & Zero Truncation)
           ===================================================================== */}
        {activeTab === 'transitions' && (
          <div className="space-y-6">
            <div className="bg-[#0f1522] border border-slate-800 rounded-2xl p-6 space-y-5">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div>
                  <h3 className="font-extrabold text-base text-white flex items-center gap-2">
                    <Coins className="w-5 h-5 text-cyan-400" />
                    <span>Comprehensive Ledger State Transitions & Exact Pre/Post Diffs (Zero Truncation)</span>
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Every observable account balance, token custody allocation, and state mutation with full untruncated addresses, visual comparison bars, and exact BigInt integer deltas.
                  </p>
                </div>
                <span className="px-3 py-1 rounded-xl bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 font-mono text-xs font-bold shrink-0">
                  {tx.stateTransitions.length} Verified State Mutations
                </span>
              </div>

              <div className="space-y-4">
                {tx.stateTransitions.map((st, idx) => {
                  const isToken = st.transitionType === 'token-delta' || st.transitionType === 'account-created';
                  return (
                    <div
                      key={st.id}
                      className={`p-5 rounded-2xl border space-y-4 ${
                        isToken
                          ? 'bg-emerald-950/15 border-emerald-500/35'
                          : 'bg-[#090d14] border-slate-800'
                      }`}
                    >
                      {/* Top Header: Transition Index, Account Label, Full Address, Confidence Badge */}
                      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-2 border-b border-slate-800/80 pb-3">
                        <div className="space-y-1">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="px-2.5 py-0.5 rounded bg-cyan-500/20 text-cyan-300 font-mono text-[10px] font-bold">
                              STATE MUTATION #{idx + 1} • {st.transitionType.toUpperCase()}
                            </span>
                            <span className="font-extrabold text-sm text-white">
                              {st.accountLabel || 'Solana State Account'}
                            </span>
                            {st.percentChange && (
                              <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 font-mono text-[10px] font-bold">
                                Delta: {st.percentChange}
                              </span>
                            )}
                          </div>
                          <div className="text-xs text-slate-400">
                            Full Account Address (Untruncated):{' '}
                            <button
                              onClick={() => onSelectAddress(st.account)}
                              className="font-mono text-cyan-300 hover:underline font-bold break-all cursor-pointer"
                            >
                              {st.account}
                            </button>
                          </div>
                        </div>

                        <div className="text-right">
                          <span className="px-2.5 py-1 rounded-lg bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 font-mono text-[10px] font-bold">
                            {st.confidence.toUpperCase()}
                          </span>
                        </div>
                      </div>

                      {/* Asset / Field & Visual Before -> After State Comparison */}
                      <div className="space-y-2">
                        <div className="text-xs font-bold text-amber-300">
                          Mutated Field / Asset: <span className="text-white">{st.fieldOrAsset}</span>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
                          <div className="p-3.5 rounded-xl bg-[#0d131f] border border-slate-800 space-y-1">
                            <span className="text-[10px] font-mono uppercase text-slate-400 block">
                              1. Pre-Transaction State (Before)
                            </span>
                            <div className="font-mono font-bold text-slate-200 break-all">
                              {st.beforeState}
                            </div>
                          </div>

                          <div className="p-3.5 rounded-xl bg-[#0d131f] border border-cyan-500/30 space-y-1">
                            <span className="text-[10px] font-mono uppercase text-cyan-300 block">
                              2. Exact Net State Shift (Delta)
                            </span>
                            <div className="font-mono font-extrabold text-emerald-400 break-all">
                              {st.rawDelta || st.notes}
                            </div>
                          </div>

                          <div className="p-3.5 rounded-xl bg-[#0d131f] border border-emerald-500/30 space-y-1">
                            <span className="text-[10px] font-mono uppercase text-emerald-300 block">
                              3. Post-Transaction State (After)
                            </span>
                            <div className="font-mono font-extrabold text-cyan-300 break-all">
                              {st.afterState}
                            </div>
                          </div>
                        </div>
                      </div>

                      {/* Visual State Progress Bar */}
                      <div className="space-y-1">
                        <div className="flex justify-between text-[10px] font-mono text-slate-400">
                          <span>Pre-Execution Ledger Snapshot</span>
                          <span>Committed Post-Execution Ledger State (Slot #{tx.slot.toLocaleString()})</span>
                        </div>
                        <div className="w-full h-2.5 rounded-full bg-slate-900 overflow-hidden flex">
                          <div
                            className="h-full bg-slate-600"
                            style={{ width: isToken ? '15%' : '85%' }}
                          ></div>
                          <div
                            className={`h-full ${isToken ? 'bg-emerald-400' : 'bg-cyan-400'}`}
                            style={{ width: isToken ? '85%' : '15%' }}
                          ></div>
                        </div>
                      </div>

                      {/* Footer Provenance & Notes */}
                      <div className="pt-2 border-t border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-[11px] text-slate-300">
                        <div>
                          <strong className="text-slate-400">Forensic Explanation:</strong> {st.notes}
                        </div>
                        <div className="font-mono text-[10px] text-slate-400 shrink-0">
                          Source: {st.instructionRef} •{' '}
                          <button
                            onClick={() => setSelectedEvidence(st.evidence)}
                            className="text-cyan-400 hover:underline font-bold cursor-pointer"
                          >
                            View RPC Proof
                          </button>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        )}

        {/* =====================================================================
            TAB 7: KNOWLEDGE GRAPH (Requirement #2)
           ===================================================================== */}
        {activeTab === 'graph' && (
          <div className="space-y-4">
            <KnowledgeGraph
              relationships={tx.relationships}
              accountsRegistry={tx.accountsRegistry}
              onSelectAddress={onSelectAddress}
              onSelectRelationship={(rel) => {
                setSelectedEvidence(rel.evidence);
              }}
            />
          </div>
        )}

        {/* =====================================================================
            TAB 8: EVIDENCE CATALOG (Requirement #6: Exponentially Detailed, Visuals & Zero Truncation)
           ===================================================================== */}
        {activeTab === 'evidence' && (
          <div className="space-y-6">
            {/* Top Visual Evidence Telemetry HUD */}
            <div className="bg-[#0f1522] border border-slate-800 rounded-2xl p-6 space-y-5">
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                <div>
                  <h3 className="font-extrabold text-base text-white flex items-center gap-2">
                    <Database className="w-5 h-5 text-cyan-400" />
                    <span>
                      Comprehensive Forensic Evidence & Cryptographic Provenance Catalog ({tx.evidenceCatalog.length} Verified Proofs)
                    </span>
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Every fact, balance delta, token identity, instruction byte payload, authority, and client onboarding finding backed by untruncated JSON-RPC field paths and raw on-chain values.
                  </p>
                </div>

                {/* Search Box */}
                <div className="relative w-full lg:w-80">
                  <input
                    type="text"
                    value={evidenceSearch}
                    onChange={(e) => setEvidenceSearch(e.target.value)}
                    placeholder="Search field paths, addresses, or proofs..."
                    className="w-full bg-[#090d14] border border-slate-700 rounded-xl pl-9 pr-3 py-2 text-xs text-slate-100 placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-400"
                  />
                  <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
                </div>
              </div>

              {/* Visual Category Distribution Cards */}
              <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 text-xs">
                {[
                  { id: 'all', label: 'All Verified Proofs', count: tx.evidenceCatalog.length, color: 'text-white' },
                  {
                    id: 'sol',
                    label: 'SOL Lamport Proofs',
                    count: tx.evidenceCatalog.filter((e) => e.id.includes('sol-delta')).length,
                    color: 'text-cyan-300',
                  },
                  {
                    id: 'token',
                    label: 'Token & Mint Proofs',
                    count: tx.evidenceCatalog.filter((e) => e.id.includes('token') || e.id.includes('mint')).length,
                    color: 'text-emerald-300',
                  },
                  {
                    id: 'instructions',
                    label: 'Instruction & CPI Proofs',
                    count: tx.evidenceCatalog.filter((e) => e.id.includes('ev-inst')).length,
                    color: 'text-violet-300',
                  },
                  {
                    id: 'alerts',
                    label: 'Onboarding & Header Proofs',
                    count: tx.evidenceCatalog.filter(
                      (e) => !e.id.includes('sol-delta') && !e.id.includes('token') && !e.id.includes('ev-inst')
                    ).length,
                    color: 'text-amber-300',
                  },
                ].map((cat) => (
                  <button
                    key={cat.id}
                    onClick={() => setEvidenceFilter(cat.id)}
                    className={`p-3.5 rounded-xl border text-left transition cursor-pointer ${
                      evidenceFilter === cat.id
                        ? 'bg-cyan-500/15 border-cyan-400'
                        : 'bg-[#090d14] border-slate-800 hover:border-slate-700'
                    }`}
                  >
                    <span className="text-[10px] text-slate-400 uppercase block">{cat.label}</span>
                    <span className={`text-xl font-mono font-extrabold ${cat.color}`}>{cat.count}</span>
                  </button>
                ))}
              </div>

              {/* Visual Proof Coverage Bar */}
              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-[11px] text-slate-400">
                  <span>100% On-Chain JSON-RPC Provenance Verification Coverage</span>
                  <span className="font-mono text-emerald-400 font-bold">
                    Endpoint: {tx.rpcEndpointUsed} • Slot #{tx.slot.toLocaleString()}
                  </span>
                </div>
                <div className="w-full h-2.5 rounded-full bg-slate-900 overflow-hidden flex">
                  <div className="h-full bg-cyan-400" style={{ width: '30%' }}></div>
                  <div className="h-full bg-emerald-400" style={{ width: '25%' }}></div>
                  <div className="h-full bg-violet-400" style={{ width: '30%' }}></div>
                  <div className="h-full bg-amber-400" style={{ width: '15%' }}></div>
                </div>
              </div>

              {/* Detailed Untruncated Evidence Cards */}
              <div className="space-y-4 pt-2">
                {filteredEvidence.map((ev, idx) => (
                  <div
                    key={ev.id}
                    className="p-5 rounded-2xl bg-[#090d14] border border-slate-800/90 space-y-3"
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="px-2.5 py-0.5 rounded bg-cyan-500/20 text-cyan-300 font-mono text-[10px] font-bold">
                          PROOF #{idx + 1} • {ev.id}
                        </span>
                        <span className="font-bold text-white font-mono text-xs">{ev.sourceMethod}</span>
                      </div>

                      <div className="flex items-center gap-2">
                        <span className="text-[10px] font-mono px-2.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 font-bold">
                          {ev.verificationStatus.toUpperCase()} ON-CHAIN
                        </span>
                        <button
                          onClick={() =>
                            copyHelper(JSON.stringify(ev.rawValue, null, 2), `ev-${ev.id}`)
                          }
                          className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-[10px] font-mono text-slate-300 flex items-center gap-1 cursor-pointer"
                        >
                          {copiedTextId === `ev-${ev.id}` ? (
                            <>
                              <Check className="w-3 h-3 text-emerald-400" /> Copied JSON
                            </>
                          ) : (
                            <>
                              <Copy className="w-3 h-3" /> Copy Raw Proof
                            </>
                          )}
                        </button>
                      </div>
                    </div>

                    {/* Forensic Interpretation */}
                    <div className="text-xs text-slate-200 leading-relaxed font-medium">
                      {ev.interpretation}
                    </div>

                    {/* Untruncated Provenance Metadata Grid */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5 text-[11px] font-mono">
                      <div className="p-2.5 rounded-lg bg-[#0d131f] border border-slate-800 break-all">
                        <span className="text-slate-500 block text-[10px]">JSON-RPC FIELD PATH (UNTRUNCATED):</span>
                        <span className="text-cyan-300">{ev.fieldPath}</span>
                      </div>
                      <div className="p-2.5 rounded-lg bg-[#0d131f] border border-slate-800 break-all">
                        <span className="text-slate-500 block text-[10px]">REFERENCED ENTITY / SIGNATURE:</span>
                        <span className="text-emerald-300">
                          {ev.accountAddress || ev.transactionSignature || tx.signature}
                        </span>
                      </div>
                    </div>

                    {/* Complete Raw On-Chain Value Inspector (Untruncated) */}
                    <div className="space-y-1">
                      <span className="text-[10px] font-mono uppercase text-slate-400 block">
                        Verified Raw On-Chain Payload Value (JSON):
                      </span>
                      <pre className="p-3.5 rounded-xl bg-[#06090f] border border-slate-800/90 font-mono text-[11px] text-slate-300 overflow-x-auto whitespace-pre-wrap break-all max-h-64">
                        {JSON.stringify(ev.rawValue, null, 2)}
                      </pre>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* =====================================================================
            TAB 9: FORENSIC REPORT (PRINT / PDF)
           ===================================================================== */}
        {activeTab === 'report' && (
          <div className="bg-white text-slate-900 p-8 sm:p-12 rounded-2xl shadow-2xl space-y-6 print:shadow-none print:p-0">
            <div className="border-b-2 border-slate-900 pb-4 flex items-center justify-between">
              <div>
                <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-slate-900">
                  SOL-MATE FORENSIC INVESTIGATION REPORT
                </h1>
                <p className="text-xs text-slate-600 mt-0.5">
                  Automated Solana On-Chain Forensic & Token Onboarding Intelligence Report • Sandeep Kumar Sahoo
                </p>
              </div>
              <div className="text-right text-xs text-slate-600">
                <div>Date: {new Date(tx.retrievedAt).toLocaleDateString()}</div>
                <div>
                  Status: <strong className="text-slate-900">{tx.success ? 'SUCCESS' : 'FAILED'}</strong>
                </div>
              </div>
            </div>

            <div className="space-y-2">
              <h2 className="text-sm font-bold uppercase tracking-wider text-slate-800">
                1. Executive Summary & Token Identity
              </h2>
              <p className="text-xs text-slate-700 leading-relaxed bg-slate-100 p-3.5 rounded-lg border border-slate-200 break-all">
                Transaction signature <code className="font-mono font-bold text-slate-900">{tx.signature}</code> was verified on Solana {tx.cluster} at slot {tx.slot.toLocaleString()} ({tx.formattedTime}). Total network execution fee was {tx.feeSol.toFixed(6)} SOL paid by {tx.feePayer}.{' '}
                {resolvedTokens.length > 0 &&
                  `Primary Token Involved: ${resolvedTokens[0].name} (${resolvedTokens[0].symbol}) on Mint ${resolvedTokens[0].mint}. `}
                {alertIntel?.clientOnboarding?.explanation}
              </p>
            </div>

            <div className="space-y-2">
              <h2 className="text-sm font-bold uppercase tracking-wider text-slate-800">
                2. State Transitions ({tx.stateTransitions.length})
              </h2>
              <div className="space-y-2">
                {tx.stateTransitions.map((st) => (
                  <div key={st.id} className="p-3 border rounded text-xs space-y-1 break-all">
                    <div className="font-bold text-slate-900">
                      {st.accountLabel} ({st.account}) — {st.fieldOrAsset}
                    </div>
                    <div className="font-mono text-slate-700">
                      Before: {st.beforeState} ➔ After: {st.afterState} ({st.rawDelta})
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="space-y-2">
              <h2 className="text-sm font-bold uppercase tracking-wider text-slate-800">
                3. Security & Compliance Heuristic Findings ({tx.riskFindings.length})
              </h2>
              <div className="space-y-2">
                {tx.riskFindings.map((f, i) => (
                  <div key={i} className="p-3 border rounded text-xs space-y-1">
                    <div className="font-bold text-slate-900">
                      {f.title} ({f.severity.toUpperCase()})
                    </div>
                    <p className="text-slate-700">{f.explanation}</p>
                    <div className="text-[10px] text-slate-500">Evidence: {f.evidence.sourceMethod}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

function MatchesCatAndQuery(acc: any, matchesCat: boolean, q: string): boolean {
  if (!matchesCat) return false;
  return (
    (acc.address || '').toLowerCase().includes(q) ||
    (acc.label || '').toLowerCase().includes(q) ||
    (acc.ownerProgramLabel || '').toLowerCase().includes(q) ||
    (acc.roles || []).some((r: string) => r.toLowerCase().includes(q))
  );
}
