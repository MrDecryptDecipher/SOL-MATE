/**
 * SOL-MATE — Ease Mode Forensic Command Workspace (A • B • C • D Architecture)
 * Provides an executive-grade, deeply advanced forensic experience:
 * A: Instant Solana Tx Hash Input, Live Mainnet Address Signature Discovery & 1-Click Verified Scenarios
 * B: Instant Alert Type Classification (Mint, Burn, StopCodes, Account Creation/Onboarding, Admin, Scam) with Rule IDs & Byte Proofs
 * C: Value Involved, Signers, Fee Payers, Interactive Whitelist Management, From -> To Flow of Funds & 10-Vector Scam/Admin Matrix
 * D: Interactive Knowledge Graph (Correlated Lifecycle vs. Independent Alert + Full Persistent IST Database Graph Topology)
 */

import React, { useState, useMemo } from 'react';
import {
  Search,
  ArrowRight,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  UserCheck,
  Clock,
  GitBranch,
  Database,
  KeyRound,
  Coins,
  Send,
  Loader2,
  Sparkles,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  Filter,
  Radio,
  Cpu,
} from 'lucide-react';
import { TransactionRecord } from '../types/forensics';
import {
  forensicsEngine,
  InvestigationProgress,
  isValidEvmAddress,
  isValidEvmTxHash,
} from '../services/forensicsEngine';
import { isValidBase58Signature, isValidSolanaAddress } from '../services/transactionParser';
import { getForensicReplayRawTransaction } from '../services/universalDetectionEngine';
import { REAL_MAINNET_SAMPLES } from './SearchHero';
import {
  buildEaseModeForensicBreakdown,
  PersistentKnowledgeGraphState,
  updateAddressCustomWhitelistStatus,
  WhitelistClassification,
} from '../services/knowledgeGraphService';
import {
  getAllWhitelistedKnowledgeBaseEntries,
  getInstitutionalMetadata,
} from '../services/protocolIntelligence';
import { StructuredAlertReportView } from './StructuredAlertReportView';

interface EaseModeWorkspaceProps {
  activeTransaction: TransactionRecord | null;
  onInvestigate: (query: string) => void;
  onSelectAddress: (address: string) => void;
  onSwitchToProMode: () => void;
  onSwitchToInstantMode?: () => void;
  isLoading: boolean;
  progress: InvestigationProgress | null;
  error: string | null;
  persistentKg: PersistentKnowledgeGraphState;
}

const LIVE_DISCOVERY_TARGETS = [
  {
    label: 'Institutional Fund Mint A',
    address: 'J4cTuCH6frt4AnEmKfMS2k8hsUf7K94PV62sjUJno8Cz',
  },
  {
    label: 'Institutional Fund Mint B',
    address: 'EToDtBM2knZ8N1BHyUq2Riq5ngWTcoD3k6qpsgf7CKYY',
  },
  {
    label: 'Institutional Controller Program',
    address: '9rdASsDUnrw2EsDARtfqjabqcjfXYFKu45kZ31wF74dg',
  },
  {
    label: 'SPL Token-2022 Program',
    address: 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb',
  },
];

function renderWhitelistBadge(status: WhitelistClassification, isCustom?: boolean) {
  if (status === 'INSTITUTIONAL_WHITELISTED') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-emerald-500/15 border border-emerald-500/40 text-emerald-300 text-[10px] font-mono font-bold">
        <ShieldCheck className="w-3 h-3 text-emerald-400" />
        {isCustom ? 'ANALYST WHITELISTED' : 'WHITELISTED INSTITUTIONAL'}
      </span>
    );
  }
  if (status === 'CORE_PROTOCOL_WHITELISTED') {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-cyan-500/15 border border-cyan-500/40 text-cyan-300 text-[10px] font-mono font-bold">
        <CheckCircle2 className="w-3 h-3 text-cyan-400" />
        WHITELISTED CORE PROTOCOL
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-rose-500/15 border border-rose-500/40 text-rose-300 text-[10px] font-mono font-bold">
      <AlertTriangle className="w-3 h-3 text-rose-400" />
      {isCustom ? 'FLAGGED EXTERNAL' : 'NOT WHITELISTED / EXTERNAL'}
    </span>
  );
}

export const EaseModeWorkspace: React.FC<EaseModeWorkspaceProps> = ({
  activeTransaction,
  onInvestigate,
  onSelectAddress,
  onSwitchToProMode,
  onSwitchToInstantMode,
  isLoading,
  progress,
  error,
  persistentKg,
}) => {
  const [txInput, setTxInput] = useState(activeTransaction?.signature || '');
  const [inputError, setInputError] = useState<string | null>(null);

  // Live Mainnet Address Signature Discovery State
  const [discoveryAddress, setDiscoveryAddress] = useState('');
  const [isDiscoveringSigs, setIsDiscoveringSigs] = useState(false);
  const [discoveredSigs, setDiscoveredSigs] = useState<
    { signature: string; slot: number; blockTime: number | null; err: any }[]
  >([]);
  const [discoveryNote, setDiscoveryNote] = useState<string | null>(null);

  // Step C Whitelist Table Filter & Custom Override State
  const [whitelistFilter, setWhitelistFilter] = useState<
    'ALL' | 'WHITELISTED' | 'NON_WHITELISTED' | 'SIGNERS' | 'PROGRAMS'
  >('ALL');
  const [addressSearch, setAddressSearch] = useState('');
  const [whitelistRevision, setWhitelistRevision] = useState(0);

  // Step D Knowledge Graph Interactive Controls
  const [graphViewMode, setGraphViewMode] = useState<'tx-correlation' | 'persistent-ist-db'>(
    'tx-correlation'
  );
  const [selectedGraphNodeId, setSelectedGraphNodeId] = useState<string | null>(null);
  const [kgZoom, setKgZoom] = useState<number>(1);
  const [kgCategoryFilter, setKgCategoryFilter] = useState<
    'ALL' | 'WHITELISTED' | 'NON_WHITELISTED' | 'PROGRAMS' | 'MINTS' | 'WALLETS'
  >('ALL');
  const [kgSearchQuery, setKgSearchQuery] = useState('');

  // Pre-Seeded Kinexys by J.P. Morgan & Solana Whitelist Knowledge Base Explorer State
  const [kbEcosystemFilter, setKbEcosystemFilter] = useState<
    'ALL' | 'FACT_CORE' | 'MONY' | 'JLTXX' | 'KINEXYS_SCA_EOA' | 'SOLANA_CORE'
  >('ALL');
  const [kbSearchQuery, setKbSearchQuery] = useState('');

  const allWhitelistKnowledgeBase = useMemo(() => getAllWhitelistedKnowledgeBaseEntries(), []);

  const filteredKnowledgeBase = useMemo(() => {
    return allWhitelistKnowledgeBase.filter((item) => {
      if (kbEcosystemFilter !== 'ALL' && item.ecosystem !== kbEcosystemFilter) {
        return false;
      }
      if (kbSearchQuery.trim()) {
        const q = kbSearchQuery.trim().toLowerCase();
        return (
          item.address.toLowerCase().includes(q) ||
          item.label.toLowerCase().includes(q) ||
          item.roleTitle.toLowerCase().includes(q) ||
          item.whatItIs.toLowerCase().includes(q) ||
          item.whyWhitelisted.toLowerCase().includes(q) ||
          item.howItWorks.toLowerCase().includes(q) ||
          (item.pairedAddress || '').toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [allWhitelistKnowledgeBase, kbEcosystemFilter, kbSearchQuery]);

  const breakdown = useMemo(() => {
    if (!activeTransaction) return null;
    return buildEaseModeForensicBreakdown(activeTransaction);
  }, [activeTransaction, persistentKg, whitelistRevision]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = txInput.trim();
    if (!trimmed) {
      setInputError(
        'Please paste a Solana transaction hash/signature or select a verified scenario below.'
      );
      return;
    }
    const isReplay = Boolean(getForensicReplayRawTransaction(trimmed));
    const isValid =
      isReplay ||
      isValidBase58Signature(trimmed) ||
      isValidSolanaAddress(trimmed) ||
      isValidEvmTxHash(trimmed) ||
      isValidEvmAddress(trimmed);

    if (!isValid) {
      setInputError(
        'Invalid Solana transaction hash format. Enter a Base58 signature (80–90 chars), Solana address, or 0x hash.'
      );
      return;
    }
    setInputError(null);
    onInvestigate(trimmed);
  };

  const handleSampleClick = (sig: string) => {
    setTxInput(sig);
    setInputError(null);
    onInvestigate(sig);
  };

  const handleDiscoverLiveSignatures = async (addrToQuery: string) => {
    const cleanAddr = addrToQuery.trim();
    if (!cleanAddr || !isValidSolanaAddress(cleanAddr)) {
      setDiscoveryNote('Please enter a valid Base58 Solana address to fetch live signatures.');
      return;
    }
    setDiscoveryAddress(cleanAddr);
    setIsDiscoveringSigs(true);
    setDiscoveryNote(`Querying Solana Mainnet RPC for recent transactions involving ${cleanAddr.slice(0, 12)}...`);
    try {
      const sigs = await forensicsEngine.getAddressHistory(cleanAddr, 6);
      setDiscoveredSigs(sigs);
      if (sigs.length > 0) {
        setDiscoveryNote(
          `Found ${sigs.length} live Mainnet transaction signature(s) for ${cleanAddr.slice(0, 10)}... — click any signature below to analyze in Ease Mode.`
        );
      } else {
        setDiscoveryNote('No recent signatures returned from RPC for this address.');
      }
    } catch (err: any) {
      setDiscoveryNote(err?.message || 'Unable to query live RPC signatures right now.');
    } finally {
      setIsDiscoveringSigs(false);
    }
  };

  const handleToggleAddressWhitelist = async (
    address: string,
    label: string,
    currentStatus: WhitelistClassification
  ) => {
    const nextStatus: WhitelistClassification =
      currentStatus === 'NON_WHITELISTED_EXTERNAL'
        ? 'INSTITUTIONAL_WHITELISTED'
        : 'NON_WHITELISTED_EXTERNAL';
    await updateAddressCustomWhitelistStatus({
      address,
      label,
      status: nextStatus,
    });
    setWhitelistRevision((r) => r + 1);
  };

  const filteredWhitelistRows = useMemo(() => {
    if (!breakdown) return [];
    return breakdown.addressWhitelistMatrix.filter((row) => {
      if (
        whitelistFilter === 'WHITELISTED' &&
        row.whitelistStatus === 'NON_WHITELISTED_EXTERNAL'
      ) {
        return false;
      }
      if (
        whitelistFilter === 'NON_WHITELISTED' &&
        row.whitelistStatus !== 'NON_WHITELISTED_EXTERNAL'
      ) {
        return false;
      }
      if (whitelistFilter === 'SIGNERS' && !row.isSigner) {
        return false;
      }
      if (
        whitelistFilter === 'PROGRAMS' &&
        !row.isExecutable &&
        row.category !== 'token-mint' &&
        row.category !== 'program'
      ) {
        return false;
      }
      if (addressSearch.trim()) {
        const q = addressSearch.trim().toLowerCase();
        return (
          row.address.toLowerCase().includes(q) ||
          row.label.toLowerCase().includes(q) ||
          row.roleSummary.toLowerCase().includes(q) ||
          row.institutionOrProtocol.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [breakdown, whitelistFilter, addressSearch]);

  const filteredPersistentNodes = useMemo(() => {
    return persistentKg.nodes.filter((n) => {
      if (kgCategoryFilter === 'WHITELISTED' && !n.isWhitelisted) return false;
      if (kgCategoryFilter === 'NON_WHITELISTED' && n.isWhitelisted) return false;
      if (kgCategoryFilter === 'PROGRAMS' && !n.category.includes('program')) return false;
      if (kgCategoryFilter === 'MINTS' && !n.category.includes('mint')) return false;
      if (
        kgCategoryFilter === 'WALLETS' &&
        (n.category.includes('program') || n.category.includes('mint'))
      ) {
        return false;
      }
      if (kgSearchQuery.trim()) {
        const q = kgSearchQuery.trim().toLowerCase();
        return (
          n.address.toLowerCase().includes(q) ||
          n.label.toLowerCase().includes(q) ||
          n.institution.toLowerCase().includes(q) ||
          n.ecosystem.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [persistentKg.nodes, kgCategoryFilter, kgSearchQuery]);

  // Compute radial SVG coordinates for Persistent Database Knowledge Graph topology
  const persistentGraphLayout = useMemo(() => {
    const nodesToRender = filteredPersistentNodes.slice(0, 18);
    const centerX = 460;
    const centerY = 195;
    const positions = new Map<string, { x: number; y: number; node: typeof nodesToRender[0] }>();

    nodesToRender.forEach((node, idx) => {
      if (idx === 0) {
        positions.set(node.address, { x: centerX, y: centerY, node });
      } else if (idx <= 6) {
        const angle = ((idx - 1) / Math.min(6, nodesToRender.length - 1)) * Math.PI * 2 - Math.PI / 2;
        positions.set(node.address, {
          x: Math.round(centerX + Math.cos(angle) * 145),
          y: Math.round(centerY + Math.sin(angle) * 110),
          node,
        });
      } else {
        const outerCount = nodesToRender.length - 7;
        const angle = ((idx - 7) / Math.max(1, outerCount)) * Math.PI * 2;
        positions.set(node.address, {
          x: Math.round(centerX + Math.cos(angle) * 320),
          y: Math.round(centerY + Math.sin(angle) * 155),
          node,
        });
      }
    });

    const visibleEdges = persistentKg.edges.filter(
      (e) => positions.has(e.source) && positions.has(e.target)
    );

    return { positions: Array.from(positions.values()), posMap: positions, visibleEdges };
  }, [filteredPersistentNodes, persistentKg.edges]);

  const selectedNodeRecord = useMemo(() => {
    if (!selectedGraphNodeId) return null;
    const fromKg = persistentKg.nodes.find((n) => n.address === selectedGraphNodeId);
    const fromTx = breakdown?.addressWhitelistMatrix.find(
      (r) => r.address === selectedGraphNodeId
    );
    const connectedEdges = persistentKg.edges.filter(
      (e) => e.source === selectedGraphNodeId || e.target === selectedGraphNodeId
    );
    return {
      address: selectedGraphNodeId,
      kgNode: fromKg,
      txRow: fromTx,
      connectedEdges,
    };
  }, [selectedGraphNodeId, persistentKg, breakdown]);

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 py-6 space-y-6">
      {/* =====================================================================
          STEP A: SOLANA TRANSACTION HASH INPUT, LIVE RPC DISCOVERY & SCENARIOS
         ===================================================================== */}
      <section className="bg-[#0d1320] border border-cyan-500/30 rounded-2xl p-5 sm:p-6 shadow-xl relative overflow-hidden">
        <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-cyan-400 via-blue-500 to-emerald-400" />

        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 mb-4">
          <div>
            <div className="inline-flex items-center gap-2 text-xs font-mono font-bold text-cyan-400">
              <span>EASE MODE • STEP A — REAL-TIME TRANSACTION ASSURANCE & LIVE MAINNET INPUT</span>
            </div>
            <h1 className="text-xl sm:text-2xl font-extrabold text-white mt-0.5">
              Adaptive Transaction Alert Intelligence, Counterparty Verification & IST Knowledge Graph
            </h1>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <span className="px-2.5 py-1 rounded-lg bg-[#080c14] border border-slate-800 text-[11px] font-mono text-emerald-400 flex items-center gap-1.5">
              <Database className="w-3.5 h-3.5" />
              <span>
                Persistent KG: {persistentKg.nodes.length} Nodes • {persistentKg.edges.length} Edges •{' '}
                {persistentKg.transactions.length} Txs (IST)
              </span>
            </span>
            {onSwitchToInstantMode && (
              <button
                type="button"
                onClick={onSwitchToInstantMode}
                className="px-3 py-1.5 rounded-lg bg-amber-500/15 hover:bg-amber-500/25 border border-amber-500/40 text-amber-300 text-xs font-bold transition cursor-pointer flex items-center gap-1.5"
              >
                <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-ping" />
                <span>Instant Mode (1s Whitelist Scanner) →</span>
              </button>
            )}
            <button
              type="button"
              onClick={onSwitchToProMode}
              className="px-3 py-1.5 rounded-lg bg-blue-500/15 hover:bg-blue-500/25 border border-blue-500/40 text-blue-300 text-xs font-bold transition cursor-pointer"
            >
              Open 9-Tab Pro Mode →
            </button>
          </div>
        </div>

        <form onSubmit={handleSearchSubmit} className="space-y-3">
          <div className="flex flex-col sm:flex-row gap-2.5">
            <div className="relative flex-1">
              <input
                type="text"
                value={txInput}
                onChange={(e) => {
                  setTxInput(e.target.value);
                  if (inputError) setInputError(null);
                }}
                placeholder="Paste Solana transaction hash / signature, Wallet, Mint, or 0x hash..."
                disabled={isLoading}
                className="w-full bg-[#070a10] border border-slate-700 focus:border-cyan-400 rounded-xl pl-10 pr-4 py-3 text-xs sm:text-sm font-mono text-white placeholder-slate-500 focus:outline-none transition"
              />
              <Search className="w-4 h-4 text-cyan-400 absolute left-3.5 top-3.5" />
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="px-6 py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-extrabold text-xs sm:text-sm flex items-center justify-center gap-2 shadow-lg shadow-cyan-500/20 transition cursor-pointer shrink-0 disabled:opacity-50"
            >
              {isLoading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Analyzing Tx...</span>
                </>
              ) : (
                <>
                  <span>Analyze Transaction</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </div>

          {inputError && (
            <p className="text-xs text-rose-400 flex items-center gap-1.5">
              <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
              <span>{inputError}</span>
            </p>
          )}
        </form>

        {/* Live Mainnet Signature Discovery Bar */}
        <div className="mt-4 pt-3 border-t border-slate-800/80 space-y-2.5">
          <div className="flex flex-wrap items-center justify-between gap-2 text-[11px]">
            <span className="font-bold text-slate-300 flex items-center gap-1.5">
              <Radio className="w-3.5 h-3.5 text-emerald-400" />
              Live Mainnet Address Signature Discovery (Fetch Real On-Chain Signatures):
            </span>
            <div className="flex flex-wrap items-center gap-1.5">
              {LIVE_DISCOVERY_TARGETS.map((t) => (
                <button
                  key={t.address}
                  type="button"
                  onClick={() => handleDiscoverLiveSignatures(t.address)}
                  disabled={isDiscoveringSigs}
                  className="px-2.5 py-1 rounded-lg bg-[#080c14] hover:bg-cyan-500/15 border border-slate-800 hover:border-cyan-500/40 text-[11px] font-mono text-cyan-300 transition cursor-pointer"
                >
                  Fetch {t.label}
                </button>
              ))}
            </div>
          </div>

          {discoveryNote && (
            <div className="p-2.5 rounded-xl bg-[#080c14] border border-slate-800 space-y-2">
              <div className="text-[11px] font-mono text-cyan-300 flex items-center justify-between">
                <span>{discoveryNote}</span>
                {discoveredSigs.length > 0 && (
                  <button
                    type="button"
                    onClick={() => {
                      setDiscoveredSigs([]);
                      setDiscoveryNote(null);
                    }}
                    className="text-[10px] text-slate-400 hover:text-white cursor-pointer"
                  >
                    Clear
                  </button>
                )}
              </div>
              {discoveredSigs.length > 0 && (
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                  {discoveredSigs.map((item) => (
                    <button
                      key={item.signature}
                      type="button"
                      onClick={() => handleSampleClick(item.signature)}
                      className="p-2 rounded-lg bg-[#0c1322] hover:bg-cyan-500/15 border border-slate-800 hover:border-cyan-400 text-left transition cursor-pointer flex items-center justify-between gap-2"
                    >
                      <div className="min-w-0">
                        <div className="text-[11px] font-mono font-bold text-white truncate">
                          {item.signature.slice(0, 22)}...
                        </div>
                        <div className="text-[10px] font-mono text-slate-400">
                          Slot #{item.slot.toLocaleString()} • {item.err ? 'REVERTED' : 'SUCCESS'}
                        </div>
                      </div>
                      <ArrowRight className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                    </button>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Quick 1-Click Verified Scenarios Bar */}
        <div className="mt-4 pt-3 border-t border-slate-800/80 space-y-2">
          <div className="flex items-center justify-between text-[11px] text-slate-400">
            <span className="font-semibold">
              1-Click Verified Forensic Scenarios (Mint • Onboarding • Burn Anomaly • SetStopCodes • DiamondCut • Unknown Fallback):
            </span>
            <span className="font-mono text-cyan-400 hidden sm:inline">
              Auto-trains Persistent Knowledge Graph in IST
            </span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
            {REAL_MAINNET_SAMPLES.map((s, i) => {
              const isSelected = activeTransaction?.signature === s.signature;
              return (
                <button
                  key={i}
                  type="button"
                  onClick={() => handleSampleClick(s.signature)}
                  disabled={isLoading}
                  className={`p-2.5 rounded-xl border text-left transition cursor-pointer flex items-center justify-between gap-2 ${
                    isSelected
                      ? 'bg-cyan-500/15 border-cyan-400 text-white'
                      : 'bg-[#080c14] hover:bg-[#101726] border-slate-800 text-slate-300'
                  }`}
                >
                  <div className="min-w-0">
                    <div className="text-[10px] font-mono text-cyan-400 truncate">{s.badge}</div>
                    <div className="text-xs font-bold text-white truncate">{s.label}</div>
                  </div>
                  <ArrowRight className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                </button>
              );
            })}
          </div>
        </div>

        {isLoading && progress && (
          <div className="mt-4 pt-3 border-t border-slate-800 space-y-1.5">
            <div className="flex items-center justify-between text-xs text-cyan-300 font-mono">
              <span>{progress.message}</span>
              <span>{progress.percent}%</span>
            </div>
            <div className="w-full h-1.5 bg-slate-900 rounded-full overflow-hidden">
              <div
                className="h-full bg-cyan-400 transition-all duration-300"
                style={{ width: `${progress.percent}%` }}
              />
            </div>
          </div>
        )}

        {error && !isLoading && (
          <div className="mt-4 p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-xs text-rose-300">
            {error}
          </div>
        )}
      </section>

      {/* If no transaction is loaded yet, prompt user */}
      {!breakdown && !isLoading && (
        <div className="p-8 rounded-2xl bg-[#0b101b] border border-slate-800 text-center space-y-4">
          <Sparkles className="w-8 h-8 text-cyan-400 mx-auto" />
          <div className="space-y-1 max-w-xl mx-auto">
            <h2 className="text-lg font-extrabold text-white">
              Select Any Solana Transaction Above for Instant Ease Mode Analysis
            </h2>
            <p className="text-xs text-slate-400">
              Click any of the 6 verified scenarios above or paste a Solana transaction hash to see
              Step B (Alert Classification), Step C (Value, Signers, Fee Payer, Whitelist & Flow of
              Funds), and Step D (Correlated vs. Independent Knowledge Graph).
            </p>
          </div>
        </div>
      )}

      {/* =====================================================================
          WHEN A TRANSACTION IS LOADED: RENDER COPYABLE ALERT REPORT + STEPS B, C, AND D
         ===================================================================== */}
      {breakdown && (
        <>
          <StructuredAlertReportView
            breakdown={breakdown}
            onSelectAddress={onSelectAddress}
            onInvestigateSignature={handleSampleClick}
          />

          {/* =================================================================
              STEP B: INSTANT ALERT CLASSIFICATION, BYTE PROOF & CLIENT ONBOARDING
             ================================================================= */}
          <section className="bg-[#0c121e] border border-slate-800 rounded-2xl p-5 sm:p-6 space-y-5">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-800/80">
              <div>
                <span className="text-xs font-mono font-bold text-emerald-400">
                  EASE MODE • STEP B — INSTANT ALERT CLASSIFICATION, BYTE PROOF & ONBOARDING DETECTION
                </span>
                <h2 className="text-lg sm:text-xl font-extrabold text-white mt-0.5">
                  {breakdown.alertHeadline}
                </h2>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <span
                  className={`px-3 py-1 rounded-lg font-mono text-xs font-extrabold uppercase border ${
                    breakdown.alertSeverity === 'critical'
                      ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                      : breakdown.alertSeverity === 'high'
                      ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                      : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                  }`}
                >
                  PRIMARY ALERT: {breakdown.primaryAlertKind} ({breakdown.alertSeverity})
                </span>

                {breakdown.isClientOnboarded && (
                  <span className="px-3 py-1 rounded-lg bg-emerald-500 text-slate-950 font-mono text-xs font-extrabold flex items-center gap-1">
                    <UserCheck className="w-3.5 h-3.5" />
                    CLIENT ONBOARDED FOR {breakdown.tokenInvolvedSymbol}
                  </span>
                )}
              </div>
            </div>

            {/* Executive Narrative Summary */}
            <div className="p-3.5 rounded-xl bg-[#080c14] border border-slate-800 text-xs text-slate-200 leading-relaxed">
              <span className="font-mono font-bold text-cyan-400 mr-2">FORENSIC VERDICT:</span>
              {breakdown.alertExplanation}
            </div>

            {/* ADAPTIVE BUSINESS & OPERATIONAL ALERT INTELLIGENCE (HANDLES ANY TRANSACTION WORKFLOW) */}
            <div className="space-y-2.5 p-4 rounded-xl bg-[#080c14] border border-cyan-500/30">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div>
                  <div className="text-xs font-extrabold text-cyan-300 uppercase tracking-wider flex items-center gap-2">
                    <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                    Adaptive Business & Operational Alert Intelligence (360° Transaction Review)
                  </div>
                  <p className="text-[11px] text-slate-400 mt-0.5">
                    Goes beyond fixed rulebooks to automatically surface every business, compliance, settlement, custody, and governance event occurring inside this transaction.
                  </p>
                </div>
                <span className="px-2.5 py-1 rounded-lg bg-cyan-500/15 border border-cyan-500/40 text-cyan-300 font-mono text-[11px] font-bold shrink-0">
                  {breakdown.dynamicSynthesizedAlerts.length} Business & Operational Event(s) Identified
                </span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5 pt-1">
                {breakdown.dynamicSynthesizedAlerts.map((dynAlert) => (
                  <div
                    key={dynAlert.alertId}
                    className={`p-3.5 rounded-xl border flex flex-col justify-between space-y-2 ${
                      dynAlert.severity === 'critical'
                        ? 'bg-rose-950/25 border-rose-500/50'
                        : dynAlert.severity === 'high'
                        ? 'bg-amber-950/25 border-amber-500/50'
                        : dynAlert.severity === 'medium'
                        ? 'bg-cyan-950/20 border-cyan-500/40'
                        : 'bg-[#0b101b] border-slate-800'
                    }`}
                  >
                    <div className="space-y-1.5">
                      <div className="flex flex-wrap items-center justify-between gap-1.5">
                        <div className="flex items-center gap-1.5">
                          <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-700 font-mono text-[10px] font-bold text-cyan-300">
                            {dynAlert.dynamicCode}
                          </span>
                          <span className="text-[10px] font-mono text-emerald-300 font-bold">
                            {dynAlert.categoryLabel}
                          </span>
                        </div>
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-mono font-extrabold uppercase ${
                            dynAlert.severity === 'critical'
                              ? 'bg-rose-500 text-slate-950'
                              : dynAlert.severity === 'high'
                              ? 'bg-amber-400 text-slate-950'
                              : dynAlert.severity === 'medium'
                              ? 'bg-cyan-400 text-slate-950'
                              : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                          }`}
                        >
                          {dynAlert.severity}
                        </span>
                      </div>

                      <div className="text-xs font-extrabold text-white">{dynAlert.title}</div>
                      <p className="text-[11px] text-slate-300 leading-relaxed">
                        {dynAlert.mechanism}
                      </p>
                    </div>

                    <div className="pt-2 border-t border-slate-800/80 space-y-1 font-mono text-[10px]">
                      <div className="text-slate-400 flex items-center justify-between gap-2">
                        <span className="truncate">
                          Origin: <span className="text-cyan-300">{dynAlert.synthesisOrigin}</span>
                        </span>
                        {dynAlert.involvedAddresses[0] && (
                          <button
                            type="button"
                            onClick={() => onSelectAddress(dynAlert.involvedAddresses[0])}
                            className="text-cyan-400 hover:underline shrink-0 cursor-pointer"
                          >
                            {dynAlert.involvedAddresses[0].slice(0, 10)}...
                          </button>
                        )}
                      </div>
                      <div className="text-amber-300 truncate" title={dynAlert.byteOrStateProof}>
                        Proof: {dynAlert.byteOrStateProof}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* 7-Dimension Alert Radar Grid with Rule IDs, Instruction Evidence & State Diffs */}
            <div className="space-y-2">
              <div className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                Baseline 7-Dimension Institutional Guardrail Radar (Mint • Burn • StopCodes • Onboarding • Admin • Scam • Transfer)
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
                {breakdown.matchedAlertKinds.map((item) => (
                  <div
                    key={item.kind}
                    className={`p-3.5 rounded-xl border transition flex flex-col justify-between space-y-2 ${
                      item.isMatched
                        ? item.badgeTone === 'rose'
                          ? 'bg-rose-950/30 border-rose-500/50 text-white'
                          : item.badgeTone === 'amber'
                          ? 'bg-amber-950/30 border-amber-500/50 text-white'
                          : item.badgeTone === 'emerald'
                          ? 'bg-emerald-950/30 border-emerald-500/50 text-white'
                          : 'bg-cyan-950/30 border-cyan-500/50 text-white'
                        : 'bg-[#080b12] border-slate-800/70 text-slate-500 opacity-80'
                    }`}
                  >
                    <div className="space-y-1">
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-[10px] font-mono text-cyan-400">{item.ruleId}</span>
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                            item.isMatched
                              ? 'bg-emerald-500 text-slate-950'
                              : 'bg-slate-800 text-slate-400'
                          }`}
                        >
                          {item.isMatched ? 'DETECTED' : 'NO'}
                        </span>
                      </div>
                      <div className="text-xs font-extrabold">{item.label}</div>
                      <p className="text-[11px] leading-relaxed text-slate-300">{item.reason}</p>
                    </div>

                    <div className="pt-2 border-t border-slate-800/80 space-y-0.5 font-mono text-[10px]">
                      <div className="text-slate-400 truncate" title={item.instructionEvidence}>
                        IX: <span className="text-slate-200">{item.instructionEvidence}</span>
                      </div>
                      <div className="text-emerald-300 truncate" title={item.stateDiffProof}>
                        Diff: {item.stateDiffProof}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Dedicated Client Onboarding, Token Metadata & IST Timestamps Strip */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-3 pt-1">
              <div className="p-4 rounded-xl bg-[#080c14] border border-slate-800 space-y-1.5">
                <span className="text-[10px] font-mono uppercase text-cyan-400 font-bold">
                  TOKEN / ASSET INVOLVED ({breakdown.tokenStandard})
                </span>
                <div className="text-base font-extrabold text-white">
                  {breakdown.tokenInvolvedName} ({breakdown.tokenInvolvedSymbol})
                </div>
                <button
                  type="button"
                  onClick={() => onSelectAddress(breakdown.tokenMintAddress)}
                  className="text-[11px] font-mono text-cyan-300 hover:underline truncate block max-w-full cursor-pointer"
                >
                  Mint Address: {breakdown.tokenMintAddress}
                </button>
                <div className="text-[11px] font-mono text-slate-400">
                  Governing Program:{' '}
                  <button
                    type="button"
                    onClick={() =>
                      onSelectAddress(breakdown.clientOnboardingDetails.governingProgramId)
                    }
                    className="text-emerald-300 hover:underline cursor-pointer"
                  >
                    {breakdown.clientOnboardingDetails.governingProgramName}
                  </button>
                </div>
              </div>

              <div className="p-4 rounded-xl bg-[#080c14] border border-slate-800 space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono uppercase text-emerald-400 font-bold">
                    CLIENT ONBOARDING & CUSTODY PROOF
                  </span>
                  <span className="px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-300 font-mono text-[10px] font-bold">
                    {breakdown.clientOnboardingDetails.onboardingStatus}
                  </span>
                </div>
                <div className="text-xs font-bold text-white">
                  Pre: {breakdown.clientOnboardingDetails.initialBalanceBefore} → Post:{' '}
                  <span className="text-emerald-400">
                    {breakdown.clientOnboardingDetails.resultingBalanceAfter}
                  </span>{' '}
                  ({breakdown.clientOnboardingDetails.provisionedAmount})
                </div>
                <div className="text-[11px] font-mono text-slate-300 flex flex-wrap gap-x-3 gap-y-1">
                  <button
                    type="button"
                    onClick={() =>
                      onSelectAddress(breakdown.clientOnboardingDetails.clientWalletAddress)
                    }
                    className="text-cyan-300 hover:underline cursor-pointer"
                  >
                    Client Wallet:{' '}
                    {breakdown.clientOnboardingDetails.clientWalletAddress.slice(0, 12)}...
                  </button>
                  <button
                    type="button"
                    onClick={() =>
                      onSelectAddress(breakdown.clientOnboardingDetails.clientTokenAccountAddress)
                    }
                    className="text-amber-300 hover:underline cursor-pointer"
                  >
                    Custody Vault:{' '}
                    {breakdown.clientOnboardingDetails.clientTokenAccountAddress.slice(0, 12)}...
                  </button>
                </div>
              </div>

              <div className="p-4 rounded-xl bg-[#080c14] border border-slate-800 space-y-1.5">
                <span className="text-[10px] font-mono uppercase text-amber-300 font-bold flex items-center gap-1">
                  <Clock className="w-3.5 h-3.5" /> IST TIMESTAMPS (ASIA/KOLKATA • UTC+05:30)
                </span>
                <div className="text-xs font-mono text-white">
                  On-Chain Block Time: <span className="text-cyan-300">{breakdown.blockTimeIST}</span>
                </div>
                <div className="text-xs font-mono text-slate-300">
                  KG Trained Time: <span className="text-emerald-300">{breakdown.trainedAtIST}</span>
                </div>
                <div className="text-[11px] font-mono text-slate-400">
                  Slot #{breakdown.slot.toLocaleString()} • {breakdown.computeUnitsConsumed.toLocaleString()} Compute Units
                </div>
              </div>
            </div>
          </section>

          {/* =================================================================
              STEP C: VALUE INVOLVED, SIGNERS, FEE PAYERS, WHITELIST AUDIT,
                      FROM -> TO FLOW OF FUNDS & 10-VECTOR SCAM/ADMIN MATRIX
             ================================================================= */}
          <section className="bg-[#0c121e] border border-slate-800 rounded-2xl p-5 sm:p-6 space-y-6">
            <div className="border-b border-slate-800/80 pb-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div>
                <span className="text-xs font-mono font-bold text-amber-300">
                  EASE MODE • STEP C — VALUE, SIGNERS, FEE PAYER, WHITELIST, FLOW OF FUNDS & 10-VECTOR SCAM AUDIT
                </span>
                <h2 className="text-lg sm:text-xl font-extrabold text-white mt-0.5">
                  Financial Impact, Counterparty Whitelist Provenance & Deterministic Security Matrix
                </h2>
              </div>
              <div className="flex items-center gap-2 font-mono text-xs">
                <span className="px-2.5 py-1 rounded-lg bg-emerald-500/15 border border-emerald-500/40 text-emerald-300 font-bold">
                  {breakdown.whitelistedCount} Whitelisted
                </span>
                <span
                  className={`px-2.5 py-1 rounded-lg border font-bold ${
                    breakdown.nonWhitelistedCount > 0
                      ? 'bg-rose-500/15 border-rose-500/40 text-rose-300'
                      : 'bg-slate-800 border-slate-700 text-slate-400'
                  }`}
                >
                  {breakdown.nonWhitelistedCount} Non-Whitelisted
                </span>
              </div>
            </div>

            {/* Top 3 Summary Cards: 1. Value Involved | 2. Signers & Fee Payer | 3. Scam / Admin Verdict */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              {/* 1. Value Involved */}
              <div className="p-4 rounded-xl bg-[#080c14] border border-slate-800 space-y-2.5">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono font-bold text-cyan-400 flex items-center gap-1.5">
                    <Coins className="w-4 h-4" /> 1. VALUE INVOLVED & SUPPLY DELTA
                  </span>
                  <span className="text-[11px] font-mono text-slate-400">
                    Slot #{breakdown.slot.toLocaleString()}
                  </span>
                </div>
                <div className="text-2xl font-mono font-extrabold text-white">
                  {breakdown.valueInvolvedHeadline}
                </div>
                <p className="text-xs text-slate-300 leading-relaxed">
                  {breakdown.valueInvolvedSubtext}
                </p>
                <div className="pt-2 border-t border-slate-800/80 space-y-1 font-mono text-[11px]">
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400">Net Supply Impact:</span>
                    <span className="text-emerald-300 font-bold">{breakdown.netSupplyImpact}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400">Network Fee:</span>
                    <span className="text-slate-200">
                      {breakdown.feeSolFormatted} ({breakdown.feeLamports} Lamports)
                    </span>
                  </div>
                </div>
              </div>

              {/* 2. Signers & Fee Payer */}
              <div className="p-4 rounded-xl bg-[#080c14] border border-slate-800 space-y-2.5">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono font-bold text-emerald-400 flex items-center gap-1.5">
                    <KeyRound className="w-4 h-4" /> 2. FEE PAYER & SIGNERS ({breakdown.signersAudit.length})
                  </span>
                </div>
                <div className="space-y-2">
                  <div className="p-2.5 rounded-lg bg-[#0c121e] border border-slate-800/90 space-y-1">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-[10px] font-mono font-bold text-amber-300">
                        FEE PAYER & DISPATCHER
                      </span>
                      {renderWhitelistBadge(
                        breakdown.feePayerAudit.whitelistStatus,
                        breakdown.feePayerAudit.isCustomWhitelisted
                      )}
                    </div>
                    <div className="text-xs font-bold text-white truncate">
                      {breakdown.feePayerAudit.label}
                    </div>
                    <button
                      type="button"
                      onClick={() => onSelectAddress(breakdown.feePayerAudit.address)}
                      className="text-[11px] font-mono text-cyan-300 hover:underline truncate block max-w-full cursor-pointer"
                    >
                      {breakdown.feePayerAudit.address}
                    </button>
                    <div className="text-[10px] font-mono text-slate-400">
                      SOL Balance: {breakdown.feePayerAudit.preSolFormatted} →{' '}
                      {breakdown.feePayerAudit.postSolFormatted} ({breakdown.feePayerAudit.solDeltaFormatted})
                    </div>
                  </div>

                  {breakdown.signersAudit
                    .filter((s) => s.address !== breakdown.feePayerAudit.address)
                    .map((sigAcc) => (
                      <div
                        key={sigAcc.address}
                        className="p-2 rounded-lg bg-[#0c121e] border border-slate-800/90 flex items-center justify-between gap-2"
                      >
                        <button
                          type="button"
                          onClick={() => onSelectAddress(sigAcc.address)}
                          className="text-[11px] font-mono text-cyan-300 hover:underline truncate cursor-pointer"
                        >
                          Co-Signer: {sigAcc.address.slice(0, 16)}...
                        </button>
                        {renderWhitelistBadge(
                          sigAcc.whitelistStatus,
                          sigAcc.isCustomWhitelisted
                        )}
                      </div>
                    ))}
                </div>
              </div>

              {/* 3. Scam / Anomaly & Admin-Level Verdict */}
              <div
                className={`p-4 rounded-xl border space-y-2 ${
                  breakdown.scamOrAnomalyVerdict.status === 'CRITICAL_ANOMALY_OR_SCAM_RISK'
                    ? 'bg-rose-950/25 border-rose-500/50'
                    : breakdown.scamOrAnomalyVerdict.status === 'ADMIN_GOVERNANCE_CHANGE'
                    ? 'bg-amber-950/20 border-amber-500/40'
                    : 'bg-emerald-950/20 border-emerald-500/40'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono font-bold text-white flex items-center gap-1.5">
                    <ShieldAlert className="w-4 h-4 text-cyan-400" /> 3. ADMIN & SCAM / ANOMALY VERDICT
                  </span>
                  <span className="px-2 py-0.5 rounded bg-slate-900/80 border border-slate-700 font-mono text-[10px] font-bold text-cyan-300">
                    Risk: {breakdown.scamOrAnomalyVerdict.riskScore}/100
                  </span>
                </div>
                <div className="text-xs font-extrabold text-white">
                  {breakdown.scamOrAnomalyVerdict.headline}
                </div>
                <p className="text-[11px] text-slate-300 leading-relaxed">
                  {breakdown.scamOrAnomalyVerdict.explanation}
                </p>
                <ul className="space-y-1 pt-1">
                  {breakdown.scamOrAnomalyVerdict.indicators.slice(0, 3).map((ind, idx) => (
                    <li key={idx} className="text-[11px] text-slate-300 flex items-start gap-1.5">
                      <span className="text-cyan-400 font-bold">•</span>
                      <span>{ind}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>

            {/* 4. Visual From -> To Flow of Funds Pipeline */}
            <div className="space-y-2.5">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                  <Send className="w-3.5 h-3.5 text-cyan-400" />
                  4. From → To Flow of Funds & Asset Movement Reconciliation
                </h3>
                <span className="text-[11px] font-mono text-slate-400">
                  {breakdown.flowOfFunds.length} Verified Flow Vector(s)
                </span>
              </div>

              <div className="space-y-2.5">
                {breakdown.flowOfFunds.map((flow) => (
                  <div
                    key={flow.id}
                    className="p-4 rounded-xl bg-[#080c14] border border-slate-800 grid grid-cols-1 lg:grid-cols-11 gap-3 items-center"
                  >
                    {/* FROM */}
                    <div className="lg:col-span-4 space-y-1">
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-[10px] font-mono uppercase text-slate-400">
                          FROM (SOURCE / ISSUER • IX #{flow.instructionIndex})
                        </span>
                        {renderWhitelistBadge(flow.fromWhitelisted)}
                      </div>
                      <div className="text-xs font-bold text-white truncate">{flow.fromLabel}</div>
                      <button
                        type="button"
                        onClick={() => onSelectAddress(flow.fromAddress)}
                        className="text-[11px] font-mono text-cyan-300 hover:underline truncate block max-w-full cursor-pointer"
                      >
                        {flow.fromAddress}
                      </button>
                    </div>

                    {/* DIRECTION & AMOUNT */}
                    <div className="lg:col-span-3 flex flex-col items-center justify-center p-2.5 rounded-xl bg-[#0d1422] border border-cyan-500/30 text-center">
                      <span className="text-[10px] font-mono font-bold text-cyan-300 uppercase">
                        {flow.flowKind.replace(/_/g, ' ')}
                      </span>
                      <div className="text-sm font-mono font-extrabold text-white my-0.5">
                        {flow.formattedAmount}
                      </div>
                      <span className="text-[10px] text-slate-400 font-mono">
                        {flow.rawAmountInfo}
                      </span>
                    </div>

                    {/* TO */}
                    <div className="lg:col-span-4 space-y-1">
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-[10px] font-mono uppercase text-slate-400">
                          TO (DESTINATION / RECIPIENT)
                        </span>
                        {renderWhitelistBadge(flow.toWhitelisted)}
                      </div>
                      <div className="text-xs font-bold text-white truncate">{flow.toLabel}</div>
                      <button
                        type="button"
                        onClick={() => onSelectAddress(flow.toAddress)}
                        className="text-[11px] font-mono text-cyan-300 hover:underline truncate block max-w-full cursor-pointer"
                      >
                        {flow.toAddress}
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* 5. 10-Vector Deterministic Admin & Scam/Anomaly Evaluation Matrix */}
            <div className="space-y-2.5">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                  <Cpu className="w-3.5 h-3.5 text-emerald-400" />
                  5. 10-Vector Deterministic Admin & Scam / Anomaly Security Audit
                </h3>
                <span className="text-[11px] font-mono text-slate-400">
                  Evaluates Supply, Burn Conservation, StopCodes, Upgrades, Whitelist & Drains
                </span>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
                {breakdown.tenVectorSecurityMatrix.map((vec) => (
                  <div
                    key={vec.vectorId}
                    className={`p-3 rounded-xl border flex flex-col justify-between space-y-1.5 ${
                      vec.status === 'CRITICAL_VIOLATION'
                        ? 'bg-rose-950/25 border-rose-500/50'
                        : vec.status === 'ADMIN_GOVERNANCE'
                        ? 'bg-amber-950/20 border-amber-500/40'
                        : 'bg-[#080c14] border-slate-800'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-xs font-bold text-white">
                        <span className="font-mono text-cyan-400 mr-1.5">{vec.vectorId}</span>
                        {vec.title}
                      </span>
                      <span
                        className={`px-2 py-0.5 rounded font-mono text-[10px] font-bold shrink-0 ${
                          vec.status === 'CRITICAL_VIOLATION'
                            ? 'bg-rose-500 text-slate-950'
                            : vec.status === 'ADMIN_GOVERNANCE'
                            ? 'bg-amber-400 text-slate-950'
                            : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                        }`}
                      >
                        {vec.status.replace(/_/g, ' ')}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-300 leading-relaxed">{vec.proofSummary}</p>
                    <div className="flex items-center justify-between text-[10px] font-mono text-slate-400 pt-1 border-t border-slate-800/70">
                      <span>{vec.domain}</span>
                      <span className="text-cyan-300 truncate max-w-[210px]">
                        {vec.technicalEvidence}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* 6. Complete Interactive Associated Addresses Whitelist Verification Table */}
            <div className="space-y-3">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div>
                  <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">
                    6. Interactive Associated Addresses Whitelist Verification Table (
                    {filteredWhitelistRows.length}/{breakdown.addressWhitelistMatrix.length}{' '}
                    Entities)
                  </h3>
                  <p className="text-[11px] text-slate-400">
                    Filter by provenance, inspect live RPC state, or click &ldquo;Whitelist / Flag&rdquo; to
                    persist analyst provenance overrides to the Knowledge Graph in IST.
                  </p>
                </div>

                <div className="flex flex-wrap items-center gap-1.5">
                  {(
                    [
                      ['ALL', 'All Entities'],
                      ['WHITELISTED', 'Whitelisted'],
                      ['NON_WHITELISTED', 'Non-Whitelisted'],
                      ['SIGNERS', 'Signers'],
                      ['PROGRAMS', 'Programs & Mints'],
                    ] as const
                  ).map(([key, label]) => (
                    <button
                      key={key}
                      type="button"
                      onClick={() => setWhitelistFilter(key)}
                      className={`px-2.5 py-1 rounded-lg text-[11px] font-mono font-bold transition cursor-pointer ${
                        whitelistFilter === key
                          ? 'bg-cyan-500 text-slate-950'
                          : 'bg-[#080c14] border border-slate-800 text-slate-400 hover:text-white'
                      }`}
                    >
                      {label}
                    </button>
                  ))}
                  <input
                    type="text"
                    value={addressSearch}
                    onChange={(e) => setAddressSearch(e.target.value)}
                    placeholder="Filter address or role..."
                    className="bg-[#080c14] border border-slate-800 rounded-lg px-2.5 py-1 text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400 w-44"
                  />
                </div>
              </div>

              <div className="overflow-x-auto rounded-xl border border-slate-800 bg-[#080c14]">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="border-b border-slate-800 text-[10px] font-mono uppercase text-slate-400 bg-[#0b101b]">
                      <th className="py-2.5 px-3">Entity / Address</th>
                      <th className="py-2.5 px-3">Role & Permissions</th>
                      <th className="py-2.5 px-3">Whitelist Status</th>
                      <th className="py-2.5 px-3">Institution / Protocol</th>
                      <th className="py-2.5 px-3 text-right">SOL / Token Delta</th>
                      <th className="py-2.5 px-3 text-right">Analyst Whitelist Control</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/70">
                    {filteredWhitelistRows.map((row) => {
                      const instMeta = getInstitutionalMetadata(row.address);
                      return (
                        <tr key={row.address} className="hover:bg-slate-900/60 transition">
                          <td className="py-2.5 px-3">
                            <div className="font-bold text-slate-100">{row.label}</div>
                            <button
                              type="button"
                              onClick={() => onSelectAddress(row.address)}
                              className="font-mono text-[11px] text-cyan-300 hover:underline cursor-pointer"
                            >
                              {row.address}
                            </button>
                            {instMeta?.pairedAddress && (
                              <div className="text-[10px] font-mono text-violet-300 mt-0.5">
                                Paired ({instMeta.pairedRole}):{' '}
                                <button
                                  type="button"
                                  onClick={() => onSelectAddress(instMeta.pairedAddress!)}
                                  className="underline hover:text-white cursor-pointer"
                                >
                                  {instMeta.pairedAddress.slice(0, 14)}...
                                </button>
                              </div>
                            )}
                          </td>
                          <td className="py-2.5 px-3 max-w-xs">
                            <div className="text-slate-200 text-[11px] font-semibold">
                              {instMeta?.roleTitle || row.roleSummary}
                            </div>
                            {instMeta && (
                              <div className="text-[10px] text-slate-400 mt-0.5 leading-snug">
                                <span className="text-cyan-300 font-semibold">What:</span>{' '}
                                {instMeta.whatItIs}
                              </div>
                            )}
                            <div className="flex flex-wrap gap-1 mt-1">
                              {row.isFeePayer && (
                                <span className="px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 text-[9px] font-mono font-bold">
                                  FEE PAYER
                                </span>
                              )}
                              {row.isSigner && (
                                <span className="px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 text-[9px] font-mono font-bold">
                                  SIGNER
                                </span>
                              )}
                              {row.isWritable && (
                                <span className="px-1.5 py-0.5 rounded bg-cyan-500/20 text-cyan-300 text-[9px] font-mono font-bold">
                                  WRITABLE
                                </span>
                              )}
                              {row.isExecutable && (
                                <span className="px-1.5 py-0.5 rounded bg-violet-500/20 text-violet-300 text-[9px] font-mono font-bold">
                                  EXECUTABLE
                                </span>
                              )}
                            </div>
                          </td>
                          <td className="py-2.5 px-3 max-w-xs">
                            {renderWhitelistBadge(row.whitelistStatus, row.isCustomWhitelisted)}
                            {instMeta && (
                              <div className="text-[10px] text-slate-400 mt-1 leading-snug">
                                <span className="text-emerald-300 font-semibold">Why:</span>{' '}
                                {instMeta.whyWhitelisted}
                              </div>
                            )}
                          </td>
                          <td className="py-2.5 px-3 text-[11px] text-slate-300 max-w-xs">
                            <div className="font-semibold text-white">
                              {row.institutionOrProtocol}
                            </div>
                            <div className="text-[10px] font-mono text-slate-500">
                              Owner: {row.ownerProgram}
                            </div>
                            {instMeta && (
                              <div className="text-[10px] text-slate-400 mt-0.5 leading-snug">
                                <span className="text-amber-300 font-semibold">How:</span>{' '}
                                {instMeta.howItWorks}
                              </div>
                            )}
                          </td>
                          <td className="py-2.5 px-3 text-right font-mono text-[11px]">
                            {row.tokenDeltaFormatted !== '—' && (
                              <div className="font-bold text-emerald-300">
                                {row.tokenDeltaFormatted}
                              </div>
                            )}
                            <div className="text-slate-400">{row.solDeltaFormatted}</div>
                          </td>
                          <td className="py-2.5 px-3 text-right">
                            <div className="inline-flex items-center gap-1.5">
                              <button
                                type="button"
                                onClick={() =>
                                  handleToggleAddressWhitelist(
                                    row.address,
                                    row.label,
                                    row.whitelistStatus
                                  )
                                }
                                className={`px-2.5 py-1 rounded-lg font-mono text-[10px] font-bold border transition cursor-pointer ${
                                  row.whitelistStatus === 'NON_WHITELISTED_EXTERNAL'
                                    ? 'bg-emerald-500/15 hover:bg-emerald-500/25 border-emerald-500/40 text-emerald-300'
                                    : 'bg-rose-500/10 hover:bg-rose-500/20 border-rose-500/30 text-rose-300'
                                }`}
                              >
                                {row.whitelistStatus === 'NON_WHITELISTED_EXTERNAL'
                                  ? '+ Verify & Whitelist'
                                  : 'Flag External'}
                              </button>
                              <button
                                type="button"
                                onClick={() => onSelectAddress(row.address)}
                                className="px-2 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-300 font-mono text-[10px] cursor-pointer"
                              >
                                RPC Drawer
                              </button>
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>

            {/* 7. Pre-Seeded Institutional & Solana Whitelisted Knowledge Base Directory */}
            <div className="space-y-3 pt-4 border-t border-slate-800/90">
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-2">
                <div>
                  <span className="text-[10px] font-mono font-bold text-emerald-400 uppercase">
                    AUTHORITATIVE WHITELIST KNOWLEDGE BASE (PRE-TRAINED IN PERSISTENT GRAPH)
                  </span>
                  <h3 className="text-sm sm:text-base font-extrabold text-white">
                    7. Verified Institutional Counterparty, Tokenized Asset & Smart Contract Whitelist Registry ({filteredKnowledgeBase.length}/{allWhitelistKnowledgeBase.length} Entities)
                  </h3>
                  <p className="text-[11px] text-slate-400">
                    Every whitelisted address below is pre-trained into our Persistent Knowledge Graph with its exact Role, What It Is, Why It Is Whitelisted, How It Works, and Paired SCA↔EOA / PDA relationships.
                  </p>
                </div>

                <div className="flex flex-wrap items-center gap-1.5">
                  {(
                    [
                      ['ALL', `All (${allWhitelistKnowledgeBase.length})`],
                      ['FACT_CORE', 'Core Governance & Compliance (9)'],
                      ['MONY', 'Institutional Asset Suite I (5)'],
                      ['JLTXX', 'Institutional Asset Suite II (5)'],
                      ['KINEXYS_SCA_EOA', 'SCA ↔ EOA Signer Pairs (12)'],
                      ['SOLANA_CORE', 'Solana Native (5)'],
                    ] as const
                  ).map(([key, label]) => (
                    <button
                      key={key}
                      type="button"
                      onClick={() => setKbEcosystemFilter(key)}
                      className={`px-2.5 py-1 rounded-lg text-[11px] font-mono font-bold transition cursor-pointer ${
                        kbEcosystemFilter === key
                          ? 'bg-emerald-500 text-slate-950'
                          : 'bg-[#080c14] border border-slate-800 text-slate-400 hover:text-white'
                      }`}
                    >
                      {label}
                    </button>
                  ))}
                  <input
                    type="text"
                    value={kbSearchQuery}
                    onChange={(e) => setKbSearchQuery(e.target.value)}
                    placeholder="Search address, role, program, SCA, EOA..."
                    className="bg-[#080c14] border border-slate-800 rounded-lg px-2.5 py-1 text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-emerald-400 w-56"
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 max-h-[540px] overflow-y-auto pr-1">
                {filteredKnowledgeBase.map((meta) => (
                  <div
                    key={meta.address}
                    className="p-3.5 rounded-xl bg-[#080c14] border border-slate-800 hover:border-emerald-500/40 transition space-y-2 flex flex-col justify-between"
                  >
                    <div className="space-y-1.5">
                      <div className="flex flex-wrap items-center justify-between gap-1.5">
                        <span className="px-2 py-0.5 rounded bg-emerald-500/15 border border-emerald-500/40 text-emerald-300 font-mono text-[10px] font-bold">
                          {meta.roleTitle}
                        </span>
                        <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-cyan-300 font-mono text-[10px] font-bold">
                          {meta.ecosystem}
                        </span>
                      </div>

                      <div className="text-xs font-extrabold text-white">{meta.label}</div>

                      <div className="flex items-center justify-between gap-2 bg-[#0c121e] px-2.5 py-1.5 rounded-lg border border-slate-800/90">
                        <button
                          type="button"
                          onClick={() => onSelectAddress(meta.address)}
                          className="font-mono text-[11px] text-cyan-300 hover:underline truncate cursor-pointer text-left"
                          title={meta.address}
                        >
                          {meta.address}
                        </button>
                        <button
                          type="button"
                          onClick={() => onSelectAddress(meta.address)}
                          className="px-2 py-0.5 rounded bg-cyan-500/15 text-cyan-300 font-mono text-[10px] font-bold hover:bg-cyan-500/25 shrink-0 cursor-pointer"
                        >
                          Inspect
                        </button>
                      </div>

                      {meta.pairedAddress && (
                        <div className="flex items-center justify-between gap-2 bg-violet-950/20 px-2.5 py-1 rounded-lg border border-violet-500/30 text-[10px] font-mono">
                          <span className="text-violet-300 truncate">
                            Paired ({meta.pairedRole}): {meta.pairedAddress}
                          </span>
                          <button
                            type="button"
                            onClick={() => onSelectAddress(meta.pairedAddress!)}
                            className="text-violet-200 underline hover:text-white shrink-0 cursor-pointer"
                          >
                            View Pair
                          </button>
                        </div>
                      )}

                      <div className="space-y-1 text-[11px] leading-relaxed pt-1">
                        <div>
                          <span className="font-mono font-bold text-cyan-400">WHAT IT IS: </span>
                          <span className="text-slate-300">{meta.whatItIs}</span>
                        </div>
                        <div>
                          <span className="font-mono font-bold text-emerald-400">WHY WHITELISTED: </span>
                          <span className="text-slate-300">{meta.whyWhitelisted}</span>
                        </div>
                        <div>
                          <span className="font-mono font-bold text-amber-300">HOW IT WORKS: </span>
                          <span className="text-slate-300">{meta.howItWorks}</span>
                        </div>
                      </div>
                    </div>

                    <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-[10px] font-mono text-slate-400">
                      <span>{meta.institution}</span>
                      <span className="text-emerald-400 font-bold">✓ Pre-Trained in IST KG</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </section>

          {/* =================================================================
              STEP D: INTERACTIVE KNOWLEDGE GRAPH (CORRELATED VS. INDEPENDENT
                      + PERSISTENT IST SOLANA DATABASE KNOWLEDGE GRAPH)
             ================================================================= */}
          <section className="bg-[#0c121e] border border-cyan-500/30 rounded-2xl p-5 sm:p-6 space-y-5">
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 pb-3 border-b border-slate-800">
              <div>
                <span className="text-xs font-mono font-bold text-violet-300">
                  EASE MODE • STEP D — CORRELATED VS. INDEPENDENT KNOWLEDGE GRAPH (IST TIMESTAMPS)
                </span>
                <h2 className="text-lg sm:text-xl font-extrabold text-white mt-0.5">
                  Interactive Entity Correlation Topology & Persistent Solana Knowledge Graph
                </h2>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <div className="inline-flex items-center bg-[#080c14] p-1 rounded-xl border border-slate-800">
                  <button
                    type="button"
                    onClick={() => setGraphViewMode('tx-correlation')}
                    className={`px-3.5 py-1.5 rounded-lg text-xs font-extrabold transition cursor-pointer ${
                      graphViewMode === 'tx-correlation'
                        ? 'bg-cyan-500 text-slate-950'
                        : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    1. Tx Lifecycle & Entity Correlation Graph
                  </button>
                  <button
                    type="button"
                    onClick={() => setGraphViewMode('persistent-ist-db')}
                    className={`px-3.5 py-1.5 rounded-lg text-xs font-extrabold transition cursor-pointer ${
                      graphViewMode === 'persistent-ist-db'
                        ? 'bg-emerald-500 text-slate-950'
                        : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    2. Full Persistent Database Graph ({persistentKg.nodes.length} Nodes • IST)
                  </button>
                </div>

                {/* Zoom Controls */}
                <div className="inline-flex items-center gap-1 bg-[#080c14] p-1 rounded-xl border border-slate-800">
                  <button
                    type="button"
                    onClick={() => setKgZoom((z) => Math.max(0.75, Number((z - 0.15).toFixed(2))))}
                    className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 cursor-pointer"
                    title="Zoom Out"
                  >
                    <ZoomOut className="w-3.5 h-3.5" />
                  </button>
                  <span className="px-2 text-[11px] font-mono text-cyan-300">
                    {Math.round(kgZoom * 100)}%
                  </span>
                  <button
                    type="button"
                    onClick={() => setKgZoom((z) => Math.min(1.5, Number((z + 0.15).toFixed(2))))}
                    className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 cursor-pointer"
                    title="Zoom In"
                  >
                    <ZoomIn className="w-3.5 h-3.5" />
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setKgZoom(1);
                      setSelectedGraphNodeId(null);
                    }}
                    className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 cursor-pointer"
                    title="Reset View"
                  >
                    <RotateCcw className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            </div>

            {graphViewMode === 'tx-correlation' ? (
              <div className="space-y-5">
                {/* Correlation Mode Status Banner */}
                <div
                  className={`p-4 rounded-xl border flex flex-col sm:flex-row sm:items-center justify-between gap-3 ${
                    breakdown.correlationMode === 'CORRELATED_LIFECYCLE'
                      ? 'bg-cyan-950/25 border-cyan-500/40'
                      : 'bg-violet-950/25 border-violet-500/40'
                  }`}
                >
                  <div className="space-y-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span
                        className={`px-2.5 py-0.5 rounded text-[10px] font-mono font-extrabold ${
                          breakdown.correlationMode === 'CORRELATED_LIFECYCLE'
                            ? 'bg-cyan-400 text-slate-950'
                            : 'bg-violet-400 text-slate-950'
                        }`}
                      >
                        {breakdown.correlationMode === 'CORRELATED_LIFECYCLE'
                          ? 'MULTI-STAGE CORRELATED LIFECYCLE ALERT'
                          : 'INDEPENDENT STANDALONE ALERT'}
                      </span>
                      <span className="text-xs font-mono text-slate-300">
                        Trained at {breakdown.trainedAtIST}
                      </span>
                      {breakdown.crossTransactionLinks.length > 0 && (
                        <span className="px-2 py-0.5 rounded bg-emerald-500/20 border border-emerald-500/40 text-emerald-300 text-[10px] font-mono font-bold">
                          Linked to {breakdown.crossTransactionLinks.length} Prior Trained Tx(s)
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-slate-200">
                      {breakdown.correlationMode === 'CORRELATED_LIFECYCLE'
                        ? `This transaction is directly correlated to prior prerequisite state (Mint/Custody Provisioning) and predicts downstream settlement or compliance actions on ${breakdown.tokenInvolvedSymbol}. Click any node in the graph below to inspect its provenance.`
                        : 'This transaction is classified as an Independent Standalone Alert without multi-stage token custody onboarding dependencies.'}
                    </p>
                  </div>
                </div>

                {/* Interactive SVG Knowledge Graph of Correlated Lifecycle + Entity Nodes + Independent Alert Cluster */}
                <div className="bg-[#070a10] border border-slate-800 rounded-2xl p-4 overflow-x-auto">
                  <div
                    className="min-w-[820px] transition-transform origin-top-left"
                    style={{ transform: `scale(${kgZoom})` }}
                  >
                    <svg viewBox="0 0 940 420" className="w-full h-auto select-none">
                      <defs>
                        <marker
                          id="arrow-cyan"
                          viewBox="0 0 10 10"
                          refX="8"
                          refY="5"
                          markerWidth="6"
                          markerHeight="6"
                          orient="auto-start-reverse"
                        >
                          <path d="M 0 1 L 10 5 L 0 9 z" fill="#22d3ee" />
                        </marker>
                        <marker
                          id="arrow-emerald"
                          viewBox="0 0 10 10"
                          refX="8"
                          refY="5"
                          markerWidth="6"
                          markerHeight="6"
                          orient="auto-start-reverse"
                        >
                          <path d="M 0 1 L 10 5 L 0 9 z" fill="#34d399" />
                        </marker>
                        <marker
                          id="arrow-amber"
                          viewBox="0 0 10 10"
                          refX="8"
                          refY="5"
                          markerWidth="6"
                          markerHeight="6"
                          orient="auto-start-reverse"
                        >
                          <path d="M 0 1 L 10 5 L 0 9 z" fill="#fbbf24" />
                        </marker>
                      </defs>

                      <rect x="0" y="0" width="940" height="420" rx="14" fill="#070a10" />

                      {/* Correlated Pipeline Track Header */}
                      <text
                        x="22"
                        y="26"
                        fill="#38bdf8"
                        fontSize="11"
                        fontWeight="bold"
                        fontFamily="monospace"
                      >
                        CORRELATED LIFECYCLE TOPOLOGY (PREVIOUS PREREQUISITE → CURRENT ACTIVE TX → NEXT PREDICTED ALERT)
                      </text>

                      {/* Directed Edges between Lifecycle Stages */}
                      <line
                        x1="230"
                        y1="95"
                        x2="310"
                        y2="95"
                        stroke="#22d3ee"
                        strokeWidth="2.2"
                        markerEnd="url(#arrow-cyan)"
                      />
                      <line
                        x1="610"
                        y1="95"
                        x2="690"
                        y2="95"
                        stroke="#34d399"
                        strokeWidth="2.2"
                        strokeDasharray="5,4"
                        markerEnd="url(#arrow-emerald)"
                      />

                      {/* Directed Edges from Current Tx to Core Involved Solana Entities */}
                      <line
                        x1="380"
                        y1="150"
                        x2="145"
                        y2="210"
                        stroke="#fbbf24"
                        strokeWidth="1.6"
                        markerEnd="url(#arrow-amber)"
                      />
                      <line
                        x1="440"
                        y1="150"
                        x2="365"
                        y2="210"
                        stroke="#22d3ee"
                        strokeWidth="1.6"
                        markerEnd="url(#arrow-cyan)"
                      />
                      <line
                        x1="490"
                        y1="150"
                        x2="585"
                        y2="210"
                        stroke="#34d399"
                        strokeWidth="1.6"
                        markerEnd="url(#arrow-emerald)"
                      />
                      <line
                        x1="540"
                        y1="150"
                        x2="800"
                        y2="210"
                        stroke="#38bdf8"
                        strokeWidth="1.6"
                        markerEnd="url(#arrow-cyan)"
                      />

                      {/* Stage 1: Previous Correlated Alert Box */}
                      <g
                        onClick={() =>
                          setSelectedGraphNodeId(
                            breakdown.correlatedStages[1]?.entities[0] ||
                              breakdown.tokenMintAddress
                          )
                        }
                        className="cursor-pointer"
                      >
                        <rect
                          x="20"
                          y="42"
                          width="210"
                          height="106"
                          rx="12"
                          fill="#0d1524"
                          stroke="#38bdf8"
                          strokeWidth="1.5"
                        />
                        <text
                          x="32"
                          y="62"
                          fill="#38bdf8"
                          fontSize="10"
                          fontWeight="bold"
                          fontFamily="monospace"
                        >
                          1. PREVIOUS PREREQUISITE
                        </text>
                        <text x="32" y="82" fill="#f8fafc" fontSize="11" fontWeight="bold">
                          {(breakdown.correlatedStages[1]?.title || 'Prior State Provisioning').slice(
                            0,
                            27
                          )}
                        </text>
                        <text x="32" y="102" fill="#94a3b8" fontSize="10" fontFamily="monospace">
                          Asset: {breakdown.tokenInvolvedSymbol} ({breakdown.tokenStandard.slice(0, 12)})
                        </text>
                        <text x="32" y="122" fill="#34d399" fontSize="10" fontFamily="monospace">
                          Status: Verified Prerequisite
                        </text>
                      </g>

                      {/* Stage 2: Current Investigated Transaction */}
                      <g
                        onClick={() => setSelectedGraphNodeId(breakdown.feePayerAudit.address)}
                        className="cursor-pointer"
                      >
                        <rect
                          x="315"
                          y="38"
                          width="295"
                          height="112"
                          rx="14"
                          fill="#0f1e33"
                          stroke="#22d3ee"
                          strokeWidth="2.5"
                        />
                        <text
                          x="330"
                          y="58"
                          fill="#22d3ee"
                          fontSize="10"
                          fontWeight="bold"
                          fontFamily="monospace"
                        >
                          2. CURRENT ACTIVE ALERT ({breakdown.primaryAlertKind})
                        </text>
                        <text x="330" y="78" fill="#ffffff" fontSize="12" fontWeight="bold">
                          {breakdown.valueInvolvedHeadline.slice(0, 34)}
                        </text>
                        <text x="330" y="98" fill="#cbd5e1" fontSize="10" fontFamily="monospace">
                          Tx: {breakdown.signature.slice(0, 24)}...
                        </text>
                        <text x="330" y="116" fill="#34d399" fontSize="10" fontFamily="monospace">
                          Whitelisted: {breakdown.whitelistedCount}/
                          {breakdown.addressWhitelistMatrix.length} Entities
                        </text>
                        <text x="330" y="134" fill="#fbbf24" fontSize="10" fontFamily="monospace">
                          IST: {breakdown.blockTimeIST}
                        </text>
                      </g>

                      {/* Stage 3: Next Predicted Alert Box */}
                      <g
                        onClick={() =>
                          setSelectedGraphNodeId(
                            breakdown.clientOnboardingDetails.clientTokenAccountAddress
                          )
                        }
                        className="cursor-pointer"
                      >
                        <rect
                          x="695"
                          y="42"
                          width="225"
                          height="106"
                          rx="12"
                          fill="#0d1922"
                          stroke="#34d399"
                          strokeWidth="1.5"
                          strokeDasharray="5,3"
                        />
                        <text
                          x="708"
                          y="62"
                          fill="#34d399"
                          fontSize="10"
                          fontWeight="bold"
                          fontFamily="monospace"
                        >
                          3. NEXT PREDICTED LIFECYCLE
                        </text>
                        <text x="708" y="82" fill="#f8fafc" fontSize="11" fontWeight="bold">
                          {(
                            breakdown.correlatedStages[4]?.title ||
                            breakdown.correlatedStages[3]?.title ||
                            'Downstream Settlement / Audit'
                          ).slice(0, 28)}
                        </text>
                        <text x="708" y="102" fill="#94a3b8" fontSize="10" fontFamily="monospace">
                          Target: {breakdown.tokenInvolvedSymbol} Custody
                        </text>
                        <text x="708" y="122" fill="#38bdf8" fontSize="10" fontFamily="monospace">
                          Watchlist: Armed & Monitoring
                        </text>
                      </g>

                      {/* Row 2: 4 Interactive Entity Nodes Directly Attached to Current Tx */}
                      {/* Entity Node A: Fee Payer & Signer */}
                      <g
                        onClick={() => setSelectedGraphNodeId(breakdown.feePayerAudit.address)}
                        className="cursor-pointer"
                      >
                        <rect
                          x="20"
                          y="212"
                          width="205"
                          height="74"
                          rx="10"
                          fill={
                            selectedGraphNodeId === breakdown.feePayerAudit.address
                              ? '#172554'
                              : '#0b1320'
                          }
                          stroke="#fbbf24"
                          strokeWidth="1.5"
                        />
                        <text
                          x="32"
                          y="230"
                          fill="#fbbf24"
                          fontSize="9.5"
                          fontWeight="bold"
                          fontFamily="monospace"
                        >
                          FEE PAYER & SIGNER
                        </text>
                        <text x="32" y="248" fill="#ffffff" fontSize="10.5" fontWeight="bold">
                          {breakdown.feePayerAudit.label.slice(0, 26)}
                        </text>
                        <text x="32" y="266" fill="#94a3b8" fontSize="9.5" fontFamily="monospace">
                          {breakdown.feePayerAudit.address.slice(0, 22)}...
                        </text>
                      </g>

                      {/* Entity Node B: Governing Program */}
                      <g
                        onClick={() =>
                          setSelectedGraphNodeId(
                            breakdown.clientOnboardingDetails.governingProgramId
                          )
                        }
                        className="cursor-pointer"
                      >
                        <rect
                          x="250"
                          y="212"
                          width="210"
                          height="74"
                          rx="10"
                          fill={
                            selectedGraphNodeId ===
                            breakdown.clientOnboardingDetails.governingProgramId
                              ? '#172554'
                              : '#0b1320'
                          }
                          stroke="#22d3ee"
                          strokeWidth="1.5"
                        />
                        <text
                          x="262"
                          y="230"
                          fill="#22d3ee"
                          fontSize="9.5"
                          fontWeight="bold"
                          fontFamily="monospace"
                        >
                          GOVERNING PROGRAM
                        </text>
                        <text x="262" y="248" fill="#ffffff" fontSize="10.5" fontWeight="bold">
                          {breakdown.clientOnboardingDetails.governingProgramName.slice(0, 27)}
                        </text>
                        <text x="262" y="266" fill="#94a3b8" fontSize="9.5" fontFamily="monospace">
                          {breakdown.clientOnboardingDetails.governingProgramId.slice(0, 22)}...
                        </text>
                      </g>

                      {/* Entity Node C: Token Mint */}
                      <g
                        onClick={() => setSelectedGraphNodeId(breakdown.tokenMintAddress)}
                        className="cursor-pointer"
                      >
                        <rect
                          x="485"
                          y="212"
                          width="205"
                          height="74"
                          rx="10"
                          fill={
                            selectedGraphNodeId === breakdown.tokenMintAddress
                              ? '#172554'
                              : '#0b1320'
                          }
                          stroke="#34d399"
                          strokeWidth="1.5"
                        />
                        <text
                          x="497"
                          y="230"
                          fill="#34d399"
                          fontSize="9.5"
                          fontWeight="bold"
                          fontFamily="monospace"
                        >
                          TOKEN MINT ({breakdown.tokenInvolvedSymbol})
                        </text>
                        <text x="497" y="248" fill="#ffffff" fontSize="10.5" fontWeight="bold">
                          {breakdown.tokenInvolvedName.slice(0, 26)}
                        </text>
                        <text x="497" y="266" fill="#94a3b8" fontSize="9.5" fontFamily="monospace">
                          {breakdown.tokenMintAddress.slice(0, 22)}...
                        </text>
                      </g>

                      {/* Entity Node D: Client Custody Vault */}
                      <g
                        onClick={() =>
                          setSelectedGraphNodeId(
                            breakdown.clientOnboardingDetails.clientTokenAccountAddress
                          )
                        }
                        className="cursor-pointer"
                      >
                        <rect
                          x="715"
                          y="212"
                          width="205"
                          height="74"
                          rx="10"
                          fill={
                            selectedGraphNodeId ===
                            breakdown.clientOnboardingDetails.clientTokenAccountAddress
                              ? '#172554'
                              : '#0b1320'
                          }
                          stroke="#38bdf8"
                          strokeWidth="1.5"
                        />
                        <text
                          x="727"
                          y="230"
                          fill="#38bdf8"
                          fontSize="9.5"
                          fontWeight="bold"
                          fontFamily="monospace"
                        >
                          CLIENT CUSTODY VAULT
                        </text>
                        <text x="727" y="248" fill="#ffffff" fontSize="10.5" fontWeight="bold">
                          {breakdown.isClientOnboarded
                            ? `Onboarded (${breakdown.clientOnboardingDetails.resultingBalanceAfter})`
                            : 'Target State Account'}
                        </text>
                        <text x="727" y="266" fill="#94a3b8" fontSize="9.5" fontFamily="monospace">
                          {breakdown.clientOnboardingDetails.clientTokenAccountAddress.slice(
                            0,
                            22
                          )}
                          ...
                        </text>
                      </g>

                      {/* Row 3: Independent Standalone Alerts Cluster */}
                      <line
                        x1="20"
                        y1="308"
                        x2="920"
                        y2="308"
                        stroke="#1e293b"
                        strokeWidth="1"
                      />
                      <text
                        x="22"
                        y="328"
                        fill="#c084fc"
                        fontSize="11"
                        fontWeight="bold"
                        fontFamily="monospace"
                      >
                        INDEPENDENT STANDALONE ALERTS CLUSTER (ISOLATED FROM LIFECYCLE CHAIN • ZERO CROSS-STAGE DEPENDENCY)
                      </text>

                      {breakdown.independentAlerts.slice(0, 2).map((ind, idx) => {
                        const xPos = 20 + idx * 455;
                        return (
                          <g key={ind.id}>
                            <rect
                              x={xPos}
                              y="340"
                              width="440"
                              height="66"
                              rx="10"
                              fill="#130f24"
                              stroke="#a855f7"
                              strokeWidth="1.2"
                            />
                            <text
                              x={xPos + 14}
                              y="360"
                              fill="#e9d5ff"
                              fontSize="11"
                              fontWeight="bold"
                            >
                              [INDEPENDENT] {ind.title.slice(0, 52)}
                            </text>
                            <text
                              x={xPos + 14}
                              y="378"
                              fill="#cbd5e1"
                              fontSize="10"
                              fontFamily="monospace"
                            >
                              {ind.observation.slice(0, 62)}
                            </text>
                            <text
                              x={xPos + 14}
                              y="394"
                              fill="#a855f7"
                              fontSize="9.5"
                              fontFamily="monospace"
                            >
                              Why Isolated: {ind.whyIndependent.slice(0, 60)}
                            </text>
                          </g>
                        );
                      })}
                    </svg>
                  </div>
                </div>

                {/* Selected Graph Node Inspector Panel */}
                {selectedNodeRecord && (
                  <div className="p-4 rounded-xl bg-[#080c14] border border-cyan-500/40 space-y-3">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div>
                        <span className="text-[10px] font-mono uppercase text-cyan-400 font-bold">
                          SELECTED KNOWLEDGE GRAPH ENTITY INSPECTOR
                        </span>
                        <h4 className="text-sm font-extrabold text-white">
                          {selectedNodeRecord.kgNode?.label ||
                            selectedNodeRecord.txRow?.label ||
                            'Solana Blockchain Entity'}
                        </h4>
                        <div className="text-xs font-mono text-cyan-300">
                          {selectedNodeRecord.address}
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <button
                          type="button"
                          onClick={() => onSelectAddress(selectedNodeRecord.address)}
                          className="px-3 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-extrabold text-xs cursor-pointer"
                        >
                          Open Live RPC Provenance Drawer
                        </button>
                        <button
                          type="button"
                          onClick={() => setSelectedGraphNodeId(null)}
                          className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs cursor-pointer"
                        >
                          Close
                        </button>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-4 gap-2.5 text-xs font-mono">
                      <div className="p-2.5 rounded-lg bg-[#0c121e] border border-slate-800">
                        <div className="text-[10px] text-slate-400">WHITELIST STATUS</div>
                        <div className="font-bold text-emerald-300 mt-0.5">
                          {selectedNodeRecord.kgNode?.whitelistTier ||
                            selectedNodeRecord.txRow?.whitelistStatus ||
                            'VERIFIED'}
                        </div>
                      </div>
                      <div className="p-2.5 rounded-lg bg-[#0c121e] border border-slate-800">
                        <div className="text-[10px] text-slate-400">INSTITUTION / PROTOCOL</div>
                        <div className="font-bold text-white mt-0.5 truncate">
                          {selectedNodeRecord.kgNode?.institution ||
                            selectedNodeRecord.txRow?.institutionOrProtocol ||
                            'Solana Mainnet'}
                        </div>
                      </div>
                      <div className="p-2.5 rounded-lg bg-[#0c121e] border border-slate-800">
                        <div className="text-[10px] text-slate-400">FIRST TRAINED (IST)</div>
                        <div className="font-bold text-cyan-300 mt-0.5">
                          {selectedNodeRecord.kgNode?.firstTrainedIST || breakdown.trainedAtIST}
                        </div>
                      </div>
                      <div className="p-2.5 rounded-lg bg-[#0c121e] border border-slate-800">
                        <div className="text-[10px] text-slate-400">OBSERVATIONS & EDGES</div>
                        <div className="font-bold text-amber-300 mt-0.5">
                          {selectedNodeRecord.kgNode?.observationCount || 1} Obs •{' '}
                          {selectedNodeRecord.connectedEdges.length} Edges
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {/* Detailed Correlated Stages vs. Independent Alerts Cards */}
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                  <div className="lg:col-span-2 space-y-2.5">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-cyan-300 flex items-center gap-1.5">
                      <GitBranch className="w-3.5 h-3.5" />
                      Correlated Lifecycle Stages ({breakdown.correlatedStages.length} Stages)
                    </h3>
                    <div className="space-y-2">
                      {breakdown.correlatedStages.map((stage) => (
                        <div
                          key={stage.stageNumber}
                          className={`p-3.5 rounded-xl border ${
                            stage.status === 'active-current'
                              ? 'bg-cyan-950/30 border-cyan-400'
                              : stage.status === 'completed-prior'
                              ? 'bg-[#080c14] border-slate-800'
                              : 'bg-emerald-950/15 border-emerald-500/30'
                          }`}
                        >
                          <div className="flex items-center justify-between gap-2">
                            <span className="text-[10px] font-mono font-bold text-cyan-400">
                              STAGE 0{stage.stageNumber} • {stage.phaseLabel}
                            </span>
                            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900 text-slate-300">
                              {stage.status.toUpperCase()}
                            </span>
                          </div>
                          <div className="text-xs font-bold text-white mt-1">{stage.title}</div>
                          <p className="text-[11px] text-slate-300 mt-1 leading-relaxed">
                            {stage.description}
                          </p>
                          <div className="text-[10px] font-mono text-emerald-300 mt-1.5">
                            Proof: {stage.evidenceNote}
                          </div>
                          {stage.entities.length > 0 && (
                            <div className="flex flex-wrap gap-1.5 mt-2">
                              {stage.entities.map((ent) => (
                                <button
                                  key={ent}
                                  type="button"
                                  onClick={() => onSelectAddress(ent)}
                                  className="px-2 py-0.5 rounded bg-slate-900 hover:bg-slate-800 border border-slate-700 font-mono text-[10px] text-cyan-300 cursor-pointer"
                                >
                                  {ent.slice(0, 14)}...
                                </button>
                              ))}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="space-y-3">
                    <div className="space-y-2.5">
                      <h3 className="text-xs font-bold uppercase tracking-wider text-violet-300">
                        Independent Standalone Alerts ({breakdown.independentAlerts.length})
                      </h3>
                      <div className="space-y-2">
                        {breakdown.independentAlerts.map((ind) => (
                          <div
                            key={ind.id}
                            className="p-3.5 rounded-xl bg-violet-950/20 border border-violet-500/30 space-y-1.5"
                          >
                            <div className="flex items-center justify-between">
                              <span className="text-[10px] font-mono font-bold text-violet-300">
                                {ind.category}
                              </span>
                              <span className="px-2 py-0.5 rounded bg-violet-500/20 text-violet-200 text-[9px] font-mono font-bold">
                                INDEPENDENT
                              </span>
                            </div>
                            <div className="text-xs font-bold text-white">{ind.title}</div>
                            <p className="text-[11px] text-slate-300 leading-relaxed">
                              {ind.observation}
                            </p>
                            <div className="text-[10px] font-mono text-violet-300 pt-1 border-t border-violet-500/20">
                              Isolation Proof: {ind.whyIndependent}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Cross-Transaction Entity Links from Persistent KG */}
                    {breakdown.crossTransactionLinks.length > 0 && (
                      <div className="space-y-2">
                        <h3 className="text-xs font-bold uppercase tracking-wider text-emerald-400">
                          Cross-Transaction Entity Correlations ({breakdown.crossTransactionLinks.length})
                        </h3>
                        <div className="space-y-2">
                          {breakdown.crossTransactionLinks.slice(0, 4).map((link) => (
                            <div
                              key={link.signature}
                              className="p-3 rounded-xl bg-[#080c14] border border-emerald-500/30 space-y-1"
                            >
                              <div className="flex items-center justify-between text-[10px] font-mono">
                                <span className="text-emerald-400 font-bold">
                                  {link.alertCategory}
                                </span>
                                <span className="text-amber-300">{link.trainedAtIST}</span>
                              </div>
                              <div className="text-xs font-bold text-white">{link.valueInvolved}</div>
                              <div className="text-[10px] font-mono text-slate-400">
                                Shared Entity: {link.sharedEntityLabel}
                              </div>
                              <button
                                type="button"
                                onClick={() => handleSampleClick(link.signature)}
                                className="text-[11px] font-mono text-cyan-300 hover:underline cursor-pointer"
                              >
                                Pivot to Tx: {link.signature.slice(0, 20)}... →
                              </button>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            ) : (
              /* ===============================================================
                 PERSISTENT SOLANA KNOWLEDGE GRAPH DATABASE VIEW (IST TIMESTAMPS)
                 =============================================================== */
              <div className="space-y-5">
                <div className="p-4 rounded-xl bg-[#080c14] border border-emerald-500/30 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div className="space-y-0.5">
                    <div className="text-xs font-mono font-bold text-emerald-400 flex items-center gap-1.5">
                      <Database className="w-4 h-4" />
                      PERSISTENT SOLANA KNOWLEDGE GRAPH (TRAINED ACROSS ALL USER INVESTIGATIONS)
                    </div>
                    <p className="text-xs text-slate-300">
                      Every Solana transaction, account, token mint, and flow of funds you inspect
                      is trained into this persistent graph with Indian Standard Time (
                      <code className="text-cyan-300">Asia/Kolkata</code>) timestamps.
                    </p>
                  </div>
                  <div className="text-right font-mono text-xs shrink-0">
                    <div className="text-amber-300 font-bold">
                      Last Trained: {persistentKg.lastTrainedIST}
                    </div>
                    <div className="text-slate-400 text-[11px]">
                      {persistentKg.nodes.length} Nodes • {persistentKg.edges.length} Edges •{' '}
                      {persistentKg.transactions.length} Txs
                    </div>
                  </div>
                </div>

                {/* Filter & Search Bar for Persistent Graph */}
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex flex-wrap items-center gap-1.5">
                    <Filter className="w-3.5 h-3.5 text-cyan-400 mr-1" />
                    {(
                      [
                        ['ALL', 'All Nodes'],
                        ['WHITELISTED', 'Whitelisted'],
                        ['NON_WHITELISTED', 'Non-Whitelisted'],
                        ['PROGRAMS', 'Programs'],
                        ['MINTS', 'Token Mints'],
                        ['WALLETS', 'Wallets & Custody'],
                      ] as const
                    ).map(([key, label]) => (
                      <button
                        key={key}
                        type="button"
                        onClick={() => setKgCategoryFilter(key)}
                        className={`px-2.5 py-1 rounded-lg text-[11px] font-mono font-bold transition cursor-pointer ${
                          kgCategoryFilter === key
                            ? 'bg-emerald-500 text-slate-950'
                            : 'bg-[#080c14] border border-slate-800 text-slate-400 hover:text-white'
                        }`}
                      >
                        {label}
                      </button>
                    ))}
                  </div>
                  <input
                    type="text"
                    value={kgSearchQuery}
                    onChange={(e) => setKgSearchQuery(e.target.value)}
                    placeholder="Search trained node, mint, or institution..."
                    className="bg-[#080c14] border border-slate-800 rounded-lg px-3 py-1 text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-emerald-400 w-64"
                  />
                </div>

                {/* Interactive SVG Network Map of Persistent Trained Nodes & Edges */}
                <div className="bg-[#070a10] border border-slate-800 rounded-2xl p-4 overflow-x-auto">
                  <div
                    className="min-w-[820px] transition-transform origin-top-left"
                    style={{ transform: `scale(${kgZoom})` }}
                  >
                    <svg viewBox="0 0 920 390" className="w-full h-auto select-none">
                      <rect x="0" y="0" width="920" height="390" rx="14" fill="#070a10" />
                      <text
                        x="20"
                        y="24"
                        fill="#34d399"
                        fontSize="11"
                        fontWeight="bold"
                        fontFamily="monospace"
                      >
                        PERSISTENT DATABASE TOPOLOGY ({persistentGraphLayout.positions.length} VISIBLE NODES • CLICK ANY NODE TO INSPECT)
                      </text>

                      {/* Render Directed Edges */}
                      {persistentGraphLayout.visibleEdges.map((edge) => {
                        const src = persistentGraphLayout.posMap.get(edge.source);
                        const dst = persistentGraphLayout.posMap.get(edge.target);
                        if (!src || !dst) return null;
                        return (
                          <g key={edge.edgeId}>
                            <line
                              x1={src.x}
                              y1={src.y}
                              x2={dst.x}
                              y2={dst.y}
                              stroke={
                                edge.correlationMode === 'CORRELATED_LIFECYCLE'
                                  ? '#22d3ee'
                                  : '#a855f7'
                              }
                              strokeWidth="1.5"
                              strokeOpacity="0.65"
                            />
                          </g>
                        );
                      })}

                      {/* Render Trained Nodes */}
                      {persistentGraphLayout.positions.map(({ x, y, node }) => {
                        const isSelected = selectedGraphNodeId === node.address;
                        const strokeColor = node.isWhitelisted ? '#34d399' : '#f43f5e';
                        return (
                          <g
                            key={node.address}
                            onClick={() => setSelectedGraphNodeId(node.address)}
                            className="cursor-pointer"
                          >
                            <circle
                              cx={x}
                              cy={y}
                              r={isSelected ? 22 : 17}
                              fill={isSelected ? '#0f172a' : '#0b1322'}
                              stroke={strokeColor}
                              strokeWidth={isSelected ? '3' : '2'}
                            />
                            <text
                              x={x}
                              y={y + 4}
                              textAnchor="middle"
                              fill="#ffffff"
                              fontSize="9"
                              fontWeight="bold"
                              fontFamily="monospace"
                            >
                              {node.ecosystem.slice(0, 5)}
                            </text>
                            <text
                              x={x}
                              y={y + 31}
                              textAnchor="middle"
                              fill="#cbd5e1"
                              fontSize="9.5"
                              fontWeight="bold"
                            >
                              {node.label.slice(0, 18)}
                            </text>
                          </g>
                        );
                      })}
                    </svg>
                  </div>
                </div>

                {/* Selected Node Inspector in Persistent Mode */}
                {selectedNodeRecord && (
                  <div className="p-4 rounded-xl bg-[#080c14] border border-emerald-500/40 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <div className="space-y-1">
                      <div className="text-[10px] font-mono text-emerald-400 font-bold">
                        SELECTED PERSISTENT GRAPH NODE (IST)
                      </div>
                      <div className="text-sm font-extrabold text-white">
                        {selectedNodeRecord.kgNode?.label || selectedNodeRecord.address}
                      </div>
                      <div className="text-xs font-mono text-cyan-300">
                        {selectedNodeRecord.address}
                      </div>
                      <div className="text-[11px] font-mono text-slate-400">
                        First Trained: {selectedNodeRecord.kgNode?.firstTrainedIST} • Last Trained:{' '}
                        {selectedNodeRecord.kgNode?.lastTrainedIST} • Observations:{' '}
                        {selectedNodeRecord.kgNode?.observationCount || 1}
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={() => onSelectAddress(selectedNodeRecord.address)}
                        className="px-3.5 py-2 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-extrabold text-xs cursor-pointer"
                      >
                        Inspect Live RPC Account
                      </button>
                      {selectedNodeRecord.kgNode?.lastSignature &&
                        selectedNodeRecord.kgNode.lastSignature.length > 30 && (
                          <button
                            type="button"
                            onClick={() =>
                              handleSampleClick(selectedNodeRecord.kgNode!.lastSignature)
                            }
                            className="px-3.5 py-2 rounded-xl bg-cyan-500/15 hover:bg-cyan-500/25 border border-cyan-500/40 text-cyan-300 font-bold text-xs cursor-pointer"
                          >
                            Load Last Tx
                          </button>
                        )}
                    </div>
                  </div>
                )}

                {/* Trained Nodes & Directed Edges Tables */}
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-cyan-300">
                      Trained Solana Entities ({filteredPersistentNodes.length} Nodes • IST)
                    </h3>
                    <div className="max-h-80 overflow-y-auto space-y-2 pr-1">
                      {filteredPersistentNodes.map((n) => (
                        <div
                          key={n.nodeId}
                          className="p-3 rounded-xl bg-[#080c14] border border-slate-800 flex items-start justify-between gap-2"
                        >
                          <div className="min-w-0 space-y-0.5">
                            <div className="text-xs font-bold text-white truncate">{n.label}</div>
                            <button
                              type="button"
                              onClick={() => onSelectAddress(n.address)}
                              className="text-[11px] font-mono text-cyan-300 hover:underline truncate block max-w-full cursor-pointer"
                            >
                              {n.address}
                            </button>
                            <div className="text-[10px] font-mono text-slate-400">
                              Trained (IST): <span className="text-amber-300">{n.lastTrainedIST}</span> •
                              Obs: {n.observationCount}x
                            </div>
                          </div>
                          <div className="shrink-0 text-right space-y-1">
                            {renderWhitelistBadge(n.whitelistTier)}
                            <div className="text-[10px] font-mono text-slate-400">{n.ecosystem}</div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="space-y-2">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-emerald-300">
                      Trained Directed Relationships & Flows ({persistentKg.edges.length} Edges • IST)
                    </h3>
                    <div className="max-h-80 overflow-y-auto space-y-2 pr-1">
                      {persistentKg.edges.map((e) => (
                        <div
                          key={e.edgeId}
                          className="p-3 rounded-xl bg-[#080c14] border border-slate-800 space-y-1"
                        >
                          <div className="flex items-center justify-between text-[10px] font-mono">
                            <span className="text-cyan-400 font-bold">{e.relationshipType}</span>
                            <span className="text-amber-300">{e.trainedAtIST}</span>
                          </div>
                          <div className="text-xs font-bold text-white">
                            {e.sourceLabel} → {e.targetLabel}
                          </div>
                          <div className="flex items-center justify-between text-[11px] font-mono text-emerald-300">
                            <span>
                              {e.amount} ({e.asset})
                            </span>
                            <span className="text-slate-400">{e.correlationMode}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </section>
        </>
      )}
    </div>
  );
};
