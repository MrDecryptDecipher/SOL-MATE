/**
 * SOL-MATE — Search & Forensic Launch Command Center
 * Base58 signature validator, live progress telemetry, real mainnet test signatures,
 * and capability showcase.
 */

import React, { useState } from 'react';
import {
  Search,
  ArrowRight,
  ShieldAlert,
  AlertTriangle,
  Loader2,
  CheckCircle2,
  Cpu,
  Fingerprint,
  Share2,
  Lock,
  Zap,
} from 'lucide-react';
import { isValidBase58Signature } from '../services/transactionParser';
import { InvestigationProgress } from '../services/forensicsEngine';
import { SolanaCluster } from '../types/solana';

// Real verified Solana Mainnet transaction signatures for fast 1-click evaluation
export const REAL_MAINNET_SAMPLES = [
  {
    label: 'J.P. Morgan FACT Protocol — JLTXX Issuance',
    description: 'Whitelisted Institutional Facet Program (9rdASs...), JLTXX Token-2022 Mint & Anchor emit_cpi! Audit Trail',
    signature: '4EcCC6GnXhkd2nCPaZES2EvNWZGCieXkTgWoZAair1UsXEZdpM9pPZSAwFSHoaonfUA876xo7qXkBWjEysRQziwo',
  },
  {
    label: 'Token-2022 Account Init & Transfer',
    description: 'Extension types, immutable owner, SPL Token-2022 CPI stack and compute units',
    signature: '295U7zEAvRB47PkWD6XvenWRwBa8q5H9THoCALqJj11zwAzo5XkTBt57ghkttggEAZFppKHACUcSTKqzkNLTAECF',
  },
  {
    label: 'Deep Institutional Correlation & Whitelist Audit',
    description: 'Full 19-address J.P. Morgan MONY & JLTXX topology + Cross-Chain EVM SCA/EOA correlation',
    signature: '4EcCC6GnXhkd2nCPaZES2EvNWZGCieXkTgWoZAair1UsXEZdpM9pPZSAwFSHoaonfUA876xo7qXkBWjEysRQziwo',
  },
];

interface SearchHeroProps {
  onInvestigate: (signature: string) => void;
  isLoading: boolean;
  progress: InvestigationProgress | null;
  error: string | null;
  currentCluster: SolanaCluster;
}

export const SearchHero: React.FC<SearchHeroProps> = ({
  onInvestigate,
  isLoading,
  progress,
  error,
  currentCluster,
}) => {
  const [signatureInput, setSignatureInput] = useState('');
  const [validationError, setValidationError] = useState<string | null>(null);

  const handleInputChange = (val: string) => {
    setSignatureInput(val);
    if (validationError) setValidationError(null);
  };

  const handleFormSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = signatureInput.trim();
    if (!trimmed) {
      setValidationError('Please enter a Solana transaction signature.');
      return;
    }
    if (!isValidBase58Signature(trimmed)) {
      setValidationError(
        'Invalid Solana signature format. Signatures must be Base58-encoded strings (80–90 chars) with no 0, O, I, or l.'
      );
      return;
    }
    setValidationError(null);
    onInvestigate(trimmed);
  };

  const handleSelectSample = (sig: string) => {
    setSignatureInput(sig);
    setValidationError(null);
    onInvestigate(sig);
  };

  return (
    <div className="max-w-5xl mx-auto px-4 py-8 sm:py-12">
      {/* Brand Hero Heading */}
      <div className="text-center space-y-3 mb-8">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-xs font-semibold">
          <ShieldAlert className="w-3.5 h-3.5" />
          <span>Solana Transaction Intelligence & Institutional On-Chain Forensics</span>
        </div>
        <h1 className="text-3xl sm:text-5xl font-extrabold tracking-tight text-white">
          SOL<span className="text-cyan-400">-MATE</span>
        </h1>
        <p className="text-base sm:text-lg text-slate-400 max-w-2xl mx-auto font-medium">
          Every Transaction. Every Account. Every Connection.
        </p>
        <p className="text-xs text-slate-500">
          Strictly live blockchain RPC data • J.P. Morgan FACT (MONY & JLTXX) Whitelist Intelligence • Exact BigInt arithmetic
        </p>
      </div>

      {/* Main Search Input Card */}
      <div className="bg-[#0f1520] border border-cyan-500/30 rounded-2xl p-5 sm:p-7 shadow-2xl shadow-cyan-950/40 relative overflow-hidden">
        <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-cyan-500 via-blue-500 to-violet-500"></div>

        <form onSubmit={handleFormSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">
              Transaction Signature (Base58)
            </label>
            <div className="relative">
              <input
                type="text"
                value={signatureInput}
                onChange={(e) => handleInputChange(e.target.value)}
                placeholder="Enter 88-character Solana transaction signature..."
                disabled={isLoading}
                className="w-full bg-[#080b11] border border-slate-700 focus:border-cyan-400 focus:ring-2 focus:ring-cyan-500/30 rounded-xl px-4 py-3.5 text-sm sm:text-base font-mono text-slate-100 placeholder-slate-600 transition disabled:opacity-60"
              />
              <div className="absolute right-3 top-3.5 flex items-center gap-2">
                {signatureInput && (
                  <button
                    type="button"
                    onClick={() => setSignatureInput('')}
                    className="text-xs text-slate-500 hover:text-slate-300 px-2 py-1 rounded"
                  >
                    Clear
                  </button>
                )}
              </div>
            </div>
            {validationError && (
              <p className="text-xs text-rose-400 mt-2 flex items-center gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                <span>{validationError}</span>
              </p>
            )}
          </div>

          <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 pt-2">
            <div className="text-[11px] text-slate-500 flex flex-wrap items-center gap-2">
              <span>Cluster: <strong className="text-slate-300 capitalize">{currentCluster}</strong></span>
              <span>•</span>
              <span>Parallel Pool: <strong className="text-cyan-400">Helius + PublicNode + VibeStation + Ankr + OnFinality (6x Parallel RPC/WSS)</strong></span>
            </div>

            <button
              type="submit"
              disabled={isLoading || !signatureInput.trim()}
              className="px-6 py-3 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-sm rounded-xl flex items-center justify-center gap-2 shadow-lg shadow-cyan-500/25 transition disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
            >
              {isLoading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Investigating...</span>
                </>
              ) : (
                <>
                  <Search className="w-4 h-4" />
                  <span>Investigate Transaction</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </div>
        </form>

        {/* Loading Progress Bar */}
        {isLoading && progress && (
          <div className="mt-6 pt-5 border-t border-slate-800 space-y-2">
            <div className="flex items-center justify-between text-xs font-semibold">
              <span className="text-cyan-400 flex items-center gap-2">
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                {progress.message}
              </span>
              <span className="font-mono text-slate-400">{progress.percent}%</span>
            </div>
            <div className="w-full h-2 bg-slate-900 rounded-full overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 transition-all duration-300 ease-out"
                style={{ width: `${progress.percent}%` }}
              ></div>
            </div>
          </div>
        )}

        {/* Error Banner */}
        {error && !isLoading && (
          <div className="mt-5 p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs space-y-2">
            <div className="flex items-center gap-2 font-bold text-rose-200">
              <AlertTriangle className="w-4 h-4 text-rose-400" />
              <span>Investigation Halted</span>
            </div>
            <p className="text-slate-300 font-mono text-[11px] leading-relaxed">{error}</p>
            <div className="text-[11px] text-slate-400 pt-1 border-t border-rose-500/20 flex flex-wrap items-center justify-between gap-2">
              <span>Tip: Ensure the signature exists on Solana {currentCluster} and has finalized.</span>
              {error.includes('429') && (
                <button
                  type="button"
                  onClick={() => {
                    const cfg = {
                      network: 'mainnet' as const,
                      httpEndpoint: 'https://solana-rpc.publicnode.com',
                      wsEndpoint: 'wss://solana-rpc.publicnode.com',
                      commitment: 'finalized' as const,
                      maxRequestsPerSecond: 5,
                      safetyMarginRequestsPerSecond: 4,
                      requestTimeoutMs: 15000,
                      maxRetries: 3,
                      cacheTtlMs: 300000,
                      maxHistoryLimit: 25,
                      maxGraphNodes: 60,
                    };
                    localStorage.setItem('solmate_config_v1', JSON.stringify(cfg));
                    window.location.reload();
                  }}
                  className="px-3 py-1 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold rounded-lg text-[11px] transition cursor-pointer"
                >
                  Switch to PublicNode RPC (High Capacity)
                </button>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Verified Mainnet Real Transaction Samples */}
      <div className="mt-8 space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-xs font-bold uppercase tracking-wider text-slate-400">
            Quick Forensic Samples (Real Mainnet Transactions)
          </span>
          <span className="text-[11px] text-cyan-400">Click to run instant live investigation</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {REAL_MAINNET_SAMPLES.map((sample, idx) => (
            <button
              key={idx}
              onClick={() => handleSelectSample(sample.signature)}
              disabled={isLoading}
              className="text-left p-3.5 rounded-xl bg-[#0c111a] hover:bg-[#131b26] border border-slate-800 hover:border-cyan-500/40 transition group cursor-pointer"
            >
              <div className="flex items-center justify-between text-xs font-bold text-slate-200 group-hover:text-cyan-300">
                <span>{sample.label}</span>
                <ArrowRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-cyan-400 transition transform group-hover:translate-x-0.5" />
              </div>
              <p className="text-[11px] text-slate-400 mt-1 line-clamp-2">{sample.description}</p>
              <div className="mt-2 text-[10px] font-mono text-slate-500 truncate">
                {sample.signature.slice(0, 16)}...{sample.signature.slice(-8)}
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Forensic Pillars & Non-Negotiable Rules */}
      <div className="mt-12 grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="p-3.5 rounded-xl bg-[#0a0e16] border border-slate-800/80 space-y-1.5">
          <Fingerprint className="w-5 h-5 text-cyan-400" />
          <h4 className="text-xs font-bold text-slate-200">Address Provenance</h4>
          <p className="text-[11px] text-slate-400 leading-relaxed">
            Distinguishes program owner, internal token owner, wallet signer, and PDA with strict verifiable evidence.
          </p>
        </div>

        <div className="p-3.5 rounded-xl bg-[#0a0e16] border border-slate-800/80 space-y-1.5">
          <Cpu className="w-5 h-5 text-violet-400" />
          <h4 className="text-xs font-bold text-slate-200">Nested CPI Execution</h4>
          <p className="text-[11px] text-slate-400 leading-relaxed">
            Complete instruction tree with Cross-Program Invocations, stack depth, and exact compute units consumed.
          </p>
        </div>

        <div className="p-3.5 rounded-xl bg-[#0a0e16] border border-slate-800/80 space-y-1.5">
          <Share2 className="w-5 h-5 text-blue-400" />
          <h4 className="text-xs font-bold text-slate-200">Asset Flow Reconciliation</h4>
          <p className="text-[11px] text-slate-400 leading-relaxed">
            Exact BigInt integer arithmetic for lamports and SPL tokens. Matches pre/post balance deltas without float inaccuracies.
          </p>
        </div>

        <div className="p-3.5 rounded-xl bg-[#0a0e16] border border-slate-800/80 space-y-1.5">
          <Lock className="w-5 h-5 text-emerald-400" />
          <h4 className="text-xs font-bold text-slate-200">Zero-Mock Standard</h4>
          <p className="text-[11px] text-slate-400 leading-relaxed">
            Every displayed finding comes directly from real RPC queries or verifiable calculations. Read-only forensics.
          </p>
        </div>
      </div>
    </div>
  );
};
