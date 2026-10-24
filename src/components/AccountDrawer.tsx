/**
 * SOL-MATE — Account Forensic Intelligence Drawer
 * Slide-over deep inspection for any Solana address.
 * Displays full untruncated addresses, verifiable on-chain state, pre/post SOL & token deltas,
 * role proofs, owner program vs token owner distinction, explorer links, and bounded historical transactions.
 */

import React, { useState, useEffect } from 'react';
import {
  X,
  Copy,
  Check,
  ExternalLink,
  Shield,
  Coins,
  Cpu,
  History,
  AlertCircle,
  CheckCircle2,
  Key,
} from 'lucide-react';
import { AccountRecord } from '../types/forensics';
import { forensicsEngine } from '../services/forensicsEngine';
import { SolanaCluster } from '../types/solana';

interface AccountDrawerProps {
  account: AccountRecord | null;
  onClose: () => void;
  cluster: SolanaCluster;
  onSelectTx?: (sig: string) => void;
}

export const AccountDrawer: React.FC<AccountDrawerProps> = ({
  account,
  onClose,
  cluster,
  onSelectTx,
}) => {
  const [copied, setCopied] = useState(false);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyItems, setHistoryItems] = useState<any[]>([]);
  const [historyError, setHistoryError] = useState<string | null>(null);

  useEffect(() => {
    setHistoryItems([]);
    setHistoryError(null);
  }, [account?.address]);

  if (!account) return null;

  const safeAddr = account.address || 'Unknown';
  const safeOwnerProg = account.ownerProgram || '11111111111111111111111111111111';
  const safeRoles = Array.isArray(account.roles) ? account.roles : [];
  const safeProofs = Array.isArray(account.roleProofs) ? account.roleProofs : [];
  const safeLamports = account.lamports !== undefined ? BigInt(account.lamports) : 0n;
  const safeSol = typeof account.solBalance === 'number' ? account.solBalance : Number(safeLamports) / 1e9;

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const clusterParam = cluster === 'mainnet' ? '' : `?cluster=${cluster}`;
  const solscanUrl = `https://solscan.io/account/${safeAddr}${clusterParam}`;
  const explorerUrl = `https://explorer.solana.com/address/${safeAddr}${clusterParam}`;

  const fetchHistory = async () => {
    setHistoryLoading(true);
    setHistoryError(null);
    try {
      const items = await forensicsEngine.getAddressHistory(safeAddr, 10);
      setHistoryItems(Array.isArray(items) ? items : []);
    } catch (err: any) {
      setHistoryError(err?.message || 'Unable to retrieve address history from current RPC');
    } finally {
      setHistoryLoading(false);
    }
  };

  return (
    <div className="fixed inset-y-0 right-0 z-50 w-full sm:w-[520px] lg:w-[600px] bg-[#0c1017] border-l border-slate-800 shadow-2xl flex flex-col justify-between overflow-hidden animate-in slide-in-from-right duration-200">
      {/* Drawer Header */}
      <div className="p-4 sm:p-5 border-b border-slate-800/80 bg-[#090b10] flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Shield className="w-5 h-5 text-cyan-400" />
          <div>
            <h3 className="font-extrabold text-base text-white tracking-wide">
              Deep Address Intelligence Inspector
            </h3>
            <p className="text-[11px] text-slate-400">
              Full Untruncated Cryptographic Identity, Custody State & Role Provenance
            </p>
          </div>
        </div>
        <button
          onClick={onClose}
          className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition cursor-pointer"
          aria-label="Close Drawer"
        >
          <X className="w-5 h-5" />
        </button>
      </div>

      {/* Drawer Content */}
      <div className="p-4 sm:p-5 overflow-y-auto space-y-6 flex-1">
        {/* Basic Identity & Explorer Links */}
        <div className="bg-[#111722] border border-slate-700/60 rounded-xl p-4 space-y-3">
          <div className="flex items-center justify-between text-xs gap-2">
            <span className="text-cyan-300 font-bold uppercase tracking-wider">
              {account.label || 'Solana Public Key'}
            </span>
            <span className="text-[10px] px-2.5 py-0.5 rounded bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/30 shrink-0">
              {(account.category || 'unclassified').toUpperCase()}
            </span>
          </div>

          {account.institutionalInfo && (
            <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 space-y-1.5">
              <div className="flex items-center justify-between text-xs font-bold text-emerald-300">
                <span>{account.institutionalInfo.roleTitle}</span>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-200">
                  {account.institutionalInfo.ecosystem} • VERIFIED
                </span>
              </div>
              <div className="text-[11px] text-cyan-300 font-semibold">
                {account.institutionalInfo.institution} ({account.institutionalInfo.protocol})
              </div>
              <p className="text-[11px] text-slate-300 leading-relaxed">
                {account.institutionalInfo.description}
              </p>
            </div>
          )}

          <div className="bg-[#090b10] p-3 rounded-lg border border-slate-800 flex items-center justify-between gap-2">
            <div className="space-y-0.5 min-w-0">
              <span className="text-[10px] uppercase tracking-wider text-slate-500 block">
                Full Base58 Address (Untruncated)
              </span>
              <code className="text-xs font-mono text-cyan-300 break-all select-all block">
                {safeAddr}
              </code>
            </div>
            <button
              onClick={() => copyToClipboard(safeAddr)}
              className="p-2 text-slate-400 hover:text-cyan-300 bg-slate-800/80 rounded-lg transition shrink-0 cursor-pointer"
              title="Copy Full Address"
            >
              {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
            </button>
          </div>

          {/* Active Roles Badges */}
          <div className="flex flex-wrap items-center gap-1.5 pt-1">
            {account.isFeePayer && (
              <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                FEE PAYER
              </span>
            )}
            {account.isSigner && (
              <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                ED25519 SIGNER
              </span>
            )}
            {account.isWritable ? (
              <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">
                WRITABLE STATE
              </span>
            ) : (
              <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                READ-ONLY
              </span>
            )}
            {safeRoles.map((r) => (
              <span
                key={r}
                className="text-[10px] font-mono px-2 py-0.5 rounded bg-violet-500/15 text-violet-300 border border-violet-500/30"
              >
                {r}
              </span>
            ))}
          </div>

          <div className="flex items-center gap-2 pt-1">
            <a
              href={solscanUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="flex-1 text-center py-1.5 px-3 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 flex items-center justify-center gap-1.5 transition"
            >
              <span>View on Solscan</span>
              <ExternalLink className="w-3 h-3 text-slate-400" />
            </a>
            <a
              href={explorerUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="flex-1 text-center py-1.5 px-3 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 flex items-center justify-center gap-1.5 transition"
            >
              <span>Solana Explorer</span>
              <ExternalLink className="w-3 h-3 text-slate-400" />
            </a>
          </div>
        </div>

        {/* Critical Distinction Notice */}
        <div className="p-3.5 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs space-y-1">
          <div className="flex items-center gap-1.5 font-bold text-amber-200">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>Forensic Distinction Notice (Owner Program vs. Wallet Authority)</span>
          </div>
          <p className="text-[11px] text-slate-300 leading-relaxed">
            The Solana account owner program (<strong>{account.ownerProgramLabel || 'System / Token Program'}</strong> • <code className="font-mono text-amber-200 break-all">{safeOwnerProg}</code>) is the smart contract code managing this account's bytes. It is distinct from the cryptographic wallet authority who signed or owns the underlying tokens.
          </p>
        </div>

        {/* Verifiable On-Chain State */}
        <div className="space-y-3">
          <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider">
            Verifiable Account State & Balance Delta
          </h4>
          <div className="grid grid-cols-2 gap-2.5 text-xs">
            <div className="bg-[#111722] p-3.5 rounded-xl border border-slate-800/80 space-y-1">
              <span className="text-[11px] text-slate-400">Post-Tx Balance (SOL)</span>
              <div className="font-mono font-bold text-white text-sm">
                {safeSol.toFixed(9)} SOL
              </div>
              <div className="font-mono text-[10px] text-slate-400 break-all">
                {safeLamports.toString()} lamports
              </div>
            </div>

            <div className="bg-[#111722] p-3.5 rounded-xl border border-slate-800/80 space-y-1">
              <span className="text-[11px] text-slate-400">Executable Binary Status</span>
              <div className="font-bold text-white text-sm">
                {account.isExecutable ? (
                  <span className="text-violet-400 flex items-center gap-1">
                    <Cpu className="w-3.5 h-3.5" /> Executable Smart Contract
                  </span>
                ) : (
                  <span className="text-cyan-300 flex items-center gap-1">
                    <Key className="w-3.5 h-3.5" /> State / Custody Account
                  </span>
                )}
              </div>
              <div className="text-[10px] text-slate-400">
                {account.deltaSol !== undefined && account.deltaSol !== 0
                  ? `Tx SOL Delta: ${account.deltaSol >= 0 ? '+' : ''}${account.deltaSol.toFixed(6)} SOL`
                  : 'Zero SOL change in tx'}
              </div>
            </div>

            <div className="bg-[#111722] p-3.5 rounded-xl border border-slate-800/80 space-y-1 col-span-2">
              <span className="text-[11px] text-slate-400">Account Owner Program (Full Address)</span>
              <div className="font-mono text-cyan-300 text-xs break-all">
                {account.ownerProgramLabel ? (
                  <div>
                    <span className="font-bold text-white">{account.ownerProgramLabel}</span>
                    <div className="text-[11px] text-cyan-300 mt-0.5">{safeOwnerProg}</div>
                  </div>
                ) : (
                  safeOwnerProg
                )}
              </div>
            </div>

            {account.tokenMetadata && (
              <div className="bg-[#111722] p-3.5 rounded-xl border border-cyan-500/30 space-y-2.5 col-span-2">
                <span className="text-xs font-bold text-cyan-300 flex items-center gap-1.5">
                  <Coins className="w-4 h-4 text-cyan-400" />
                  Resolved Token & Custody Metadata (Untruncated)
                </span>
                <div className="space-y-2 text-xs">
                  {(account.tokenMetadata.mintName || account.tokenMetadata.mintSymbol) && (
                    <div className="p-2.5 rounded-lg bg-[#090d14] border border-slate-800 flex items-center justify-between">
                      <span className="text-slate-400">Token Involved:</span>
                      <span className="font-bold text-emerald-300">
                        {account.tokenMetadata.mintName || 'Solana Token'} ({account.tokenMetadata.mintSymbol || 'TOKEN'})
                      </span>
                    </div>
                  )}
                  {account.tokenMetadata.tokenOwner && (
                    <div className="p-2.5 rounded-lg bg-[#090d14] border border-slate-800 space-y-1">
                      <span className="text-slate-400 block text-[11px]">Internal Token Owner Wallet (Full Address):</span>
                      <code className="font-mono text-cyan-300 break-all block select-all">
                        {account.tokenMetadata.tokenOwner}
                      </code>
                    </div>
                  )}
                  {account.tokenMetadata.mint && (
                    <div className="p-2.5 rounded-lg bg-[#090d14] border border-slate-800 space-y-1">
                      <span className="text-slate-400 block text-[11px]">Token Mint Contract Address (Full Address):</span>
                      <code className="font-mono text-pink-300 break-all block select-all">
                        {account.tokenMetadata.mint}
                      </code>
                    </div>
                  )}
                  <div className="grid grid-cols-2 gap-2 pt-1">
                    {account.tokenMetadata.decimals !== undefined && (
                      <div className="p-2 rounded bg-[#090d14] border border-slate-800">
                        <span className="text-slate-400 text-[10px] block">Decimals</span>
                        <span className="font-mono font-bold text-slate-200">{account.tokenMetadata.decimals}</span>
                      </div>
                    )}
                    <div className="p-2 rounded bg-[#090d14] border border-slate-800">
                      <span className="text-slate-400 text-[10px] block">Token Standard</span>
                      <span className="font-mono font-bold text-slate-200">
                        {account.tokenMetadata.tokenProgram === 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb'
                          ? 'Token-2022'
                          : 'SPL Token'}
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Role Provenance & On-Chain Proofs */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider">
              Role Provenance & On-Chain Proofs
            </h4>
            <span className="text-[11px] text-cyan-400 font-semibold">{safeProofs.length} verified proof(s)</span>
          </div>

          <div className="space-y-2.5">
            {safeProofs.length === 0 ? (
              <p className="text-xs text-slate-400 p-3.5 bg-[#111722] rounded-xl border border-slate-800">
                Standard referenced account in transaction message. Click "Load History" below to inspect historical activity.
              </p>
            ) : (
              safeProofs.map((proof, idx) => (
                <div
                  key={idx}
                  className="bg-[#111722] border border-cyan-500/25 rounded-xl p-3.5 space-y-2"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-bold text-cyan-300 flex items-center gap-1.5">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                      {proof.title}
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 shrink-0">
                      {(proof.evidence?.verificationStatus || 'verified').toUpperCase()}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-200 leading-relaxed">{proof.reason}</p>
                  <div className="pt-2 border-t border-slate-800/80 text-[10px] font-mono text-slate-400 space-y-0.5">
                    <div>RPC Source: <span className="text-cyan-300">{proof.evidence?.sourceMethod}</span></div>
                    <div>Field Path: <span className="text-slate-300">{proof.evidence?.fieldPath}</span></div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Bounded History Explorer */}
        <div className="space-y-3 pt-2">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider">
              Recent On-Chain Transaction History
            </h4>
            <button
              onClick={fetchHistory}
              disabled={historyLoading}
              className="text-xs text-cyan-400 hover:text-cyan-300 font-semibold flex items-center gap-1 px-3 py-1.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 transition disabled:opacity-50 cursor-pointer"
            >
              <History className="w-3.5 h-3.5" />
              <span>{historyLoading ? 'Querying RPC Pool...' : 'Load History'}</span>
            </button>
          </div>

          {historyError && (
            <p className="text-xs text-rose-400 bg-rose-500/10 border border-rose-500/30 p-2.5 rounded-lg">
              {historyError}
            </p>
          )}

          {historyItems.length > 0 && (
            <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
              {historyItems.map((item, idx) => {
                const sig = item?.signature || '';
                return (
                  <div
                    key={idx}
                    onClick={() => sig && onSelectTx && onSelectTx(sig)}
                    className="p-3 rounded-lg bg-[#111722] hover:bg-slate-800 border border-slate-800/80 transition flex items-center justify-between gap-3 cursor-pointer group"
                  >
                    <div className="space-y-1 min-w-0">
                      <div className="font-mono text-xs text-cyan-300 group-hover:text-cyan-200 font-semibold break-all">
                        {sig}
                      </div>
                      <div className="text-[10px] text-slate-400">
                        Slot {(item?.slot ?? 0).toLocaleString()} •{' '}
                        {item?.blockTime ? new Date(item.blockTime * 1000).toLocaleString() : 'Finalized'}
                      </div>
                    </div>
                    <span
                      className={`text-[9px] px-2 py-0.5 rounded font-bold shrink-0 ${
                        item?.err === null ? 'bg-emerald-500/20 text-emerald-300' : 'bg-rose-500/20 text-rose-300'
                      }`}
                    >
                      {item?.err === null ? 'SUCCESS' : 'FAILED'}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* Drawer Footer */}
      <div className="p-4 border-t border-slate-800/80 bg-[#090b10] flex items-center justify-between text-xs text-slate-500">
        <span>SOL-MATE Forensic Registry</span>
        <span>Observation Slot: {account.observationSlot?.toLocaleString() || 'Finalized'}</span>
      </div>
    </div>
  );
};
