/**
 * SOL-MATE — Monitored Wallets & Trend Reporting
 * Deep state tracking of monitored accounts across time, live balance reconciliation,
 * and suspicious pattern watchers.
 */

import React, { useState, useEffect } from 'react';
import {
  Users,
  Plus,
  Trash2,
  ExternalLink,
  ShieldAlert,
  Search,
  Eye,
  ArrowRight,
  TrendingUp,
  RefreshCw,
} from 'lucide-react';
import { deepStorage, MonitoredAccount } from '../services/deepStorage';
import { rpcClient } from '../services/rpcClient';
import { isValidSolanaAddress } from '../services/transactionParser';
import { getInstitutionalMetadata } from '../services/protocolIntelligence';

const DEFAULT_MONITORED_WATCHLIST: MonitoredAccount[] = [
  {
    address: 'J4cTuCH6frt4AnEmKfMS2k8hsUf7K94PV62sjUJno8Cz',
    label: 'J.P. Morgan JLTXX Liquidity Token Mint (Token-2022)',
    addedAt: 1744835852000,
    notes: 'Regulated Token-2022 Mint • Monitored for MintTo, BurnApprove, and SetStopCodes',
  },
  {
    address: 'EToDtBM2knZ8N1BHyUq2Riq5ngWTcoD3k6qpsgf7CKYY',
    label: 'J.P. Morgan MONY Settlement Token Mint (Token-2022)',
    addedAt: 1744835852000,
    notes: 'Regulated Token-2022 Mint • Monitored for First-Time Client Onboarding & High-Value Issuance',
  },
  {
    address: '9rdASsDUnrw2EsDARtfqjabqcjfXYFKu45kZ31wF74dg',
    label: 'J.P. Morgan / Kinexys FACT Tokenization Controller Program',
    addedAt: 1744835852000,
    notes: 'Governing Smart Contract • Monitored for MintTo, prepare_burn, BurnApprove, SetStopCodes',
  },
  {
    address: '4tm6TUNqJqnxUoD3ocknd8MfK4DC2tBezaXJFTVyZK1D',
    label: 'FACT Operations Fee Payer & Dispatcher Authority',
    addedAt: 1744835852000,
    notes: 'Whitelisted Institutional Dispatcher & Compliance Authority Signer',
  },
  {
    address: 'DwWsjJsCic4xF7MPgqSxT7WZGancjGtumbmVVYFK1zXR',
    label: 'Onboarded Institutional Client Custody Wallet (JLTXX Holder)',
    addedAt: 1744835852000,
    notes: 'Owner of JLTXX Token-2022 Custody Vault CUNnRnBZT7sjAb911toVo7UQzfQ1PdVEUDjLGQsmzPcj',
  },
];

interface MonitoredAccountsProps {
  onSelectAddress: (addr: string) => void;
}

export const MonitoredAccountsView: React.FC<MonitoredAccountsProps> = ({ onSelectAddress }) => {
  const [accounts, setAccounts] = useState<MonitoredAccount[]>([]);
  const [loading, setLoading] = useState(false);
  const [newAddress, setNewAddress] = useState('');
  const [newLabel, setNewLabel] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [liveBalances, setLiveBalances] = useState<Record<string, number>>({});
  const [refreshingBalances, setRefreshingBalances] = useState(false);

  const loadAccounts = async () => {
    setLoading(true);
    try {
      let list = await deepStorage.listMonitoredAccounts();
      if (list.length === 0) {
        for (const seed of DEFAULT_MONITORED_WATCHLIST) {
          await deepStorage.addMonitoredAccount(seed);
        }
        list = await deepStorage.listMonitoredAccounts();
      }
      setAccounts(list);
      fetchLiveBalances(list);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAccounts();
  }, []);

  const fetchLiveBalances = async (accList: MonitoredAccount[]) => {
    setRefreshingBalances(true);
    const balanceMap: Record<string, number> = {};
    await Promise.all(
      accList.map(async (acc) => {
        try {
          const bal = await rpcClient.call<{ value: number }>('getBalance', [acc.address], {
            priority: 2,
          });
          if (bal && typeof bal.value === 'number') {
            balanceMap[acc.address] = bal.value / 1e9;
          }
        } catch {
          // non-fatal
        }
      })
    );
    setLiveBalances(balanceMap);
    setRefreshingBalances(false);
  };

  const handleAddAccount = async (e: React.FormEvent) => {
    e.preventDefault();
    const addr = newAddress.trim();
    if (!addr) return;
    if (!isValidSolanaAddress(addr)) {
      setError('Invalid Solana address format (expected 32-44 Base58 characters).');
      return;
    }
    setError(null);

    const inst = getInstitutionalMetadata(addr);
    const account: MonitoredAccount = {
      address: addr,
      label: newLabel.trim() || inst?.label || 'Monitored Forensic Target',
      addedAt: Date.now(),
      notes: inst
        ? `${inst.institution} • ${inst.protocol} (${inst.roleTitle})`
        : 'Added to forensic surveillance watchlist',
    };

    await deepStorage.addMonitoredAccount(account);
    setNewAddress('');
    setNewLabel('');
    loadAccounts();
  };

  const handleRemove = async (addr: string) => {
    await deepStorage.removeMonitoredAccount(addr);
    const list = await deepStorage.listMonitoredAccounts();
    setAccounts(list);
  };

  const handleSeedDefaults = async () => {
    for (const seed of DEFAULT_MONITORED_WATCHLIST) {
      await deepStorage.addMonitoredAccount(seed);
    }
    loadAccounts();
  };

  const totalMonitoredSol = Object.values(liveBalances).reduce((a, b) => a + b, 0);

  return (
    <div className="max-w-6xl mx-auto px-4 py-8 space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-[#0d121c] border border-blue-500/20 rounded-2xl p-5 shadow-xl">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <Users className="w-5 h-5 text-blue-400" />
            <h2 className="text-xl font-extrabold text-white">Monitored Wallets, Mints & Trend Reporting</h2>
          </div>
          <p className="text-xs text-slate-400">
            Continuous surveillance of institutional token mints, governing programs, dispatchers, and client custody wallets with live RPC balance polling.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleSeedDefaults}
            className="px-3 py-1.5 rounded-xl bg-cyan-500/15 hover:bg-cyan-500/25 text-xs font-bold text-cyan-300 border border-cyan-500/30 transition cursor-pointer"
          >
            Restore Institutional Presets
          </button>
          <button
            onClick={() => fetchLiveBalances(accounts)}
            disabled={refreshingBalances}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 border border-slate-700 transition cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 text-cyan-400 ${refreshingBalances ? 'animate-spin' : ''}`} />
            <span>Refresh Live Balances</span>
          </button>
        </div>
      </div>

      {/* Overview Analytics Bar */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="p-4 rounded-xl bg-[#0f1522] border border-slate-800">
          <span className="text-[11px] text-slate-400 uppercase tracking-wider">Watched Entities</span>
          <div className="text-2xl font-mono font-extrabold text-white mt-1">
            {accounts.length}
          </div>
        </div>

        <div className="p-4 rounded-xl bg-[#0f1522] border border-slate-800">
          <span className="text-[11px] text-slate-400 uppercase tracking-wider">Total Combined SOL</span>
          <div className="text-2xl font-mono font-extrabold text-cyan-300 mt-1">
            {totalMonitoredSol.toFixed(4)} SOL
          </div>
        </div>

        <div className="p-4 rounded-xl bg-[#0f1522] border border-slate-800">
          <span className="text-[11px] text-slate-400 uppercase tracking-wider">Surveillance Policy</span>
          <div className="text-xs font-semibold text-emerald-400 mt-2 flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
            <span>6x Parallel RPC Pool + Rule Engine Active</span>
          </div>
        </div>
      </div>

      {/* Add New Watchlist Account Form */}
      <div className="bg-[#0f1522] border border-slate-800 rounded-2xl p-5 space-y-4">
        <h3 className="font-bold text-sm text-white">Add Wallet, Token Mint, or Program to Monitored Registry</h3>
        <form onSubmit={handleAddAccount} className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <input
            type="text"
            value={newAddress}
            onChange={(e) => setNewAddress(e.target.value)}
            placeholder="Solana Address, Token Mint, or Program ID (Base58)..."
            className="sm:col-span-2 bg-[#090d14] border border-slate-700 rounded-xl px-4 py-2 text-xs text-slate-200 placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-400"
          />
          <div className="flex gap-2">
            <input
              type="text"
              value={newLabel}
              onChange={(e) => setNewLabel(e.target.value)}
              placeholder="Label (e.g. Treasury, Mint)..."
              className="flex-1 bg-[#090d14] border border-slate-700 rounded-xl px-3 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-400"
            />
            <button
              type="submit"
              className="px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs rounded-xl transition shrink-0 cursor-pointer"
            >
              Add
            </button>
          </div>
        </form>
        {error && <p className="text-xs text-rose-400">{error}</p>}
      </div>

      {/* Accounts List */}
      <div className="space-y-3">
        {accounts.length === 0 ? (
          <div className="p-12 text-center bg-[#0a0e16] rounded-2xl border border-slate-800 space-y-3">
            <Users className="w-8 h-8 text-slate-600 mx-auto" />
            <h3 className="text-sm font-bold text-slate-300">No Monitored Wallets</h3>
            <p className="text-xs text-slate-500 max-w-sm mx-auto">
              Add addresses above or click below to load default institutional watch targets.
            </p>
            <button
              onClick={handleSeedDefaults}
              className="px-4 py-2 bg-cyan-500 text-slate-950 font-bold text-xs rounded-xl cursor-pointer"
            >
              Load Institutional Watchlist Presets
            </button>
          </div>
        ) : (
          accounts.map((acc) => {
            const bal = liveBalances[acc.address];
            const inst = getInstitutionalMetadata(acc.address);
            return (
              <div
                key={acc.address}
                onClick={() => onSelectAddress(acc.address)}
                className="p-4 rounded-xl bg-[#0f1522] hover:bg-[#131b2a] border border-slate-800 hover:border-cyan-500/40 transition cursor-pointer flex flex-col lg:flex-row lg:items-center justify-between gap-4 group"
              >
                <div className="space-y-1.5 min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-bold text-sm text-white group-hover:text-cyan-300">
                      {acc.label}
                    </span>
                    {inst && (
                      <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 font-mono text-[10px] font-bold">
                        {inst.ecosystem} • {inst.roleTitle}
                      </span>
                    )}
                  </div>
                  <div className="font-mono text-xs text-cyan-300 break-all">
                    {acc.address}
                  </div>
                  <div className="text-[11px] text-slate-400">
                    {acc.notes} • Click to open Deep Address & History Inspector
                  </div>
                </div>

                <div className="flex items-center gap-4 shrink-0">
                  <div className="text-right">
                    <span className="text-[10px] text-slate-500 uppercase tracking-wider block">
                      Live Mainnet Balance
                    </span>
                    <span className="font-mono font-bold text-sm text-white">
                      {bal !== undefined ? `${bal.toFixed(6)} SOL` : 'Polling RPC...'}
                    </span>
                  </div>

                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      handleRemove(acc.address);
                    }}
                    className="p-2 text-slate-500 hover:text-rose-400 hover:bg-rose-500/10 rounded-lg transition cursor-pointer"
                    title="Remove from monitoring"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};

