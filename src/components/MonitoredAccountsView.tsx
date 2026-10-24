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
      const list = await deepStorage.listMonitoredAccounts();
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
    for (const acc of accList) {
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
    }
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

    const account: MonitoredAccount = {
      address: addr,
      label: newLabel.trim() || 'Monitored Target',
      addedAt: Date.now(),
      notes: 'Added to forensic surveillance watchlist',
    };

    await deepStorage.addMonitoredAccount(account);
    setNewAddress('');
    setNewLabel('');
    loadAccounts();
  };

  const handleRemove = async (addr: string) => {
    await deepStorage.removeMonitoredAccount(addr);
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
            <h2 className="text-xl font-extrabold text-white">Monitored Wallets & Trend Reporting</h2>
          </div>
          <p className="text-xs text-slate-400">
            Track key wallets across multiple investigations with live on-chain balance polling.
          </p>
        </div>

        <button
          onClick={() => fetchLiveBalances(accounts)}
          disabled={refreshingBalances}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 border border-slate-700 transition"
        >
          <RefreshCw className={`w-3.5 h-3.5 text-cyan-400 ${refreshingBalances ? 'animate-spin' : ''}`} />
          <span>Refresh Balances</span>
        </button>
      </div>

      {/* Overview Analytics Bar */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="p-4 rounded-xl bg-[#0f1522] border border-slate-800">
          <span className="text-[11px] text-slate-400 uppercase tracking-wider">Watched Accounts</span>
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
          <div className="text-xs font-semibold text-emerald-400 mt-2 flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
            <span>Real-time OnFinality Feed</span>
          </div>
        </div>
      </div>

      {/* Add New Watchlist Account Form */}
      <div className="bg-[#0f1522] border border-slate-800 rounded-2xl p-5 space-y-4">
        <h3 className="font-bold text-sm text-white">Add Wallet to Monitored Registry</h3>
        <form onSubmit={handleAddAccount} className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <input
            type="text"
            value={newAddress}
            onChange={(e) => setNewAddress(e.target.value)}
            placeholder="Solana Wallet Address (Base58)..."
            className="sm:col-span-2 bg-[#090d14] border border-slate-700 rounded-xl px-4 py-2 text-xs text-slate-200 placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-400"
          />
          <div className="flex gap-2">
            <input
              type="text"
              value={newLabel}
              onChange={(e) => setNewLabel(e.target.value)}
              placeholder="Label (e.g. Whale, Treasury)..."
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
          <div className="p-12 text-center bg-[#0a0e16] rounded-2xl border border-slate-800 space-y-2">
            <Users className="w-8 h-8 text-slate-600 mx-auto" />
            <h3 className="text-sm font-bold text-slate-300">No Monitored Wallets</h3>
            <p className="text-xs text-slate-500 max-w-sm mx-auto">
              Add addresses above or save fee payers during investigations to monitor their live balance trends.
            </p>
          </div>
        ) : (
          accounts.map((acc) => {
            const bal = liveBalances[acc.address];
            return (
              <div
                key={acc.address}
                onClick={() => onSelectAddress(acc.address)}
                className="p-4 rounded-xl bg-[#0f1522] hover:bg-[#131b2a] border border-slate-800 hover:border-cyan-500/40 transition cursor-pointer flex flex-col sm:flex-row sm:items-center justify-between gap-4 group"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-sm text-white">{acc.label}</span>
                    <span className="font-mono text-xs text-cyan-300">
                      {acc.address.slice(0, 8)}...{acc.address.slice(-6)}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-400">
                    Added: {new Date(acc.addedAt).toLocaleDateString()} • {acc.notes}
                  </div>
                </div>

                <div className="flex items-center gap-4">
                  <div className="text-right">
                    <span className="text-[10px] text-slate-500 uppercase tracking-wider block">Live Balance</span>
                    <span className="font-mono font-bold text-sm text-white">
                      {bal !== undefined ? `${bal.toFixed(4)} SOL` : 'Polling...'}
                    </span>
                  </div>

                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      handleRemove(acc.address);
                    }}
                    className="p-2 text-slate-500 hover:text-rose-400 hover:bg-rose-500/10 rounded-lg transition"
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
