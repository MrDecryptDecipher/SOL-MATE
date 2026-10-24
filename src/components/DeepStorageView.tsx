/**
 * SOL-MATE — Deep State Storage Library
 * Manages saved forensic cases, case export/import, search, and historical case analytics.
 */

import React, { useState } from 'react';
import {
  Database,
  Search,
  Trash2,
  ExternalLink,
  Download,
  Upload,
  Calendar,
  AlertTriangle,
  CheckCircle2,
  ArrowRight,
  ShieldAlert,
} from 'lucide-react';
import { SavedInvestigationSummary, deepStorage } from '../services/deepStorage';

interface DeepStorageViewProps {
  investigations: SavedInvestigationSummary[];
  onSelectInvestigation: (sig: string) => void;
  onRefresh: () => void;
}

export const DeepStorageView: React.FC<DeepStorageViewProps> = ({
  investigations,
  onSelectInvestigation,
  onRefresh,
}) => {
  const [filterText, setFilterText] = useState('');
  const [exporting, setExporting] = useState(false);

  const handleDelete = async (sig: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (confirm('Delete this saved investigation from local IndexedDB?')) {
      await deepStorage.deleteInvestigation(sig);
      onRefresh();
    }
  };

  const handleExportBackup = async () => {
    setExporting(true);
    try {
      const json = await deepStorage.exportAllJson();
      const blob = new Blob([json], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `SOLMATE_DeepStorage_Backup_${new Date().toISOString().slice(0, 10)}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } finally {
      setExporting(false);
    }
  };

  const filtered = investigations.filter(
    (inv) =>
      inv.signature.toLowerCase().includes(filterText.toLowerCase()) ||
      inv.analystTags.some((t) => t.toLowerCase().includes(filterText.toLowerCase()))
  );

  return (
    <div className="max-w-6xl mx-auto px-4 py-8 space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-[#0d121c] border border-violet-500/20 rounded-2xl p-5 shadow-xl">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <Database className="w-5 h-5 text-violet-400" />
            <h2 className="text-xl font-extrabold text-white">Saved Forensic Investigations</h2>
          </div>
          <p className="text-xs text-slate-400">
            Persistent IndexedDB archive of analyzed transactions and evidence catalogs.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleExportBackup}
            disabled={exporting || investigations.length === 0}
            className="px-3.5 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 border border-slate-700 flex items-center gap-1.5 transition disabled:opacity-50"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            <span>Export Archive (JSON)</span>
          </button>
        </div>
      </div>

      {/* Search and Filters */}
      <div className="flex items-center justify-between gap-3">
        <div className="relative flex-1 max-w-md">
          <input
            type="text"
            value={filterText}
            onChange={(e) => setFilterText(e.target.value)}
            placeholder="Search saved signatures or tags..."
            className="w-full bg-[#090d14] border border-slate-700 rounded-xl pl-9 pr-4 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-400 font-mono"
          />
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
        </div>
        <span className="text-xs text-slate-400 font-mono">{filtered.length} Case(s)</span>
      </div>

      {/* Case List */}
      {filtered.length === 0 ? (
        <div className="p-12 text-center bg-[#0a0e16] rounded-2xl border border-slate-800 space-y-2">
          <Database className="w-8 h-8 text-slate-600 mx-auto" />
          <h3 className="text-sm font-bold text-slate-300">No Saved Investigations Found</h3>
          <p className="text-xs text-slate-500 max-w-sm mx-auto">
            Run an investigation on any Solana transaction signature and click "Save Case" to persist it in your local forensic library.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {filtered.map((inv) => (
            <div
              key={inv.signature}
              onClick={() => onSelectInvestigation(inv.signature)}
              className="p-4 rounded-xl bg-[#0f1522] hover:bg-[#131b2a] border border-slate-800 hover:border-cyan-500/40 transition cursor-pointer flex flex-col sm:flex-row sm:items-center justify-between gap-4 group"
            >
              <div className="space-y-1.5">
                <div className="flex items-center gap-2">
                  <span
                    className={`text-[9px] px-2 py-0.5 rounded font-bold ${
                      inv.status === 'success'
                        ? 'bg-emerald-500/20 text-emerald-300'
                        : 'bg-rose-500/20 text-rose-300'
                    }`}
                  >
                    {inv.status.toUpperCase()}
                  </span>
                  <span className="font-mono text-cyan-300 group-hover:text-cyan-200 font-bold text-sm">
                    {inv.signature.slice(0, 14)}...{inv.signature.slice(-8)}
                  </span>
                </div>

                <div className="flex flex-wrap items-center gap-3 text-xs text-slate-400 font-mono">
                  <span>Slot {inv.slot.toLocaleString()}</span>
                  <span>•</span>
                  <span>{inv.accountsCount} accounts</span>
                  <span>•</span>
                  <span>{inv.instructionsCount} instructions</span>
                  <span>•</span>
                  <span>Fee: {inv.feeSol.toFixed(6)} SOL</span>
                </div>
              </div>

              <div className="flex items-center gap-4">
                <div className="text-right">
                  <span className="text-[10px] text-slate-500 uppercase tracking-wider block">Risk Score</span>
                  <span
                    className={`font-mono font-bold text-sm ${
                      inv.riskScore === 0
                        ? 'text-emerald-400'
                        : inv.riskScore < 40
                        ? 'text-amber-400'
                        : 'text-rose-400'
                    }`}
                  >
                    {inv.riskScore}/100
                  </span>
                </div>

                <button
                  onClick={(e) => handleDelete(inv.signature, e)}
                  className="p-2 text-slate-500 hover:text-rose-400 hover:bg-rose-500/10 rounded-lg transition"
                  title="Delete case"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
