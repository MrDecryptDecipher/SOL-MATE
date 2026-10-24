/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import { Sidebar, ActiveTab } from './components/Sidebar';
import { Header } from './components/Header';
import { SearchHero } from './components/SearchHero';
import { InvestigationWorkspace } from './components/InvestigationWorkspace';
import { LiveMonitoring } from './components/LiveMonitoring';
import { DeepStorageView } from './components/DeepStorageView';
import { MonitoredAccountsView } from './components/MonitoredAccountsView';
import { AccountDrawer } from './components/AccountDrawer';
import { SettingsModal } from './components/SettingsModal';
import { forensicsEngine, InvestigationProgress } from './services/forensicsEngine';
import { deepStorage, SavedInvestigationSummary } from './services/deepStorage';
import { AccountRecord, TransactionRecord } from './types/forensics';
import { SolanaCluster } from './types/solana';
import { loadAppConfig, saveAppConfig } from './services/config';
import { getInstitutionalMetadata } from './services/protocolIntelligence';

interface ErrorBoundaryProps {
  children: React.ReactNode;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

class ErrorBoundary extends React.Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error('Forensic ErrorBoundary caught error:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="p-8 text-center bg-[#090b10] text-slate-200 min-h-screen flex flex-col items-center justify-center space-y-4">
          <div className="p-5 rounded-xl bg-rose-500/10 border border-rose-500/30 max-w-lg space-y-2">
            <h2 className="text-base font-bold text-rose-300">Forensics Component Boundary Caught An Issue</h2>
            <p className="text-xs text-slate-400 font-mono">{this.state.error?.message}</p>
            <button
              onClick={() => {
                this.setState({ hasError: false, error: null });
              }}
              className="mt-3 px-4 py-1.5 bg-cyan-500 text-slate-950 font-bold rounded-lg text-xs cursor-pointer"
            >
              Recover Workspace
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

export default function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('search');
  const [currentCluster, setCurrentCluster] = useState<SolanaCluster>('mainnet');
  const [activeTransaction, setActiveTransaction] = useState<TransactionRecord | null>(null);
  const [selectedAccount, setSelectedAccount] = useState<AccountRecord | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [progress, setProgress] = useState<InvestigationProgress | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [savedInvestigations, setSavedInvestigations] = useState<SavedInvestigationSummary[]>([]);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);

  useEffect(() => {
    const config = loadAppConfig();
    setCurrentCluster(config.network);
    refreshSavedCases();

    if (typeof window !== 'undefined') {
      const params = new URLSearchParams(window.location.search);
      const urlSig = params.get('tx') || params.get('signature');
      if (urlSig) {
        handleInvestigate(urlSig);
      }
    }
  }, []);

  const refreshSavedCases = async () => {
    try {
      const list = await deepStorage.listSavedInvestigations();
      setSavedInvestigations(list);
    } catch (err) {
      console.warn('Failed to load saved cases from storage:', err);
    }
  };

  const handleInvestigate = async (signature: string) => {
    setIsLoading(true);
    setError(null);
    setProgress({ stage: 'validating-signature', message: 'Initiating forensic inspection...', percent: 5 });

    try {
      if (typeof window !== 'undefined' && window.history) {
        const url = new URL(window.location.href);
        url.searchParams.set('tx', signature);
        window.history.pushState({}, '', url.toString());
      }

      const txRecord = await forensicsEngine.investigate(signature, currentCluster, (p) => {
        setProgress(p);
      });

      setActiveTransaction(txRecord);
      setActiveTab('investigation');
      refreshSavedCases();
    } catch (err: any) {
      setError(err.message || 'An unexpected error occurred during investigation');
    } finally {
      setIsLoading(false);
    }
  };

  const handleSelectSavedTx = async (sig: string) => {
    const cached = await deepStorage.getInvestigation(sig);
    if (cached && cached.resolvedTokens && cached.alertIntelligence && cached.deepCorrelations) {
      setActiveTransaction(cached);
      setActiveTab('investigation');
    } else {
      handleInvestigate(sig);
    }
  };

  const handleSelectAddress = (address: string) => {
    if (!address) return;
    if (activeTransaction && activeTransaction.accountsRegistry[address]) {
      setSelectedAccount(activeTransaction.accountsRegistry[address]);
    } else {
      const instMeta = getInstitutionalMetadata(address);
      const tempAcc: AccountRecord = {
        address,
        label: instMeta?.label || 'Inspected Solana Address',
        institutionalInfo: instMeta
          ? {
              shortLabel: instMeta.shortLabel,
              roleTitle: instMeta.roleTitle,
              ecosystem: instMeta.ecosystem,
              institution: instMeta.institution,
              protocol: instMeta.protocol,
              description: instMeta.description,
              securityStatus: instMeta.securityStatus,
            }
          : undefined,
        category: instMeta ? instMeta.category : 'unclassified',
        categoryConfidence: instMeta ? 'high' : 'low',
        roles: instMeta?.isProgram
          ? ['program-id']
          : instMeta?.isPda
          ? ['program-derived-address']
          : ['readonly'],
        roleProofs: instMeta
          ? [
              {
                role: instMeta.isProgram ? 'program-id' : 'program-derived-address',
                title: `Verified Entity: ${instMeta.roleTitle}`,
                reason: `${instMeta.description} (${instMeta.institution} • ${instMeta.protocol})`,
                evidence: {
                  id: `proof-inst-${address}`,
                  sourceMethod: 'SOL-MATE Protocol Intelligence Registry',
                  fieldPath: `INSTITUTIONAL_REGISTRY[${address}]`,
                  rawValue: instMeta,
                  interpretation: `Verified ${instMeta.label}`,
                  verificationStatus: 'verified',
                },
              },
            ]
          : [],
        isSigner: false,
        isWritable: false,
        isFeePayer: false,
        isExecutable: Boolean(instMeta?.isProgram),
        ownerProgram: instMeta?.relatedProgram || '11111111111111111111111111111111',
        ownerProgramLabel: instMeta?.protocol || 'System Program',
        lamports: 0n,
        solBalance: 0,
        liveStateFetched: false,
      };
      setSelectedAccount(tempAcc);
    }
  };

  const handleClusterChange = (cluster: SolanaCluster) => {
    setCurrentCluster(cluster);
    const config = loadAppConfig();
    config.network = cluster;
    saveAppConfig(config);
  };

  return (
    <ErrorBoundary>
      <div className="flex min-h-screen bg-[#090b10] text-slate-100 font-sans">
        <Sidebar
          activeTab={activeTab}
          onTabChange={(tab) => {
            setActiveTab(tab);
            if (tab === 'settings') setIsSettingsOpen(true);
          }}
          hasActiveTransaction={!!activeTransaction}
          activeSignature={activeTransaction?.signature}
          savedInvestigations={savedInvestigations}
          onSelectSavedTx={handleSelectSavedTx}
        />

        <div className="flex-1 flex flex-col min-w-0">
          <Header
            currentCluster={currentCluster}
            onClusterChange={handleClusterChange}
            onOpenSettings={() => setIsSettingsOpen(true)}
            onSearchSignature={handleInvestigate}
            isInvestigating={isLoading}
          />

          <main className="flex-1 pb-16">
            {activeTab === 'search' && (
              <SearchHero
                onInvestigate={handleInvestigate}
                isLoading={isLoading}
                progress={progress}
                error={error}
                currentCluster={currentCluster}
              />
            )}

            {activeTab === 'investigation' && activeTransaction && (
              <InvestigationWorkspace
                transaction={activeTransaction}
                onSelectAddress={handleSelectAddress}
                onSaveCase={refreshSavedCases}
                onAddMonitoredAccount={(addr) => {
                  deepStorage.addMonitoredAccount({
                    address: addr,
                    label: activeTransaction.accountsRegistry[addr]?.label || 'Monitored Forensic Target',
                    addedAt: Date.now(),
                    notes: `Added from transaction ${(activeTransaction.signature || '').slice(0, 12)}...`,
                  });
                }}
              />
            )}

            {activeTab === 'investigation' && !activeTransaction && (
              <div className="max-w-2xl mx-auto px-4 py-16 text-center space-y-3">
                <h3 className="text-base font-bold text-slate-300">No Active Case Selected</h3>
                <p className="text-xs text-slate-500">
                  Enter a Solana transaction signature or select a sample case to start forensic analysis.
                </p>
                <button
                  onClick={() => setActiveTab('search')}
                  className="px-4 py-2 bg-cyan-500 text-slate-950 text-xs font-bold rounded-xl cursor-pointer"
                >
                  Go to Search
                </button>
              </div>
            )}

            {activeTab === 'monitoring' && (
              <LiveMonitoring
                onInvestigateSignature={handleInvestigate}
                onSelectAddress={handleSelectAddress}
              />
            )}

            {activeTab === 'saved' && (
              <DeepStorageView
                investigations={savedInvestigations}
                onSelectInvestigation={handleSelectSavedTx}
                onRefresh={refreshSavedCases}
              />
            )}

            {activeTab === 'monitored-accounts' && (
              <MonitoredAccountsView onSelectAddress={handleSelectAddress} />
            )}
          </main>
        </div>

        <AccountDrawer
          account={selectedAccount}
          onClose={() => setSelectedAccount(null)}
          cluster={currentCluster}
          onSelectTx={handleInvestigate}
        />

        <SettingsModal
          isOpen={isSettingsOpen}
          onClose={() => {
            setIsSettingsOpen(false);
            if (activeTab === 'settings') setActiveTab('search');
          }}
          onConfigUpdated={() => {
            const cfg = loadAppConfig();
            setCurrentCluster(cfg.network);
          }}
        />
      </div>
    </ErrorBoundary>
  );
}
