/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import { Sidebar, ActiveTab } from './components/Sidebar';
import { Header } from './components/Header';
import { SearchHero, REAL_MAINNET_SAMPLES } from './components/SearchHero';
import { InvestigationWorkspace } from './components/InvestigationWorkspace';
import { LiveMonitoring } from './components/LiveMonitoring';
import { DeepStorageView } from './components/DeepStorageView';
import { MonitoredAccountsView } from './components/MonitoredAccountsView';
import { AccountDrawer } from './components/AccountDrawer';
import { SettingsModal } from './components/SettingsModal';
import { UniversalAlertInbox } from './components/UniversalAlertInbox';
import { AssetProgramExplorer } from './components/AssetProgramExplorer';
import { DetectionEngineeringConsole } from './components/DetectionEngineeringConsole';
import { PublicHomepage } from './components/PublicHomepage';
import { EaseModeWorkspace } from './components/EaseModeWorkspace';
import { InstantModeWorkspace } from './components/InstantModeWorkspace';
import {
  forensicsEngine,
  InvestigationProgress,
  isValidEvmAddress,
  isValidEvmTxHash,
} from './services/forensicsEngine';
import { isValidBase58Signature, isValidSolanaAddress } from './services/transactionParser';
import { deepStorage, SavedInvestigationSummary } from './services/deepStorage';
import { AccountRecord, TransactionRecord } from './types/forensics';
import { SolanaCluster } from './types/solana';
import { loadAppConfig, saveAppConfig } from './services/config';
import { getInstitutionalMetadata } from './services/protocolIntelligence';
import {
  DEFAULT_DETECTION_RULES,
  evaluateRuleEnginePerformance,
  getForensicReplayRawTransaction,
  getMonitoredAssetProgramProfiles,
} from './services/universalDetectionEngine';
import { AnalystDisposition, DetectionRule, UniversalAlertRecord } from './types/universalIntel';
import {
  ConnectedUserProfile,
  disconnectGoogleAccount,
  getStoredUserActivities,
  getStoredUserSession,
  logUserProductActivity,
  subscribeConnectedUser,
  subscribeUserActivities,
  updateUserPreferredMode,
  UserActivityRecord,
  WorkspaceMode,
} from './services/firebaseService';
import {
  getPersistentKnowledgeGraphState,
  PersistentKnowledgeGraphState,
  subscribePersistentKnowledgeGraph,
  trainAddressToKnowledgeGraph,
  trainTransactionToKnowledgeGraph,
} from './services/knowledgeGraphService';
import { getISTGreeting } from './utils/istTime';
import { SANDEEP_PHOTO_BASE64 } from './constants/creatorPhotoBase64';
import { Sparkles, ShieldCheck, Globe, Clock, Database, X } from 'lucide-react';

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
  const [connectedUser, setConnectedUser] = useState<ConnectedUserProfile | null>(() =>
    getStoredUserSession()
  );
  const [workspaceMode, setWorkspaceMode] = useState<WorkspaceMode>(
    () => getStoredUserSession()?.preferredMode || 'ease'
  );
  const [showHomepagePreview, setShowHomepagePreview] = useState(false);
  const [showWelcomeBanner, setShowWelcomeBanner] = useState(true);
  const [userActivities, setUserActivities] = useState<UserActivityRecord[]>(() =>
    getStoredUserActivities()
  );
  const [persistentKg, setPersistentKg] = useState<PersistentKnowledgeGraphState>(() =>
    getPersistentKnowledgeGraphState()
  );

  const [activeTab, setActiveTab] = useState<ActiveTab>('search');
  const [currentCluster, setCurrentCluster] = useState<SolanaCluster>('mainnet');
  const [activeTransaction, setActiveTransaction] = useState<TransactionRecord | null>(null);
  const [selectedAccount, setSelectedAccount] = useState<AccountRecord | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [progress, setProgress] = useState<InvestigationProgress | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [savedInvestigations, setSavedInvestigations] = useState<SavedInvestigationSummary[]>([]);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [detectionRules, setDetectionRules] = useState<DetectionRule[]>(() => DEFAULT_DETECTION_RULES);
  const [dispositionMap, setDispositionMap] = useState<
    Record<string, { disposition: AnalystDisposition; notes?: string }>
  >({});

  useEffect(() => {
    const unsubUser = subscribeConnectedUser((u) => {
      setConnectedUser(u);
      if (u?.preferredMode) {
        setWorkspaceMode(u.preferredMode);
      }
    });
    const unsubActs = subscribeUserActivities((acts) => setUserActivities(acts));
    const unsubKg = subscribePersistentKnowledgeGraph((kg) => setPersistentKg(kg));
    return () => {
      unsubUser();
      unsubActs();
      unsubKg();
    };
  }, []);

  const engineEval = React.useMemo(
    () => evaluateRuleEnginePerformance(detectionRules),
    [detectionRules]
  );

  const universalAlertsWithDispositions: UniversalAlertRecord[] = React.useMemo(() => {
    return engineEval.generatedAlerts.map((a) => {
      const over = dispositionMap[a.alertId];
      if (!over) return a;
      return {
        ...a,
        disposition: over.disposition,
        dispositionNotes: over.notes,
        dispositionUpdatedAt: Date.now(),
      };
    });
  }, [engineEval.generatedAlerts, dispositionMap]);

  const handleUpdateDisposition = (
    alertId: string,
    disposition: AnalystDisposition,
    notes?: string
  ) => {
    setDispositionMap((prev) => ({
      ...prev,
      [alertId]: { disposition, notes },
    }));
    logUserProductActivity({
      actionType: 'ALERT_DISPOSITION',
      actionTitle: `Updated Alert ${alertId} Disposition to ${disposition}`,
      targetId: alertId,
      mode: workspaceMode,
      details: `Analyst disposition set to ${disposition}${notes ? ` (${notes})` : ''}`,
    });
  };

  useEffect(() => {
    const config = loadAppConfig();
    setCurrentCluster(config.network);
    refreshSavedCases();

    if (typeof window !== 'undefined') {
      const params = new URLSearchParams(window.location.search);
      const urlSig = params.get('tx') || params.get('signature');
      if (urlSig) {
        handleInvestigate(urlSig);
        return;
      }
    }

    // Load default flagship JLTXX Mainnet transaction so Ease Mode and Pro Mode have live data ready
    if (!activeTransaction) {
      handleInvestigate(REAL_MAINNET_SAMPLES[0].signature);
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

  const handleWorkspaceModeChange = async (nextMode: WorkspaceMode) => {
    setWorkspaceMode(nextMode);
    await updateUserPreferredMode(nextMode);
  };

  const handleInvestigate = async (queryStr: string) => {
    const trimmed = (queryStr || '').trim();
    if (!trimmed) return;

    const isReplayTx = Boolean(getForensicReplayRawTransaction(trimmed));
    const isTx = isReplayTx || isValidBase58Signature(trimmed) || isValidEvmTxHash(trimmed);
    const isAddr = !isTx && (isValidSolanaAddress(trimmed) || isValidEvmAddress(trimmed));

    if (isAddr) {
      handleSelectAddress(trimmed);
      const matchedProfile = getMonitoredAssetProgramProfiles().find((p) => p.identifier === trimmed);
      if (matchedProfile && workspaceMode === 'pro') {
        setActiveTab('asset-explorer');
        return;
      }
      try {
        const hist = await forensicsEngine.getAddressHistory(trimmed, 1);
        if (hist && hist.length > 0 && hist[0].signature) {
          await handleInvestigate(hist[0].signature);
        }
      } catch {
        // Drawer is already open for inspection
      }
      return;
    }

    setIsLoading(true);
    setError(null);
    setProgress({ stage: 'validating-signature', message: 'Initiating forensic inspection...', percent: 5 });

    try {
      if (typeof window !== 'undefined' && window.history) {
        const url = new URL(window.location.href);
        url.searchParams.set('tx', trimmed);
        window.history.pushState({}, '', url.toString());
      }

      const txRecord = await forensicsEngine.investigate(trimmed, currentCluster, (p) => {
        setProgress(p);
      });

      setActiveTransaction(txRecord);
      if (workspaceMode === 'pro') {
        setActiveTab('investigation');
      }
      refreshSavedCases();

      // Log product activity and train Persistent Solana Knowledge Graph with IST timestamps
      await logUserProductActivity({
        actionType: 'TX_INVESTIGATION',
        actionTitle: `Investigated Transaction ${trimmed.slice(0, 14)}... (${txRecord.alertIntelligence.primaryAlertType})`,
        targetId: trimmed,
        mode: workspaceMode,
        details: `Slot #${txRecord.slot.toLocaleString()} • ${txRecord.combinedAccounts.length} Accounts • Risk Score ${txRecord.heuristicRiskScore}/100`,
      });

      await trainTransactionToKnowledgeGraph(txRecord, connectedUser);
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
      if (workspaceMode === 'pro') {
        setActiveTab('investigation');
      }
      await trainTransactionToKnowledgeGraph(cached, connectedUser);
    } else {
      handleInvestigate(sig);
    }
  };

  const handleSelectAddress = (address: string) => {
    if (!address) return;
    const existingAcc = activeTransaction?.accountsRegistry?.[address];
    if (existingAcc) {
      setSelectedAccount(existingAcc);
      trainAddressToKnowledgeGraph(existingAcc, connectedUser);
      logUserProductActivity({
        actionType: 'ADDRESS_INSPECTION',
        actionTitle: `Inspected Address ${address.slice(0, 12)}... (${existingAcc.label || existingAcc.category})`,
        targetId: address,
        mode: workspaceMode,
        details: `Live RPC & Institutional Registry inspection for ${address}`,
      });
      forensicsEngine
        .inspectAddressLive(address, existingAcc)
        .then((enriched) => {
          setSelectedAccount((prev) => (prev?.address === address ? enriched : prev));
          trainAddressToKnowledgeGraph(enriched, connectedUser);
        })
        .catch(() => {});
    } else {
      const instMeta = getInstitutionalMetadata(address);
      const tempAcc: AccountRecord = {
        address,
        label: instMeta?.label || 'Inspected Blockchain Address',
        institutionalInfo: instMeta
          ? {
              shortLabel: instMeta.shortLabel,
              roleTitle: instMeta.roleTitle,
              ecosystem: instMeta.ecosystem,
              institution: instMeta.institution,
              protocol: instMeta.protocol,
              description: instMeta.description,
              whatItIs: instMeta.whatItIs,
              whyWhitelisted: instMeta.whyWhitelisted,
              howItWorks: instMeta.howItWorks,
              pairedAddress: instMeta.pairedAddress,
              pairedRole: instMeta.pairedRole,
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
      trainAddressToKnowledgeGraph(tempAcc, connectedUser);
      logUserProductActivity({
        actionType: 'ADDRESS_INSPECTION',
        actionTitle: `Inspected Address ${address.slice(0, 12)}... (${tempAcc.label})`,
        targetId: address,
        mode: workspaceMode,
        details: `Live RPC & Institutional Registry inspection for ${address}`,
      });
      forensicsEngine
        .inspectAddressLive(address, tempAcc)
        .then((enriched) => {
          setSelectedAccount((prev) => (prev?.address === address ? enriched : prev));
          trainAddressToKnowledgeGraph(enriched, connectedUser);
        })
        .catch(() => {});
    }
  };

  const handleClusterChange = (cluster: SolanaCluster) => {
    setCurrentCluster(cluster);
    const config = loadAppConfig();
    config.network = cluster;
    saveAppConfig(config);
  };

  // =========================================================================
  // AUTH GATE: Only after user is authenticated do they see the whole product!
  // Unauthenticated users (or users previewing the homepage) see PublicHomepage
  // =========================================================================
  if (!connectedUser || showHomepagePreview) {
    return (
      <ErrorBoundary>
        <PublicHomepage
          existingUser={connectedUser}
          onReturnToWorkspace={
            connectedUser ? () => setShowHomepagePreview(false) : undefined
          }
          onAuthenticated={(profile) => {
            setConnectedUser(profile);
            setWorkspaceMode(profile.preferredMode || 'ease');
            setShowHomepagePreview(false);
            setShowWelcomeBanner(true);
            if (activeTransaction) {
              trainTransactionToKnowledgeGraph(activeTransaction, profile);
            }
          }}
        />
      </ErrorBoundary>
    );
  }

  const greeting = getISTGreeting(connectedUser.name);

  return (
    <ErrorBoundary>
      <div className="flex min-h-screen bg-[#090b10] text-slate-100 font-sans">
        {/* In Pro Mode, render the full 9-item Sidebar navigation */}
        {workspaceMode === 'pro' && (
          <Sidebar
            activeTab={activeTab}
            onTabChange={(tab) => {
              setActiveTab(tab);
              if (tab === 'settings') setIsSettingsOpen(true);
              logUserProductActivity({
                actionType: 'NAVIGATION',
                actionTitle: `Navigated to Pro Mode Tab: ${tab.toUpperCase()}`,
                targetId: tab,
                mode: 'pro',
                details: `Opened ${tab} view in Pro Mode`,
              });
            }}
            hasActiveTransaction={!!activeTransaction}
            activeSignature={activeTransaction?.signature}
            savedInvestigations={savedInvestigations}
            onSelectSavedTx={handleSelectSavedTx}
            totalAlertsCount={universalAlertsWithDispositions.length}
            onSwitchToInstantMode={() => handleWorkspaceModeChange('instant')}
          />
        )}

        <div className="flex-1 flex flex-col min-w-0">
          <Header
            currentCluster={currentCluster}
            onClusterChange={handleClusterChange}
            onOpenSettings={() => setIsSettingsOpen(true)}
            onSearchSignature={handleInvestigate}
            isInvestigating={isLoading}
            connectedUser={connectedUser}
            workspaceMode={workspaceMode}
            onWorkspaceModeChange={handleWorkspaceModeChange}
            userActivities={userActivities}
            persistentKg={persistentKg}
            onViewPublicHomepage={() => setShowHomepagePreview(true)}
            onSignOut={async () => {
              await disconnectGoogleAccount();
              setConnectedUser(null);
            }}
          />

          {/* Personalized IST Greeting / Wish & Database Session Telemetry Banner */}
          {showWelcomeBanner && (
            <div className="bg-gradient-to-r from-[#0c1626] via-[#0e1b2e] to-[#0c1626] border-b border-cyan-500/30 px-4 sm:px-6 py-2.5 flex flex-wrap items-center justify-between gap-3 text-xs">
              <div className="flex flex-wrap items-center gap-2.5">
                <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-md bg-emerald-500/15 border border-emerald-500/40 text-emerald-300 font-extrabold">
                  <Sparkles className="w-3.5 h-3.5 text-emerald-400" />
                  {greeting.salutation}
                </span>
                <span className="text-slate-300">
                  Connected Google Account:{' '}
                  <strong className="text-cyan-300 font-mono">{connectedUser.email}</strong>
                </span>
                <span className="text-slate-600 hidden md:inline">•</span>
                <span className="text-slate-300 hidden md:inline-flex items-center gap-1 font-mono text-[11px]">
                  <Globe className="w-3 h-3 text-cyan-400" />
                  IP Logged: <strong className="text-emerald-400">{connectedUser.ipAddress}</strong>
                </span>
                <span className="text-slate-600 hidden lg:inline">•</span>
                <span className="text-slate-300 hidden lg:inline-flex items-center gap-1 font-mono text-[11px]">
                  <Database className="w-3 h-3 text-amber-400" />
                  Persistent KG Trained: <strong className="text-amber-300">{persistentKg.lastTrainedIST}</strong>
                </span>
              </div>

              <div className="flex items-center gap-2">
                <span className="text-[11px] font-mono text-cyan-300 hidden sm:inline">
                  Active Mode: <strong>{workspaceMode.toUpperCase()} MODE</strong>
                </span>
                <button
                  type="button"
                  onClick={() => setShowWelcomeBanner(false)}
                  className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800/60 cursor-pointer"
                  title="Dismiss greeting banner"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          )}

          {/* MAIN WORKSPACE CONTENT: EASE MODE vs. INSTANT MODE vs. PRO MODE */}
          <main className="flex-1 pb-16">
            {workspaceMode === 'ease' ? (
              <EaseModeWorkspace
                activeTransaction={activeTransaction}
                onInvestigate={handleInvestigate}
                onSelectAddress={handleSelectAddress}
                onSwitchToProMode={() => handleWorkspaceModeChange('pro')}
                onSwitchToInstantMode={() => handleWorkspaceModeChange('instant')}
                isLoading={isLoading}
                progress={progress}
                error={error}
                persistentKg={persistentKg}
              />
            ) : workspaceMode === 'instant' ? (
              <InstantModeWorkspace
                onInvestigateSignature={handleInvestigate}
                onSelectAddress={handleSelectAddress}
                onSwitchToEaseMode={() => handleWorkspaceModeChange('ease')}
                onSwitchToProMode={() => handleWorkspaceModeChange('pro')}
              />
            ) : (
              <>
                {activeTab === 'search' && (
                  <SearchHero
                    onInvestigate={handleInvestigate}
                    onSelectAddress={handleSelectAddress}
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
                        label:
                          activeTransaction.accountsRegistry[addr]?.label ||
                          'Monitored Forensic Target',
                        addedAt: Date.now(),
                        notes: `Added from transaction ${(activeTransaction.signature || '').slice(
                          0,
                          12
                        )}...`,
                      });
                      logUserProductActivity({
                        actionType: 'MONITOR_ACCOUNT',
                        actionTitle: `Added Address ${addr.slice(0, 12)}... to Monitored Watchlist`,
                        targetId: addr,
                        mode: 'pro',
                        details: `Monitored from transaction ${activeTransaction.signature}`,
                      });
                    }}
                  />
                )}

                {activeTab === 'investigation' && !activeTransaction && (
                  <div className="max-w-2xl mx-auto px-4 py-16 text-center space-y-3">
                    <h3 className="text-base font-bold text-slate-300">No Active Case Selected</h3>
                    <p className="text-xs text-slate-500">
                      Enter a Solana transaction signature or select a sample case to start forensic
                      analysis.
                    </p>
                    <button
                      onClick={() => setActiveTab('search')}
                      className="px-4 py-2 bg-cyan-500 text-slate-950 text-xs font-bold rounded-xl cursor-pointer"
                    >
                      Go to Search
                    </button>
                  </div>
                )}

                {activeTab === 'alert-inbox' && (
                  <UniversalAlertInbox
                    alerts={universalAlertsWithDispositions}
                    incidents={engineEval.incidents}
                    activeTransaction={activeTransaction}
                    onUpdateDisposition={handleUpdateDisposition}
                    onInvestigateTransaction={handleInvestigate}
                    onSelectAddress={handleSelectAddress}
                  />
                )}

                {activeTab === 'asset-explorer' && (
                  <AssetProgramExplorer
                    onSelectAddress={handleSelectAddress}
                    onInvestigateTransaction={handleInvestigate}
                  />
                )}

                {activeTab === 'detection-console' && (
                  <DetectionEngineeringConsole
                    rules={detectionRules}
                    onUpdateRules={setDetectionRules}
                  />
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
              </>
            )}
          </main>

          {/* Persistent Workspace Footer: Built by Sandeep Kumar Sahoo (Base64 Photo) */}
          <footer className="border-t border-slate-800/80 bg-[#070a10] px-4 sm:px-6 py-3 flex flex-wrap items-center justify-between gap-4 text-xs">
            <div className="flex items-center gap-3">
              <div className="relative shrink-0">
                <img
                  src={SANDEEP_PHOTO_BASE64}
                  alt="Sandeep Kumar Sahoo"
                  className="w-10 h-10 rounded-xl object-cover border-2 border-cyan-400/70 shadow-md shadow-cyan-500/20"
                />
                <span
                  className="absolute -bottom-0.5 -right-0.5 w-3 h-3 rounded-full bg-emerald-400 border-2 border-[#070a10]"
                  title="Base64 Embedded Creator Portrait"
                />
              </div>
              <div>
                <div className="flex items-center gap-1.5 text-[10px] font-mono font-bold text-cyan-400 uppercase tracking-wider">
                  <Sparkles className="w-3 h-3" />
                  <span>SOL-MATE FORENSICS • INSTITUTIONAL BLOCKCHAIN INTELLIGENCE</span>
                </div>
                <p className="text-xs text-slate-300 mt-0.5">
                  Built by <span className="text-white font-extrabold">Sandeep Kumar Sahoo</span>
                </p>
              </div>
            </div>

            <div className="flex items-center gap-3 text-[11px] font-mono text-slate-400">
              <span className="text-emerald-400">3x Parallel Mainnet RPC Pool</span>
              <span>•</span>
              <span>IST (Asia/Kolkata • UTC+05:30)</span>
            </div>
          </footer>
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
