/**
 * SOL-MATE — Forensic Domain Models
 * Rigorous representations for accounts, authority provenance, state deltas,
 * execution traces, byte forensics, token resolution, client onboarding, and alert lifecycles.
 */

import { Commitment, SolanaCluster } from './solana';

export type AddressCategory =
  | 'system-program'
  | 'spl-token-program'
  | 'native-loader'
  | 'dex-amm'
  | 'lending-liquidity'
  | 'compute-budget'
  | 'user-wallet'
  | 'token-account'
  | 'token-mint'
  | 'pda'
  | 'multisig'
  | 'address-lookup-table'
  | 'program'
  | 'unclassified';

export type AccountRole =
  | 'fee-payer'
  | 'signer'
  | 'writable'
  | 'readonly'
  | 'token-owner'
  | 'token-delegate'
  | 'mint-authority'
  | 'freeze-authority'
  | 'close-authority'
  | 'program-id'
  | 'program-derived-address'
  | 'address-lookup-table'
  | 'transfer-source'
  | 'transfer-destination';

export interface EvidenceReference {
  id: string;
  sourceMethod: string;
  fieldPath: string;
  transactionSignature?: string;
  accountAddress?: string;
  instructionIndex?: number;
  slot?: number;
  rawValue: unknown;
  interpretation: string;
  verificationStatus: 'verified' | 'derived' | 'uncertain';
  timestamp?: number;
}

export interface AccountRoleProof {
  role: AccountRole;
  title: string;
  reason: string;
  evidence: EvidenceReference;
}

export interface AccountRecord {
  address: string;
  label?: string;
  institutionalInfo?: {
    shortLabel: string;
    roleTitle: string;
    ecosystem: 'FACT_CORE' | 'MONY' | 'JLTXX';
    institution: string;
    protocol: string;
    description: string;
    securityStatus: 'WHITELISTED_INSTITUTIONAL';
  };
  category: AddressCategory;
  categoryConfidence: 'high' | 'medium' | 'low';
  roles: AccountRole[];
  roleProofs: AccountRoleProof[];
  isSigner: boolean;
  isWritable: boolean;
  isFeePayer: boolean;
  isExecutable: boolean;
  ownerProgram: string;
  ownerProgramLabel?: string;
  lamports: bigint;
  solBalance: number;
  preLamports?: bigint;
  postLamports?: bigint;
  deltaLamports?: bigint;
  deltaSol?: number;
  dataLength?: number;
  rentExemptionStatus?: 'exempt' | 'not-exempt' | 'unknown';
  tokenMetadata?: {
    isMint?: boolean;
    isTokenAccount?: boolean;
    mint?: string;
    mintSymbol?: string;
    mintName?: string;
    tokenOwner?: string;
    decimals?: number;
    supplyRaw?: string;
    mintAuthority?: string | null;
    freezeAuthority?: string | null;
    delegate?: string | null;
    delegatedAmount?: string;
    state?: 'initialized' | 'uninitialized' | 'frozen';
    tokenProgram: string;
    token2022Extensions?: string[];
  };
  liveStateFetched: boolean;
  liveFetchError?: string;
  observationSlot?: number;
  lastUpdatedTimestamp?: number;
}

export interface ByteForensics {
  rawEncoding: 'base58' | 'json-parsed' | 'empty';
  byteLength: number;
  hexPreview: string;
  anchorDiscriminatorHex?: string;
  innerEventDiscriminatorHex?: string;
  decodedU64Values: string[];
  decodedU32Values: number[];
  asciiPreview?: string;
  forensicNotes: string[];
}

export interface InstructionRecord {
  index: number;
  parentIndex?: number;
  programId: string;
  programName: string;
  decodedName: string;
  isDecoded: boolean;
  rawData: string;
  decodedDetails?: Record<string, unknown>;
  byteForensics?: ByteForensics;
  accountIndices: number[];
  resolvedAccounts: {
    address: string;
    label?: string;
    institutionalRole?: string;
    isSigner: boolean;
    isWritable: boolean;
    roleHint?: string;
  }[];
  innerInstructions: InstructionRecord[];
  stackHeight: number;
  computeUnits?: number;
  logs: string[];
  outcome: 'success' | 'failed' | 'unknown';
  relatedSolDeltaLamports?: bigint;
  relatedTokenDeltas?: TokenBalanceDelta[];
}

export interface SolBalanceDelta {
  address: string;
  label?: string;
  preLamports: bigint;
  postLamports: bigint;
  deltaLamports: bigint;
  preSol: number;
  postSol: number;
  deltaSol: number;
  isFeePayer: boolean;
  feeAmountLamports?: bigint;
  category: 'direct-transfer' | 'fee-deduction' | 'rent-funding' | 'rent-recovery' | 'net-change';
  explanation: string;
  evidence: EvidenceReference;
}

export interface TokenBalanceDelta {
  accountIndex: number;
  accountAddress: string;
  mint: string;
  mintSymbol?: string;
  mintName?: string;
  issuer?: string;
  owner: string;
  ownerLabel?: string;
  programId: string;
  programName?: string;
  preRawAmount: bigint;
  postRawAmount: bigint;
  deltaRawAmount: bigint;
  decimals: number;
  preUiAmount: number;
  postUiAmount: number;
  deltaUiAmount: number;
  actionType:
    | 'transfer-in'
    | 'transfer-out'
    | 'mint'
    | 'burn'
    | 'unchanged'
    | 'account-initialized'
    | 'account-closed';
  explanation: string;
  evidence: EvidenceReference;
}

export interface AuthorityRecord {
  authorityAddress: string;
  authorityLabel?: string;
  targetAddress: string;
  targetLabel?: string;
  targetType: 'token-mint' | 'token-account' | 'program' | 'multisig' | 'lookup-table' | 'pda';
  authorityType:
    | 'mint-authority'
    | 'freeze-authority'
    | 'owner-authority'
    | 'delegate'
    | 'close-authority'
    | 'upgrade-authority'
    | 'multisig-member'
    | 'institutional-agent'
    | 'event-authority-pda'
    | 'transfer-hook-authority';
  status: 'active' | 'revoked' | 'none' | 'unknown';
  securityImpact?: string;
  scopeDescription?: string;
  details?: Record<string, unknown>;
  evidence: EvidenceReference;
  isCurrentState: boolean;
}

export interface StateTransitionRecord {
  id: string;
  account: string;
  accountLabel?: string;
  fieldOrAsset: string;
  beforeState: string;
  afterState: string;
  rawDelta?: string;
  percentChange?: string;
  instructionRef: string;
  transitionType:
    | 'balance-change'
    | 'token-delta'
    | 'account-created'
    | 'account-closed'
    | 'authority-change'
    | 'delegate-approved'
    | 'freeze-thaw'
    | 'unreconstructable';
  evidence: EvidenceReference;
  confidence: 'verified-exact' | 'partially-inferred' | 'unreconstructable';
  notes?: string;
}

export interface AssetFlowEdge {
  id: string;
  source: string;
  sourceLabel?: string;
  destination: string;
  destinationLabel?: string;
  assetType: 'SOL' | 'SPL-TOKEN';
  mint?: string;
  symbol: string;
  tokenName?: string;
  rawAmount: string;
  formattedAmount: string;
  usdValueEstimate?: number;
  instructionIndex?: number;
  flowNature?: 'transfer' | 'institutional-issuance-mint' | 'redemption-burn';
  confidence: 'verified-direct' | 'inferred-economic-delta';
  evidence: EvidenceReference;
}

export type RelationshipType =
  | 'transferred-sol'
  | 'transferred-token'
  | 'minted-token'
  | 'burned-token'
  | 'owns-token-account'
  | 'mint-authority-of'
  | 'freeze-authority-of'
  | 'delegate-of'
  | 'invoked-program'
  | 'cpi-invoked'
  | 'created-account'
  | 'closed-account'
  | 'signed-for'
  | 'interacted-with'
  | 'institutional-governance';

export interface AccountRelationship {
  id: string;
  source: string;
  target: string;
  type: RelationshipType;
  label: string;
  asset?: string;
  amount?: string;
  confidence: 'verified' | 'derived' | 'uncertain';
  evidence: EvidenceReference;
}

export type RiskSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface RiskFinding {
  id: string;
  title: string;
  severity: RiskSeverity;
  ruleCategory:
    | 'authority-tampering'
    | 'unexpected-mint'
    | 'asset-drain'
    | 'token-freeze-risk'
    | 'cpi-anomaly'
    | 'failed-instructions'
    | 'delegate-exposure'
    | 'unverified-program'
    | 'rent-abnormal'
    | 'institutional-verified'
    | 'operational-clean';
  explanation: string;
  relevantAccounts: string[];
  relevantInstructions: number[];
  observedImpact: string;
  confidence: 'verified-fact' | 'heuristic-pattern' | 'contextual-observation';
  limitations: string;
  recommendedFollowUp: string;
  scoreImpact: number;
  evidence: EvidenceReference;
}

export interface ResolvedTokenInfo {
  mint: string;
  symbol: string;
  name: string;
  decimals: number;
  tokenProgram: string;
  tokenStandard: string;
  issuer?: string;
  isInstitutional: boolean;
  totalVolumeUi: number;
  totalVolumeRaw: string;
  holdersAffected: number;
  operationSummary: string;
  mintAuthority?: string | null;
  freezeAuthority?: string | null;
  supplyUi?: string;
  extensions?: string[];
}

export interface ClientOnboardingIntelligence {
  isClientOnboarded: boolean;
  onboardingStatus: 'CONFIRMED_ONBOARDING' | 'EXISTING_CLIENT_ACTIVITY' | 'NO_TOKEN_ONBOARDING';
  headline: string;
  clientWalletAddress: string;
  clientTokenAccountAddress: string;
  tokenMintAddress: string;
  tokenName: string;
  tokenSymbol: string;
  tokenStandard: string;
  initialBalanceBefore: string;
  provisionedAmount: string;
  resultingBalanceAfter: string;
  dispatcherAuthority: string;
  governingProgramId: string;
  governingProgramName: string;
  explanation: string;
  complianceIndicators: string[];
}

export interface CorrelatedLifecycleStage {
  stageNumber: number;
  phase: 'PREVIOUS_PREREQUISITE' | 'CURRENT_ACTIVE_ALERT' | 'NEXT_PREDICTED';
  alertCode: string;
  title: string;
  status: 'completed-prior' | 'active-current' | 'predicted-next';
  correlationType: string;
  involvedEntities: string[];
  description: string;
  triggerIndicator: string;
}

export interface IndependentAlertItem {
  id: string;
  alertCode: string;
  title: string;
  severity: RiskSeverity;
  category: string;
  whyIndependent: string;
  observation: string;
  affectedAddresses: string[];
  verificationField: string;
}

export interface AlertLifecycleIntelligence {
  primaryAlertType: string;
  primaryAlertSeverity: RiskSeverity;
  primaryAlertTitle: string;
  primaryAlertSummary: string;
  correlatedTokenDisplay: string;
  clientOnboarding: ClientOnboardingIntelligence;
  lifecycleStages: CorrelatedLifecycleStage[];
  independentAlerts: IndependentAlertItem[];
}

export interface AccountCorrelationRow {
  index: number;
  address: string;
  label: string;
  category: AddressCategory;
  isWhitelistedInstitutional: boolean;
  institutionalEcosystem?: 'FACT_CORE' | 'MONY' | 'JLTXX';
  institutionalRoleTitle?: string;
  isSigner: boolean;
  isWritable: boolean;
  isFeePayer: boolean;
  outerInstructionsInvolved: number[];
  cpiInstructionsInvolved: string[];
  solDeltaLamports: string;
  solDeltaFormatted: string;
  tokenDeltaFormatted: string;
  authorityProvenance: string;
}

export interface DeepForensicsCorrelation {
  isInstitutionalFactTx: boolean;
  activeEcosystem: 'JLTXX' | 'MONY' | 'FACT_CORE' | 'STANDARD';
  institutionName?: string;
  protocolSummary: string;
  whitelistedHitCount: number;
  computeBudgetAnalysis: {
    computeUnitLimit: number | null;
    computeUnitPriceMicroLamports: string | null;
    computeUnitsConsumed: number | null;
    computeEfficiencyPercent: number | null;
    baseSignatureFeeLamports: string;
    priorityFeeLamports: string;
    totalFeeLamports: string;
  };
  token2022Summary: {
    usesToken2022: boolean;
    invokesTransferHook: boolean;
    invokesAnchorSelfCpiEvent: boolean;
    eventAuthorityPdasUsed: string[];
    mintsInvolved: {
      mint: string;
      symbol: string;
      name: string;
      issuer?: string;
      decimals: number;
      netSupplyChangeRaw: string;
      netSupplyChangeUi: number;
      operationType: 'ISSUANCE_MINT' | 'REDEMPTION_BURN' | 'PEER_TRANSFER' | 'OBSERVED';
    }[];
  };
  accountCorrelationMatrix: AccountCorrelationRow[];
}

export interface TransactionRecord {
  signature: string;
  slot: number;
  blockTime: number | null;
  formattedTime: string;
  version: 'legacy' | 'v0' | string;
  cluster: SolanaCluster;
  commitment: Commitment;
  success: boolean;
  error: string | null;
  feeLamports: bigint;
  feeSol: number;
  recentBlockhash: string;
  computeUnitsConsumed: number | null;
  staticAccounts: string[];
  loadedWritableAddresses: string[];
  loadedReadonlyAddresses: string[];
  combinedAccounts: string[];
  signers: string[];
  feePayer: string;
  outerInstructions: InstructionRecord[];
  allInstructionsFlat: InstructionRecord[];
  accountsRegistry: Record<string, AccountRecord>;
  solBalanceDeltas: SolBalanceDelta[];
  tokenBalanceDeltas: TokenBalanceDelta[];
  resolvedTokens: ResolvedTokenInfo[];
  alertIntelligence: AlertLifecycleIntelligence;
  authorities: AuthorityRecord[];
  stateTransitions: StateTransitionRecord[];
  assetFlows: AssetFlowEdge[];
  relationships: AccountRelationship[];
  riskFindings: RiskFinding[];
  heuristicRiskScore: number; // 0 (safest) - 100 (critical risk)
  deepCorrelations: DeepForensicsCorrelation;
  evidenceCatalog: EvidenceReference[];
  rawTransactionJson?: string;
  retrievedAt: number;
  rpcEndpointUsed: string;
}

export interface RpcRequestMetric {
  id: string;
  timestamp: number;
  method: string;
  durationMs: number;
  status: 'success' | 'rate-limited' | 'network-error' | 'server-error';
  queueWaitMs: number;
}

export interface InvestigationReport {
  reportId: string;
  createdAt: number;
  signature: string;
  cluster: SolanaCluster;
  rpcEndpoint: string;
  analyst: string;
  version: string;
  executiveSummary: string;
  transaction: TransactionRecord;
  limitations: string[];
}

export interface TokenPriceFeed {
  symbol: string;
  name: string;
  mint?: string;
  priceUsd: number;
  change24h: number;
  high24h?: number;
  low24h?: number;
  volume24h?: number;
  marketCap?: number;
  lastUpdated: number;
}
