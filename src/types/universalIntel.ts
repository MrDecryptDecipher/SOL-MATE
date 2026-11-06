/**
 * SOL-MATE — Universal Blockchain Alert Intelligence & Forensics Engine Types
 * Implements:
 * - Phase 2: Chain-Agnostic Universal Transaction Envelope & Protocol Adapter Interfaces
 * - Phase 3: Operating Modes, Flexible Entity Registry & Epistemic Provenance
 * - Phase 4: Versioned Detection Rule Schema across Categories A–G
 * - Phase 5: Solana Custom Token Workflows (JLTXX, MONY, Burn Workflow State Machine, Stop-Code Transitions)
 * - Phase 6: EVM & Smart Contract Security Coverage (ERC-20/721/1155, EIP-1967 Proxy, EIP-2535 DiamondCut)
 * - Phase 7: Multi-Event Incident Correlation & Unknown Transaction Intelligence
 * - Phase 8 & 9: 10-Part Analyst Explanations, Independent Severity & Confidence, Analyst Dispositions
 */

export type SupportedChain =
  | 'solana-mainnet'
  | 'solana-devnet'
  | 'solana-testnet'
  | 'ethereum-mainnet'
  | 'evm-institutional-subnet';

export type OperatingMode =
  | 'NETWORK_MONITORING'
  | 'ADDRESS_MONITORING'
  | 'ASSET_MONITORING'
  | 'TRANSACTION_INVESTIGATION'
  | 'PROGRAM_CONTRACT_MONITORING'
  | 'CLIENT_AWARE_MONITORING'
  | 'EXPLORATORY_INVESTIGATION';

/**
 * Epistemic Provenance Classification (Phase 3.3 & Phase 9.2):
 * Explicitly distinguishes verified on-chain facts from policy expectations and inferences.
 */
export type EvidenceEpistemicStatus =
  | 'CONFIRMED_ONCHAIN_FACT'
  | 'VERIFIED_CONTRACT_SEMANTICS'
  | 'CONFIGURED_POLICY_EXPECTATION'
  | 'HISTORICAL_OBSERVATION'
  | 'STATISTICAL_ANOMALY'
  | 'ANALYST_INFERENCE'
  | 'UNVERIFIED_LABEL';

/**
 * Alert Severity (Impact if malicious/unintended) — kept strictly independent of Detection Confidence.
 */
export type AlertSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/**
 * Detection Confidence (Certainty that the decoded behavior occurred as described) — kept strictly independent of Alert Severity.
 */
export type DetectionConfidence = 'confirmed' | 'high' | 'medium' | 'low' | 'heuristic';

/**
 * Analyst Disposition States (Phase 9.3)
 */
export type AnalystDisposition =
  | 'UNREVIEWED'
  | 'EXPECTED_AUTHORISED'
  | 'FALSE_POSITIVE'
  | 'SUSPICIOUS_INVESTIGATION_REQUIRED'
  | 'CONFIRMED_UNAUTHORISED_ACTIVITY'
  | 'ESCALATED'
  | 'INSUFFICIENT_EVIDENCE';

export type DetectionCategoryCode =
  | 'CATEGORY_A_ASSET_LIFECYCLE'
  | 'CATEGORY_B_VALUE_MOVEMENT'
  | 'CATEGORY_C_AUTHORITY_PERMISSIONS'
  | 'CATEGORY_D_ADMIN_PROTOCOL_STATE'
  | 'CATEGORY_E_EXECUTION_ACCESS_CONTROL'
  | 'CATEGORY_F_BEHAVIOURAL_RELATIONSHIP'
  | 'CATEGORY_G_DATA_INTEGRITY_HEALTH';

export type CanonicalActionType =
  | 'MINT_TO'
  | 'BURN_PREPARE_REQUEST'
  | 'BURN_APPROVE'
  | 'BURN_EXECUTION'
  | 'TRANSFER'
  | 'TRANSFER_CHECKED'
  | 'APPROVE_DELEGATE'
  | 'REVOKE_DELEGATE'
  | 'AUTHORITY_UPDATE'
  | 'FREEZE_ACCOUNT'
  | 'THAW_ACCOUNT'
  | 'CLOSE_ACCOUNT'
  | 'INITIALIZE_ACCOUNT'
  | 'SET_STOP_CODES'
  | 'PAUSE_STATE_CHANGE'
  | 'BLACKLIST_SANCTIONS_CHANGE'
  | 'PROXY_IMPLEMENTATION_UPGRADE'
  | 'DIAMOND_CUT_FACET_CHANGE'
  | 'TRANSFER_HOOK_INVOCATION'
  | 'ANCHOR_SELF_CPI_EVENT'
  | 'FAILED_PRIVILEGED_CALL'
  | 'UNKNOWN_CUSTOM_INSTRUCTION';

/**
 * Solana Custom Stop-Code Flags (Phase 5.2 & 5.4)
 */
export interface StopCodeFlags {
  stop_transfer_to: boolean;
  stop_transfer_from: boolean;
  stop_redemption_from: boolean;
  stop_subscription_to: boolean;
}

export interface StopCodeTransition {
  id: string;
  mintAddress: string;
  tokenSymbol: string;
  configPdaAddress: string;
  targetEntityAddress?: string;
  authoritySigner: string;
  programId: string;
  beforeFlags: StopCodeFlags;
  afterFlags: StopCodeFlags;
  changedFields: (keyof StopCodeFlags)[];
  transactionId: string;
  slotOrBlock: number;
  timestamp: number;
  isAuthorizedAuthority: boolean;
  epistemicStatus: EvidenceEpistemicStatus;
}

/**
 * Stateful Burn Workflow Integrity Model (Phase 5.3)
 * Models: prepare_burn (request) -> BurnApprove (approval) -> Burn / BurnChecked (execution + supply reduction)
 */
export type BurnLifecycleStage =
  | 'PREPARE_BURN_REQUESTED'
  | 'BURN_APPROVED'
  | 'BURN_EXECUTED_SUPPLY_REDUCED'
  | 'ANOMALOUS_APPROVAL_WITHOUT_REQUEST'
  | 'ANOMALOUS_AMOUNT_EXCEEDS_REQUEST'
  | 'ANOMALOUS_EXECUTION_WITHOUT_APPROVAL'
  | 'ANOMALOUS_BURN_WITHOUT_SUPPLY_REDUCTION';

export interface BurnWorkflowRecord {
  workflowId: string;
  mintAddress: string;
  tokenSymbol: string;
  tokenProgram: string;
  governingProgramId: string;
  holderWallet: string;
  holderTokenAccount: string;
  burnRequestPda?: string;
  requestedAmountRaw: string;
  requestedAmountUi: number;
  approvedAmountRaw?: string;
  approvedAmountUi?: number;
  burnedAmountRaw?: string;
  burnedAmountUi?: number;
  supplyBeforeRaw?: string;
  supplyAfterRaw?: string;
  verifiedSupplyReduced: boolean;
  stage: BurnLifecycleStage;
  prepareTxId?: string;
  approveTxId?: string;
  executeTxId?: string;
  approverAuthority?: string;
  anomaliesDetected: string[];
  updatedAt: number;
}

/**
 * Chain-Agnostic Universal Instruction / Call Frame (Phase 2.1)
 */
export interface UniversalCallFrame {
  frameId: string;
  index: number;
  parentIndex?: number;
  depth: number;
  targetProgramOrContract: string;
  targetName: string;
  callerAddress: string;
  canonicalAction: CanonicalActionType;
  decodedOperationName: string;
  selectorOrDiscriminatorHex?: string;
  rawInputHexOrBase58: string;
  decodedArguments: Record<string, unknown>;
  involvedAddresses: {
    address: string;
    role: string;
    isSigner: boolean;
    isWritable: boolean;
  }[];
  emittedEvents: {
    eventName: string;
    topicOrDiscriminator: string;
    fields: Record<string, unknown>;
  }[];
  outcome: 'success' | 'reverted' | 'unknown';
  decoderConfidence: DetectionConfidence;
}

/**
 * Chain-Agnostic Universal Balance / Supply Delta (Phase 2.1)
 */
export interface UniversalStateDelta {
  deltaId: string;
  deltaCategory: 'NATIVE_BALANCE' | 'TOKEN_BALANCE' | 'TOKEN_SUPPLY' | 'AUTHORITY_CONFIG' | 'STOP_CODE_CONFIG' | 'CONTRACT_SLOT';
  assetIdentifier: string; // Mint address, ERC-20 contract, or 'SOL' / 'ETH'
  assetSymbol: string;
  assetName: string;
  tokenStandard: 'SPL' | 'TOKEN_2022' | 'ERC20' | 'ERC721' | 'ERC1155' | 'NATIVE';
  subjectAddress: string;
  ownerAddress?: string;
  beforeValue: string;
  afterValue: string;
  netDelta: string;
  decimals: number;
  beforeUi?: number;
  afterUi?: number;
  netDeltaUi?: number;
  causedByFrameId?: string;
  epistemicStatus: EvidenceEpistemicStatus;
  rawProofFieldPath: string;
}

/**
 * Universal Transaction Envelope (Phase 2.1)
 * Unifies Solana (Legacy/v0, SPL, Token-2022, Custom Anchor/FACT) and EVM (EOA/SCA, Proxy, Diamond)
 */
export interface UniversalTransactionEnvelope {
  transactionId: string; // Base58 signature (Solana) or 0xKeccak256 hash (EVM)
  chain: SupportedChain;
  protocolFamily: 'SOLANA_SVM' | 'EVM';
  blockOrSlot: number;
  timestamp: number;
  formattedTimestamp: string;
  status: 'SUCCESS' | 'REVERTED';
  errorReason: string | null;
  feePayerOrSender: string;
  signers: string[];
  networkFeeRaw: string;
  networkFeeUi: string;
  computeOrGasUsed: number | null;
  callFrames: UniversalCallFrame[];
  stateDeltas: UniversalStateDelta[];
  stopCodeTransitions: StopCodeTransition[];
  burnWorkflowUpdates: BurnWorkflowRecord[];
  unknownInstructionsCount: number;
  decoderSummary: string;
  operatingModesSupported: OperatingMode[];
}

/**
 * Protocol Adapter Interface (Phase 2.2)
 */
export interface ChainProtocolAdapter<TRawInput = unknown> {
  readonly adapterId: string;
  readonly adapterName: string;
  readonly protocolFamily: 'SOLANA_SVM' | 'EVM';
  readonly supportedStandards: string[];
  normalizeTransaction(raw: TRawInput): UniversalTransactionEnvelope;
}

/**
 * 10-Part Analyst Explanation Structure (Phase 8)
 */
export interface TenPartAlertExplanation {
  observed: string;
  whatHappened: string;
  whyRuleFired: string;
  technicalInterpretation: string;
  securityImplications: string;
  evidence: {
    fieldPath: string;
    valueSummary: string;
    epistemicStatus: EvidenceEpistemicStatus;
  }[];
  context: {
    clientOnboardingNote: string;
    entityRegistryNote: string;
    operatingMode: OperatingMode;
  };
  severityAndConfidenceRationale: {
    severity: AlertSeverity;
    severityReason: string;
    confidence: DetectionConfidence;
    confidenceReason: string;
  };
  investigationChecklist: string[];
  recommendedResponse: string[];
}

/**
 * Universal Alert Record (Phases 4, 8, 9)
 */
export interface UniversalAlertRecord {
  alertId: string;
  deduplicationKey: string;
  ruleId: string;
  ruleVersion: string;
  ruleName: string;
  category: DetectionCategoryCode;
  canonicalAction: CanonicalActionType;
  chain: SupportedChain;
  transactionId: string;
  blockOrSlot: number;
  timestamp: number;
  severity: AlertSeverity;
  confidence: DetectionConfidence;
  epistemicStatus: EvidenceEpistemicStatus;
  disposition: AnalystDisposition;
  dispositionNotes?: string;
  dispositionUpdatedBy?: string;
  dispositionUpdatedAt?: number;
  title: string;
  summary: string;
  assetIdentifier?: string;
  assetSymbol?: string;
  assetName?: string;
  programOrContractId: string;
  programOrContractName: string;
  actorAddress: string;
  targetAddresses: string[];
  incidentId?: string;
  isClientOnboardingRelated: boolean;
  explanation: TenPartAlertExplanation;
}

/**
 * Multi-Event Incident Correlation Record (Phase 7.1)
 */
export interface IncidentRecord {
  incidentId: string;
  title: string;
  patternType:
    | 'MINT_DISTRIBUTION_ONWARD_TRANSFER'
    | 'BURN_REQUEST_APPROVAL_EXECUTION'
    | 'BURN_WORKFLOW_INTEGRITY_VIOLATION'
    | 'AUTHORITY_CHANGE_PRIVILEGED_ACTION'
    | 'STOP_CODE_CONFIG_CHANGE_RESTRICTED_OP'
    | 'REPEATED_FAILED_PRIVILEGED_CALLS'
    | 'PROXY_OR_DIAMOND_UPGRADE_EXECUTION'
    | 'RAPID_FAN_OUT_DRAIN';
  chain: SupportedChain;
  severity: AlertSeverity;
  confidence: DetectionConfidence;
  status: 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED_EXPECTED';
  firstSeenTimestamp: number;
  lastSeenTimestamp: number;
  involvedAssets: { identifier: string; symbol: string; name: string }[];
  involvedAddresses: string[];
  involvedTransactions: string[];
  correlatedAlertIds: string[];
  lifecycleTimeline: {
    stepOrder: number;
    stageLabel: string;
    transactionId: string;
    blockOrSlot: number;
    timestamp: number;
    actionSummary: string;
    status: 'VERIFIED_COMPLETED' | 'ACTIVE_ANOMALY' | 'EXPECTED_NEXT_STEP';
  }[];
  narrativeSummary: string;
  recommendedPlaybook: string[];
}

/**
 * Versioned Detection Rule Schema (Phase 4.1)
 */
export interface DetectionRuleCondition {
  field: string;
  operator:
    | 'EQUALS'
    | 'NOT_EQUALS'
    | 'IN'
    | 'GREATER_THAN'
    | 'LESS_THAN'
    | 'CONTAINS'
    | 'STATE_TRANSITION'
    | 'EXISTS';
  value: unknown;
  description: string;
}

export interface DetectionRuleVersionSnapshot {
  version: string;
  updatedAt: number;
  author: string;
  changelog: string;
  severity: AlertSeverity;
  confidence: DetectionConfidence;
  enabled: boolean;
  thresholdConfig: Record<string, number | string | boolean>;
}

export interface DetectionRule {
  ruleId: string;
  name: string;
  category: DetectionCategoryCode;
  version: string;
  status: 'ENABLED' | 'DISABLED' | 'DRAFT';
  supportedChains: SupportedChain[];
  targetStandards: ('SPL' | 'TOKEN_2022' | 'ERC20' | 'ERC721' | 'ERC1155' | 'PROXY' | 'DIAMOND' | 'NATIVE' | 'ANY')[];
  targetMintsOrContracts: string[]; // Empty array means universal / applies to all assets
  description: string;
  conditions: DetectionRuleCondition[];
  thresholdConfig: Record<string, number | string | boolean>;
  defaultSeverity: AlertSeverity;
  defaultConfidence: DetectionConfidence;
  deduplicationWindowSeconds: number;
  mitigationGuidance: string[];
  versionHistory: DetectionRuleVersionSnapshot[];
}

/**
 * Historical Fixture & Rule Replay Evaluation Result (Phase 4.1 & Phase 11)
 */
export interface RuleReplayFixture {
  fixtureId: string;
  title: string;
  description: string;
  chain: SupportedChain;
  category: DetectionCategoryCode;
  isMaliciousOrAnomalous: boolean;
  expectedRuleIds: string[];
  envelope: UniversalTransactionEnvelope;
}

export interface RuleEngineEvaluationMetrics {
  totalFixturesEvaluated: number;
  totalAlertsGenerated: number;
  truePositives: number;
  falsePositives: number;
  falseNegatives: number;
  precisionPercent: number;
  recallPercent: number;
  falsePositiveRatePercent: number;
  categoryCoverageCount: Record<DetectionCategoryCode, number>;
  decoderSuccessRatePercent: number;
}

/**
 * Monitored Asset & Program Profile for Asset & Program Explorer (Phase 3.2, 5, 6, 10.2)
 */
export interface AssetProgramProfile {
  identifier: string;
  symbol: string;
  name: string;
  chain: SupportedChain;
  entityType: 'SOLANA_TOKEN_2022_MINT' | 'SOLANA_SPL_MINT' | 'SOLANA_CUSTOM_PROGRAM' | 'EVM_TOKEN_PROXY' | 'EVM_DIAMOND_CONTRACT';
  tokenProgramOrImplementation: string;
  governingControllerProgram?: string;
  decimals?: number;
  currentSupplyUi: string;
  mintAuthority: string | null;
  freezeAuthority: string | null;
  upgradeOrOwnerAuthority: string | null;
  transferHookProgramId?: string | null;
  extraAccountMetaListPda?: string | null;
  configPdaAddress?: string | null;
  factAuthorityPda?: string | null;
  extensionsOrFacets: string[];
  stopCodeState?: StopCodeFlags;
  activeBurnWorkflows: BurnWorkflowRecord[];
  recentAuthorityChanges: {
    timestamp: number;
    txId: string;
    authorityType: string;
    previousAuthority: string;
    newAuthority: string;
    authorized: boolean;
  }[];
  monitoringCoverage: {
    mintBurnCovered: boolean;
    authorityChangesCovered: boolean;
    stopCodesCovered: boolean;
    burnStateMachineCovered: boolean;
    unknownInstructionFallback: boolean;
    activeRuleIds: string[];
  };
}
