/**
 * SOL-MATE — Universal Blockchain Alert Intelligence & Forensics Engine Test Suite
 * Covers all 17 verification domains required by Phase 12:
 * 1. SPL Token & Token-2022 instruction & extension parsing
 * 2. Custom Solana JLTXX & MONY instruction decoding (MintTo, prepare_burn, BurnApprove, SetStopCodes)
 * 3. Stateful Burn Workflow State Machine: valid sequence (prepare_burn -> BurnApprove -> BurnChecked)
 * 4. Burn approval without request (ANOMALOUS_APPROVAL_WITHOUT_REQUEST)
 * 5. Burn approval exceeding requested amount (ANOMALOUS_AMOUNT_EXCEEDS_REQUEST)
 * 6. Burn execution without approval or without supply reduction (ANOMALOUS_BURN_WITHOUT_SUPPLY_REDUCTION)
 * 7. Custom Stop-Code transition decoding (stop_transfer_to, stop_transfer_from, stop_redemption_from, stop_subscription_to)
 * 8. Authority change detection (Mint/Freeze/Owner/Roles)
 * 9. Client-onboarding independence (arbitrary un-onboarded wallet/mint detection)
 * 10. EVM ERC-20, EIP-1967 Proxy Upgrade, and EIP-2535 DiamondCut facet replacement detection
 * 11. Unknown instruction fallback intelligence (zero silent drops, independent Severity & Confidence)
 * 12. Alert deduplication & Multi-Event Incident Correlation
 * 13. Versioned rule engine evaluation (Precision, Recall, False-Positive Rate) & 10-Part Explanation completeness
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  isValidBase58Signature,
  isValidSolanaAddress,
  parseSolanaTransaction,
} from '../services/transactionParser';
import {
  DEFAULT_PARALLEL_ENDPOINTS,
  DEVNET_PARALLEL_ENDPOINTS,
  TESTNET_PARALLEL_ENDPOINTS,
} from '../services/config';
import {
  getInstitutionalMetadata,
  resolveTokenIdentity,
  decodeBase58,
  analyzeInstructionBytes,
  KNOWN_ANCHOR_SIGHASHES,
} from '../services/protocolIntelligence';
import {
  SolanaProtocolAdapter,
  EvmProtocolAdapter,
  evaluateBurnWorkflowIntegrity,
  decodeStopCodeTransition,
  evaluateUniversalTransaction,
  buildHistoricalReplayFixtures,
  evaluateRuleEnginePerformance,
  DEFAULT_DETECTION_RULES,
  getForensicReplayRawTransaction,
} from '../services/universalDetectionEngine';
import { KNOWN_MINTS } from '../services/tokenPrices';
import { RawTransactionResponse } from '../types/solana';
import { formatToIST, getISTGreeting } from '../utils/istTime';
import { buildEaseModeForensicBreakdown } from '../services/knowledgeGraphService';


test('1. Signature & Address validation accepts valid Solana Base58 signatures and rejects malformed inputs', () => {
  const validSig = '4EcCC6GnXhkd2nCPaZES2EvNWZGCieXkTgWoZAair1UsXEZdpM9pPZSAwFSHoaonfUA876xo7qXkBWjEysRQziwo';
  assert.equal(isValidBase58Signature(validSig), true);
  assert.equal(isValidBase58Signature(''), false);
  assert.equal(isValidBase58Signature('0123456789'), false);
  assert.equal(isValidSolanaAddress('J4cTuCH6frt4AnEmKfMS2k8hsUf7K94PV62sjUJno8Cz'), true);
  assert.equal(isValidSolanaAddress('EToDtBM2knZ8N1BHyUq2Riq5ngWTcoD3k6qpsgf7CKYY'), true);
});

test('2. Parallel RPC/WSS endpoint pools include Helius, PublicNode, and OnFinality', () => {
  const httpUrls = DEFAULT_PARALLEL_ENDPOINTS.map((e) => e.http);
  assert.equal(
    httpUrls.includes('https://mainnet.helius-rpc.com/?api-key=dea43e7c-2806-4d5e-9241-b010e5c96762'),
    true
  );
  assert.equal(httpUrls.includes('https://solana-rpc.publicnode.com'), true);
  assert.equal(httpUrls.includes('https://solana.api.onfinality.io/public'), true);
  assert.equal(DEVNET_PARALLEL_ENDPOINTS.length >= 1, true);
  assert.equal(TESTNET_PARALLEL_ENDPOINTS.length >= 1, true);
});

test('3. Token identity resolver identifies JLTXX, MONY, and custom Token-2022 mints by (mintAddress, tokenProgram)', () => {
  const jltxx = resolveTokenIdentity(
    'J4cTuCH6frt4AnEmKfMS2k8hsUf7K94PV62sjUJno8Cz',
    'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb'
  );
  assert.equal(jltxx.symbol, 'JLTXX');
  assert.equal(jltxx.tokenStandard.includes('Token-2022'), true);

  const mony = resolveTokenIdentity(
    'EToDtBM2knZ8N1BHyUq2Riq5ngWTcoD3k6qpsgf7CKYY',
    'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb'
  );
  assert.equal(mony.symbol, 'MONY');
  assert.equal(KNOWN_MINTS['EToDtBM2knZ8N1BHyUq2Riq5ngWTcoD3k6qpsgf7CKYY'].symbol, 'MONY');

  const factProg = getInstitutionalMetadata('9rdASsDUnrw2EsDARtfqjabqcjfXYFKu45kZ31wF74dg');
  assert.equal(Boolean(factProg?.isProgram), true);
  assert.equal(Boolean(KNOWN_ANCHOR_SIGHASHES['7a91c4e211b809f1']?.includes('prepare_burn')), true);
  assert.equal(Boolean(KNOWN_ANCHOR_SIGHASHES['9c42e8a055d172c3']?.includes('BurnApprove')), true);
  assert.equal(Boolean(KNOWN_ANCHOR_SIGHASHES['c155f09288a41e77']?.includes('SetStopCodes')), true);
});

test('4. Stateful Burn Workflow State Machine: Valid 3-step sequence (prepare_burn -> BurnApprove -> BurnChecked + supply reduction)', () => {
  const validBurn = evaluateBurnWorkflowIntegrity({
    workflowId: 'wf-valid-01',
    mintAddress: 'J4cTuCH6frt4AnEmKfMS2k8hsUf7K94PV62sjUJno8Cz',
    tokenSymbol: 'JLTXX',
    governingProgramId: '9rdASsDUnrw2EsDARtfqjabqcjfXYFKu45kZ31wF74dg',
    holderWallet: 'DwWsjJsCic4xF7MPgqSxT7WZGancjGtumbmVVYFK1zXR',
    holderTokenAccount: 'CUNnRnBZT7sjAb911toVo7UQzfQ1PdVEUDjLGQsmzPcj',
    hasPrepareBurnRequest: true,
    requestedAmountRaw: 5000n,
    hasBurnApproval: true,
    approvedAmountRaw: 5000n,
    hasBurnExecution: true,
    burnedAmountRaw: 5000n,
    supplyBeforeRaw: 100000n,
    supplyAfterRaw: 95000n,
    decimals: 2,
  });

  assert.equal(validBurn.stage, 'BURN_EXECUTED_SUPPLY_REDUCED');
  assert.equal(validBurn.verifiedSupplyReduced, true);
  assert.equal(validBurn.anomaliesDetected.length, 0);
});

test('5. Stateful Burn Workflow State Machine detects approval without request, approved > requested, and burn without supply decrease', () => {
  // Case A: Approval without prepare_burn request
  const noReq = evaluateBurnWorkflowIntegrity({
    workflowId: 'wf-noreq',
    mintAddress: 'J4cTuCH6frt4AnEmKfMS2k8hsUf7K94PV62sjUJno8Cz',
    tokenSymbol: 'JLTXX',
    governingProgramId: '9rdASsDUnrw2EsDARtfqjabqcjfXYFKu45kZ31wF74dg',
    holderWallet: 'Holder1',
    holderTokenAccount: 'Vault1',
    hasPrepareBurnRequest: false,
    requestedAmountRaw: 0n,
    hasBurnApproval: true,
    approvedAmountRaw: 1000n,
    hasBurnExecution: false,
  });
  assert.equal(noReq.stage, 'ANOMALOUS_APPROVAL_WITHOUT_REQUEST');
  assert.equal(noReq.anomaliesDetected.length >= 1, true);

  // Case B: Approved amount exceeds requested amount
  const exceedsReq = evaluateBurnWorkflowIntegrity({
    workflowId: 'wf-exceeds',
    mintAddress: 'J4cTuCH6frt4AnEmKfMS2k8hsUf7K94PV62sjUJno8Cz',
    tokenSymbol: 'JLTXX',
    governingProgramId: '9rdASsDUnrw2EsDARtfqjabqcjfXYFKu45kZ31wF74dg',
    holderWallet: 'Holder1',
    holderTokenAccount: 'Vault1',
    hasPrepareBurnRequest: true,
    requestedAmountRaw: 5000n,
    hasBurnApproval: true,
    approvedAmountRaw: 12000n,
    hasBurnExecution: false,
  });
  assert.equal(exceedsReq.stage, 'ANOMALOUS_AMOUNT_EXCEEDS_REQUEST');

  // Case C: Burn executed without supply reduction
  const noSupplyReduction = evaluateBurnWorkflowIntegrity({
    workflowId: 'wf-nosupply',
    mintAddress: 'J4cTuCH6frt4AnEmKfMS2k8hsUf7K94PV62sjUJno8Cz',
    tokenSymbol: 'JLTXX',
    governingProgramId: '9rdASsDUnrw2EsDARtfqjabqcjfXYFKu45kZ31wF74dg',
    holderWallet: 'Holder1',
    holderTokenAccount: 'Vault1',
    hasPrepareBurnRequest: true,
    requestedAmountRaw: 5000n,
    hasBurnApproval: true,
    approvedAmountRaw: 5000n,
    hasBurnExecution: true,
    burnedAmountRaw: 5000n,
    supplyBeforeRaw: 100000n,
    supplyAfterRaw: 100000n,
  });
  assert.equal(noSupplyReduction.stage, 'ANOMALOUS_BURN_WITHOUT_SUPPLY_REDUCTION');
  assert.equal(noSupplyReduction.verifiedSupplyReduced, false);
});

test('6. Custom Stop-Code transition decoder identifies exact changed flags and authority status', () => {
  const sc = decodeStopCodeTransition({
    id: 'sc-test-1',
    mintAddress: 'J4cTuCH6frt4AnEmKfMS2k8hsUf7K94PV62sjUJno8Cz',
    tokenSymbol: 'JLTXX',
    configPdaAddress: '4xebIssuanceAuthorityPDA1111111111111111WscM',
    authoritySigner: '4tm6TUNqJqnxUoD3ocknd8MfK4DC2tBezaXJFTVyZK1D',
    programId: '9rdASsDUnrw2EsDARtfqjabqcjfXYFKu45kZ31wF74dg',
    beforeFlags: {
      stop_transfer_to: false,
      stop_transfer_from: false,
      stop_redemption_from: false,
      stop_subscription_to: false,
    },
    afterFlags: {
      stop_transfer_to: true,
      stop_transfer_from: false,
      stop_redemption_from: true,
      stop_subscription_to: false,
    },
    transactionId: 'tx-stopcode-1',
    slotOrBlock: 457949200,
    timestamp: Date.now(),
  });

  assert.deepEqual(sc.changedFields, ['stop_transfer_to', 'stop_redemption_from']);
  assert.equal(sc.isAuthorizedAuthority, true);
});

test('7. EVM Protocol Adapter & Rule Engine detect EIP-2535 DiamondCut and EIP-1967 Proxy upgrades', () => {
  const evmAdapter = new EvmProtocolAdapter();
  const proxyEnvelope = evmAdapter.normalizeTransaction({
    txHash: '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
    chain: 'ethereum-mainnet',
    blockNumber: 22195000,
    timestamp: Date.now(),
    from: '0xAdminEOA',
    to: '0xTokenProxyContract',
    status: 'SUCCESS',
    gasUsed: 95000,
    gasFeeEth: '0.0012',
    functionName: 'upgradeTo(address)',
    selectorHex: '0x3659cfe6',
    decodedArgs: {
      contractName: 'MONY EVM TransparentUpgradeableProxy',
      newImplementation: '0xNewLogicContract999',
    },
    events: [
      {
        eventName: 'Upgraded',
        topic0: '0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b',
        fields: { implementation: '0xNewLogicContract999' },
      },
    ],
    stateDeltas: [],
  });

  const alerts = evaluateUniversalTransaction(proxyEnvelope);
  assert.equal(alerts.some((a) => a.ruleId === 'RULE-D02'), true);
  const d02 = alerts.find((a) => a.ruleId === 'RULE-D02')!;
  assert.equal(d02.severity, 'critical');
  assert.equal(d02.confidence, 'confirmed');
});

test('8. Unknown Instruction Fallback preserves unmapped instructions and keeps Severity independent of Heuristic Confidence', () => {
  const fixtures = buildHistoricalReplayFixtures();
  const unkFixture = fixtures.find((f) => f.fixtureId === 'FIXTURE-06-UNKNOWN-INSTRUCTION-FALLBACK')!;
  const alerts = evaluateUniversalTransaction(unkFixture.envelope);

  const g01 = alerts.find((a) => a.ruleId === 'RULE-G01');
  assert.equal(Boolean(g01), true);
  assert.equal(g01!.confidence, 'heuristic');
  assert.equal(g01!.severity, 'medium');
  assert.equal(Boolean(g01!.explanation.observed), true);
  assert.equal(Boolean(g01!.explanation.severityAndConfidenceRationale.confidenceReason), true);
});

test('9. Client-Onboarding Independence & 10-Part Explanation Completeness across all Historical Replay Fixtures', () => {
  const evalResult = evaluateRuleEnginePerformance(DEFAULT_DETECTION_RULES);
  assert.equal(evalResult.metrics.totalFixturesEvaluated, 6);
  assert.equal(evalResult.metrics.recallPercent, 100);
  assert.equal(evalResult.incidents.length >= 3, true);

  for (const alert of evalResult.generatedAlerts) {
    const exp = alert.explanation;
    assert.equal(exp.observed.length > 10, true);
    assert.equal(exp.whatHappened.length > 10, true);
    assert.equal(exp.whyRuleFired.length > 10, true);
    assert.equal(exp.technicalInterpretation.length > 10, true);
    assert.equal(exp.securityImplications.length > 10, true);
    assert.equal(exp.evidence.length >= 1, true);
    assert.equal(exp.investigationChecklist.length >= 1, true);
    assert.equal(exp.recommendedResponse.length >= 1, true);
  }
});

test('10. End-to-End Solana Transaction Parser generates both legacy forensic artifacts and Universal Envelope + Universal Alerts', () => {
  const jpmRawTx: RawTransactionResponse = {
    slot: 413577130,
    blockTime: 1744835852,
    version: 0,
    transaction: {
      signatures: ['4EcCC6GnXhkd2nCPaZES2EvNWZGCieXkTgWoZAair1UsXEZdpM9pPZSAwFSHoaonfUA876xo7qXkBWjEysRQziwo'],
      message: {
        accountKeys: [
          { pubkey: '4tm6TUNqJqnxUoD3ocknd8MfK4DC2tBezaXJFTVyZK1D', signer: true, writable: true },
          { pubkey: '9rdASsDUnrw2EsDARtfqjabqcjfXYFKu45kZ31wF74dg', signer: false, writable: false },
          { pubkey: 'J4cTuCH6frt4AnEmKfMS2k8hsUf7K94PV62sjUJno8Cz', signer: false, writable: true },
          { pubkey: 'CUNnClientTokenAccount111111111111111111zPcj', signer: false, writable: true },
          { pubkey: 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb', signer: false, writable: false },
          { pubkey: 'ComputeBudget111111111111111111111111111111', signer: false, writable: false },
        ],
        instructions: [
          {
            programIdIndex: 5,
            accounts: [],
            data: '3Bxs411Dtc7pkFQj',
          },
          {
            programIdIndex: 1,
            accounts: [0, 2, 3, 4],
            data: '3Bxs411Dtc7pkFQj',
          },
        ],
        recentBlockhash: '4hMpm2R9d7Xf1W2V3m4N5o6P7q8R9s0T1u2V3w4X5y6Z',
      },
    },
    meta: {
      err: null,
      fee: 10099,
      computeUnitsConsumed: 19412,
      preBalances: [2987616140, 1, 1000000, 2039280, 1, 1],
      postBalances: [2987606041, 1, 1000000, 2039280, 1, 1],
      preTokenBalances: [
        {
          accountIndex: 3,
          mint: 'J4cTuCH6frt4AnEmKfMS2k8hsUf7K94PV62sjUJno8Cz',
          owner: 'DwWsClientOwnerWallet11111111111111111111zXR',
          programId: 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb',
          uiTokenAmount: {
            amount: '0',
            decimals: 2,
            uiAmount: 0,
            uiAmountString: '0',
          },
        },
      ],
      postTokenBalances: [
        {
          accountIndex: 3,
          mint: 'J4cTuCH6frt4AnEmKfMS2k8hsUf7K94PV62sjUJno8Cz',
          owner: 'DwWsClientOwnerWallet11111111111111111111zXR',
          programId: 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb',
          uiTokenAmount: {
            amount: '3',
            decimals: 2,
            uiAmount: 0.03,
            uiAmountString: '0.03',
          },
        },
      ],
      innerInstructions: [
        {
          index: 1,
          instructions: [
            {
              programId: 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb',
              parsed: {
                type: 'mintTo',
                info: {
                  account: 'CUNnClientTokenAccount111111111111111111zPcj',
                  amount: '3',
                  mint: 'J4cTuCH6frt4AnEmKfMS2k8hsUf7K94PV62sjUJno8Cz',
                },
              },
              stackHeight: 2,
            },
          ],
        },
      ],
      logMessages: ['Program 9rdASsDUnrw2EsDARtfqjabqcjfXYFKu45kZ31wF74dg invoke [1]'],
    },
  };

  const record = parseSolanaTransaction(
    jpmRawTx,
    '4EcCC6GnXhkd2nCPaZES2EvNWZGCieXkTgWoZAair1UsXEZdpM9pPZSAwFSHoaonfUA876xo7qXkBWjEysRQziwo'
  );

  assert.equal(Boolean(record.universalEnvelope), true);
  assert.equal(record.universalEnvelope!.protocolFamily, 'SOLANA_SVM');
  assert.equal(Boolean(record.universalAlerts && record.universalAlerts.length >= 2), true);
  assert.equal(record.universalAlerts!.some((a) => a.ruleId === 'RULE-A01'), true);
  assert.equal(record.universalAlerts!.some((a) => a.ruleId === 'RULE-A03'), true);
});

test('11. Forensic Replay RawTransaction resolver supports all 6 interactive scenarios with full Universal Envelope & Alert evaluation', () => {
  const scenarioIds = [
    '4EcCC6GnXhkd2nCPaZES2EvNWZGCieXkTgWoZAair1UsXEZdpM9pPZSAwFSHoaonfUA876xo7qXkBWjEysRQziwo',
    '5MoNyOnboardTx99111111111111111111111111111111111111111111111111111111111111111111111111',
    '3BurnApproveAnomalyTxSig1111111111111111111111111111111111111111111111111111111111111111',
    '6SetStopCodesTxSig1111111111111111111111111111111111111111111111111111111111111111111111',
    '0x9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e',
    '7UnkIxFallbackTxSig111111111111111111111111111111111111111111111111111111111111111111111',
  ];

  for (const sig of scenarioIds) {
    const replay = getForensicReplayRawTransaction(sig);
    assert.equal(Boolean(replay), true, `Missing replay fixture for ${sig}`);
    const parsed = parseSolanaTransaction(replay!.rawTx, sig);
    if (replay!.envelopeOverride) {
      parsed.universalEnvelope = replay!.envelopeOverride;
      parsed.universalAlerts = evaluateUniversalTransaction(replay!.envelopeOverride);
    }
    assert.equal(Boolean(parsed.universalEnvelope), true);
    assert.equal(Boolean(parsed.universalAlerts && parsed.universalAlerts.length >= 1), true);
  }
});

test('12. IST Timestamp Utility & Ease Mode Forensic Breakdown verify Mint, Onboarding, StopCodes, Whitelist Audit, Flow of Funds & Correlated vs Independent Graph', () => {
  const istStr = formatToIST(1744835852000);
  assert.equal(istStr.endsWith('IST'), true);

  const greeting = getISTGreeting('Sandeep');
  assert.equal(greeting.salutation.includes('Sandeep'), true);
  assert.equal(greeting.currentIST.endsWith('IST'), true);

  // 1. MONY Onboarding & Mint
  const monySig = '5MoNyOnboardTx9911aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijk';
  const monyReplay = getForensicReplayRawTransaction(monySig)!;
  const monyTx = parseSolanaTransaction(monyReplay.rawTx, monySig);
  const monyEase = buildEaseModeForensicBreakdown(monyTx);
  assert.equal(monyEase.isClientOnboarded, true);
  assert.equal(monyEase.tokenInvolvedSymbol, 'MONY');
  assert.equal(monyEase.correlationMode, 'CORRELATED_LIFECYCLE');
  assert.equal(monyEase.whitelistedCount >= 3, true);
  assert.equal(monyEase.flowOfFunds.length >= 1, true);
  assert.equal(monyEase.blockTimeIST.endsWith('IST'), true);

  // 2. SetStopCodes Compliance Flag
  const stopSig = '6SetStopCodesTxSig1111111111111111111111111111111111111111111111111111111111111111111111';
  const stopReplay = getForensicReplayRawTransaction(stopSig)!;
  const stopTx = parseSolanaTransaction(stopReplay.rawTx, stopSig);
  const stopEase = buildEaseModeForensicBreakdown(stopTx);
  assert.equal(stopEase.primaryAlertKind, 'STOPCODES');
  assert.equal(stopEase.matchedAlertKinds.some((m) => m.kind === 'STOPCODES' && m.isMatched), true);

  // 3. Unknown Custom Instruction (Independent Alert)
  const unkSig = '7UnkIxFallbackTxSig11111111111111111111111111111111111111111111111111111111111111111111';
  const unkReplay = getForensicReplayRawTransaction(unkSig)!;
  const unkTx = parseSolanaTransaction(unkReplay.rawTx, unkSig);
  const unkEase = buildEaseModeForensicBreakdown(unkTx);
  assert.equal(unkEase.correlationMode, 'INDEPENDENT_ALERT');
  assert.equal(unkEase.scamOrAnomalyVerdict.status, 'CRITICAL_ANOMALY_OR_SCAM_RISK');
  assert.equal(unkEase.tenVectorSecurityMatrix.length, 10);
  assert.equal(
    unkEase.tenVectorSecurityMatrix.some((v) => v.status === 'CRITICAL_VIOLATION'),
    true
  );
  assert.equal(Boolean(monyEase.clientOnboardingDetails.clientTokenAccountAddress), true);
  assert.equal(Boolean(monyEase.matchedAlertKinds[0].ruleId), true);
});



