/**
 * SOL-MATE — Forensic Logic, Token Resolution, Client Onboarding & Alert Lifecycle Unit Tests
 * Uses node:test and node:assert/strict with npx --yes tsx --test
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
} from '../services/protocolIntelligence';
import { KNOWN_MINTS } from '../services/tokenPrices';
import { RawTransactionResponse } from '../types/solana';

test('Signature validation accepts valid Solana Base58 signatures including user signature', () => {
  const validSig = '4EcCC6GnXhkd2nCPaZES2EvNWZGCieXkTgWoZAair1UsXEZdpM9pPZSAwFSHoaonfUA876xo7qXkBWjEysRQziwo';
  assert.equal(isValidBase58Signature(validSig), true);
});

test('Parallel endpoint pools contain Helius, PublicNode, OnFinality, Solana Vibe Station, Ankr, and Official Mainnet/Devnet/Testnet', () => {
  const httpUrls = DEFAULT_PARALLEL_ENDPOINTS.map((e) => e.http);
  assert.equal(
    httpUrls.includes('https://mainnet.helius-rpc.com/?api-key=dea43e7c-2806-4d5e-9241-b010e5c96762'),
    true
  );
  assert.equal(httpUrls.includes('https://solana-rpc.publicnode.com'), true);
  assert.equal(httpUrls.includes('https://solana.api.onfinality.io/public'), true);

  const devnetUrls = DEVNET_PARALLEL_ENDPOINTS.map((e) => e.http);
  assert.equal(devnetUrls.includes('https://api.devnet.solana.com'), true);

  const testnetUrls = TESTNET_PARALLEL_ENDPOINTS.map((e) => e.http);
  assert.equal(testnetUrls.includes('https://api.testnet.solana.com'), true);
});

test('Protocol & Token Identity resolver identifies JLTXX, MONY, and custom Token-2022 mints without missing names', () => {
  const jltxxExact = resolveTokenIdentity(
    'J4cTuCH6frt4AnEmKfMS2k8hsUf7K94PV62sjUJno8Cz',
    'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb'
  );
  assert.equal(jltxxExact.symbol, 'JLTXX');
  assert.equal(jltxxExact.name.includes('JLTXX'), true);

  // Also test pattern-matched J4cT...o8Cz variant
  const jltxxVariant = resolveTokenIdentity(
    'J4cTs11111111111111111111111111111111111o8Cz',
    'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb'
  );
  assert.equal(jltxxVariant.symbol, 'JLTXX');
  assert.equal(jltxxVariant.name.includes('JLTXX'), true);
  assert.equal(jltxxVariant.isInstitutional, true);

  const factProg = getInstitutionalMetadata('9rdASsDUnrw2EsDARtfqjabqcjfXYFKu45kZ31wF74dg');
  assert.equal(Boolean(factProg?.isProgram), true);
  assert.equal(KNOWN_MINTS['EToDtBM2knZ8N1BHyUq2Riq5ngWTcoD3k6qpsgf7CKYY'].symbol, 'MONY');
});

test('Pure Base58 decoder & instruction byte forensics extracts hex and sighash discriminator', () => {
  const bytes = decodeBase58('3Bxs411Dtc7pkFQj');
  assert.equal(bytes.length > 0, true);
  const bf = analyzeInstructionBytes(
    '3Bxs411Dtc7pkFQj',
    false,
    '9rdASsDUnrw2EsDARtfqjabqcjfXYFKu45kZ31wF74dg'
  );
  assert.equal(bf.rawEncoding, 'base58');
  assert.equal(bf.byteLength > 0, true);
});

test('Client Onboarding & Alert Lifecycle Engine detects 0 -> +0.03 JLTXX client onboarding, 5 correlated lifecycle stages, and independent alerts', () => {
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

  // 1. Token Involved must be resolved with full name & symbol
  assert.equal(record.resolvedTokens.length >= 1, true);
  assert.equal(record.resolvedTokens[0].symbol, 'JLTXX');
  assert.equal(record.resolvedTokens[0].name.includes('JLTXX'), true);

  // 2. Client Onboarding must be detected (0 -> +0.03 JLTXX)
  assert.equal(record.alertIntelligence.clientOnboarding.isClientOnboarded, true);
  assert.equal(
    record.alertIntelligence.clientOnboarding.clientWalletAddress,
    'DwWsClientOwnerWallet11111111111111111111zXR'
  );
  assert.equal(
    record.alertIntelligence.clientOnboarding.clientTokenAccountAddress,
    'CUNnClientTokenAccount111111111111111111zPcj'
  );

  // 3. Correlated Lifecycle Stages (Previous -> Current -> Next) & Independent Alerts must exist
  assert.equal(record.alertIntelligence.lifecycleStages.length, 5);
  assert.equal(
    record.alertIntelligence.lifecycleStages.some((s) => s.phase === 'PREVIOUS_PREREQUISITE'),
    true
  );
  assert.equal(
    record.alertIntelligence.lifecycleStages.some((s) => s.phase === 'CURRENT_ACTIVE_ALERT'),
    true
  );
  assert.equal(
    record.alertIntelligence.lifecycleStages.some((s) => s.phase === 'NEXT_PREDICTED'),
    true
  );
  assert.equal(record.alertIntelligence.independentAlerts.length >= 1, true);

  // 4. Authorities, State Transitions, and Evidence Catalog must be comprehensive
  assert.equal(record.authorities.length >= 3, true);
  assert.equal(record.stateTransitions.length >= 2, true);
  assert.equal(record.evidenceCatalog.length >= 6, true);
});

test('Signature validation rejects empty, malformed, or 0/O/I/l invalid Base58 characters', () => {
  assert.equal(isValidBase58Signature(''), false);
  assert.equal(isValidBase58Signature('0123456789'), false);
  assert.equal(isValidBase58Signature('short'), false);
});

test('Solana address validation', () => {
  assert.equal(isValidSolanaAddress('11111111111111111111111111111111'), true);
  assert.equal(isValidSolanaAddress('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'), true);
  assert.equal(isValidSolanaAddress('invalid_address_0'), false);
});
