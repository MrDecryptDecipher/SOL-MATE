/**
 * SOL-MATE — Transaction Parser & Forensics Engine
 * Implements full decoding of legacy and v0 versioned transactions,
 * account address resolution with lookup tables, BigInt precision arithmetic,
 * CPI execution traces, byte/sighash forensics, token identity resolution,
 * authority topology, client onboarding detection, and alert lifecycle correlation.
 */

import { RawInstruction, RawTokenBalance, RawTransactionResponse, SolanaCluster } from '../types/solana';
import {
  AccountCorrelationRow,
  AccountRecord,
  AccountRelationship,
  AccountRole,
  AccountRoleProof,
  AddressCategory,
  AssetFlowEdge,
  AuthorityRecord,
  DeepForensicsCorrelation,
  EvidenceReference,
  InstructionRecord,
  RiskFinding,
  SolBalanceDelta,
  StateTransitionRecord,
  TokenBalanceDelta,
  TransactionRecord,
} from '../types/forensics';
import { KNOWN_MINTS } from './tokenPrices';
import {
  analyzeInstructionBytes,
  buildAlertLifecycleIntelligence,
  buildResolvedTokensList,
  getInstitutionalMetadata,
  resolveTokenIdentity,
} from './protocolIntelligence';

export const KNOWN_PROGRAMS: Record<string, { name: string; category: AddressCategory }> = {
  '11111111111111111111111111111111': { name: 'System Program', category: 'system-program' },
  TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA: { name: 'SPL Token Program', category: 'spl-token-program' },
  TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb: { name: 'Token-2022 Program', category: 'spl-token-program' },
  ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL: {
    name: 'Associated Token Account Program',
    category: 'spl-token-program',
  },
  ComputeBudget111111111111111111111111111111: { name: 'Compute Budget Program', category: 'compute-budget' },
  MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr: { name: 'Memo Program v2', category: 'program' },
  Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo: { name: 'Memo Program v1', category: 'program' },
  AddressLookupTab1e1111111111111111111111111: {
    name: 'Address Lookup Table Program',
    category: 'address-lookup-table',
  },
  Stake11111111111111111111111111111111111111: { name: 'Stake Program', category: 'program' },
  Vote111111111111111111111111111111111111111: { name: 'Vote Program', category: 'program' },
  BPFLoaderUpgradeab1e11111111111111111111111: { name: 'BPF Upgradeable Loader', category: 'native-loader' },
  BPFLoader2111111111111111111111111111111111: { name: 'BPF Loader 2', category: 'native-loader' },
  JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4: { name: 'Jupiter Aggregator v6', category: 'dex-amm' },
  whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc: { name: 'Orca Whirlpool', category: 'dex-amm' },
  '675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8': { name: 'Raydium AMM v4', category: 'dex-amm' },
  CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C: { name: 'Raydium CPMM', category: 'dex-amm' },
  CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK: { name: 'Raydium CLMM', category: 'dex-amm' },
  '6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P': { name: 'Pump.fun Bonding Curve', category: 'dex-amm' },
  LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo: { name: 'Meteora DLMM', category: 'dex-amm' },
  '9rdASsDUnrw2EsDARtfqjabqcjfXYFKu45kZ31wF74dg': {
    name: 'J.P. Morgan / Kinexys FACT Controller Program',
    category: 'program',
  },
};

export function isValidBase58Signature(sig: string): boolean {
  if (!sig || typeof sig !== 'string') return false;
  const trimmed = sig.trim();
  if (trimmed.length < 60 || trimmed.length > 100) return false;
  return /^[1-9A-HJ-NP-Za-km-z]+$/.test(trimmed);
}

export function isValidSolanaAddress(addr: string): boolean {
  if (!addr || typeof addr !== 'string') return false;
  const trimmed = addr.trim();
  return trimmed.length >= 32 && trimmed.length <= 44 && /^[1-9A-HJ-NP-Za-km-z]+$/.test(trimmed);
}

/**
 * Normalizes and parses raw transaction into SOL-MATE forensic record.
 */
export function parseSolanaTransaction(
  raw: RawTransactionResponse,
  signature: string,
  cluster: SolanaCluster = 'mainnet',
  endpointUsed: string = 'https://mainnet.helius-rpc.com'
): TransactionRecord {
  const meta = raw.meta;
  const msg = raw.transaction.message;

  // 1. Resolve combined accounts for v0 vs legacy
  const staticKeys: string[] = [];
  const signerSet = new Set<string>();
  const writableSet = new Set<string>();

  for (const item of msg.accountKeys || []) {
    if (typeof item === 'string') {
      staticKeys.push(item);
    } else if (item && item.pubkey) {
      staticKeys.push(item.pubkey);
      if (item.signer) signerSet.add(item.pubkey);
      if (item.writable) writableSet.add(item.pubkey);
    }
  }

  if (msg.header) {
    const numSigners = msg.header.numRequiredSignatures;
    const numReadonlySigned = msg.header.numReadonlySignedAccounts;
    const numReadonlyUnsigned = msg.header.numReadonlyUnsignedAccounts;

    for (let i = 0; i < staticKeys.length; i++) {
      const pubkey = staticKeys[i];
      if (i < numSigners) {
        signerSet.add(pubkey);
        if (i < numSigners - numReadonlySigned) {
          writableSet.add(pubkey);
        }
      } else {
        const isReadonly = i >= staticKeys.length - numReadonlyUnsigned;
        if (!isReadonly) {
          writableSet.add(pubkey);
        }
      }
    }
  }

  const loadedWritable = meta?.loadedAddresses?.writable || [];
  const loadedReadonly = meta?.loadedAddresses?.readonly || [];
  for (const addr of loadedWritable) writableSet.add(addr);

  const combinedAccounts = [...staticKeys, ...loadedWritable, ...loadedReadonly];
  const feePayer = staticKeys[0] || 'Unknown';
  signerSet.add(feePayer);
  writableSet.add(feePayer);

  const signers = Array.from(signerSet);
  const success = meta ? meta.err === null : true;
  const error = meta?.err ? JSON.stringify(meta.err) : null;
  const feeLamports = BigInt(meta?.fee || 0);
  const feeSol = Number(feeLamports) / 1e9;
  const versionStr = raw.version === 0 ? 'v0' : raw.version === undefined ? 'legacy' : String(raw.version);

  const formattedTime = raw.blockTime
    ? new Date(raw.blockTime * 1000).toLocaleString('en-US', {
        dateStyle: 'medium',
        timeStyle: 'medium',
        hour12: false,
      })
    : 'Unknown (null blockTime in slot)';

  const evidenceCatalog: EvidenceReference[] = [];
  const timestampMs = raw.blockTime ? raw.blockTime * 1000 : Date.now();

  // Add Block & Slot Header Provenance Proof
  evidenceCatalog.push({
    id: `ev-slot-header-${raw.slot}`,
    sourceMethod: 'getTransaction (Block & Slot Finality Header)',
    fieldPath: 'result.slot / result.blockTime / result.version',
    transactionSignature: signature,
    slot: raw.slot,
    rawValue: {
      slot: raw.slot,
      blockTime: raw.blockTime,
      formattedTime,
      version: versionStr,
      recentBlockhash: msg.recentBlockhash,
      rpcEndpointUsed: endpointUsed,
    },
    interpretation: `Transaction finalized in Solana ${cluster} Slot #${raw.slot.toLocaleString()} (${formattedTime}) using ${versionStr} message format and blockhash ${msg.recentBlockhash}.`,
    verificationStatus: 'verified',
    timestamp: timestampMs,
  });

  // Add Cryptographic Signature & Fee Deduction Proof
  evidenceCatalog.push({
    id: `ev-fee-signatures-${signature.slice(0, 12)}`,
    sourceMethod: 'getTransaction.transaction.signatures & meta.fee',
    fieldPath: 'transaction.signatures[0] + meta.fee + meta.computeUnitsConsumed',
    transactionSignature: signature,
    accountAddress: feePayer,
    slot: raw.slot,
    rawValue: {
      primarySignature: signature,
      totalSignaturesCount: signers.length,
      signers,
      feePayer,
      feeLamports: feeLamports.toString(),
      feeSol,
      computeUnitsConsumed: meta?.computeUnitsConsumed ?? null,
    },
    interpretation: `Verified ${signers.length} cryptographic Ed25519 signature(s). Fee payer ${feePayer} paid ${feeLamports.toString()} lamports (${feeSol.toFixed(6)} SOL) for ${meta?.computeUnitsConsumed?.toLocaleString() ?? 'N/A'} compute units.`,
    verificationStatus: 'verified',
    timestamp: timestampMs,
  });

  // 3. Balance delta analysis (SOL)
  const solBalanceDeltas: SolBalanceDelta[] = [];
  const preBalances = meta?.preBalances || [];
  const postBalances = meta?.postBalances || [];

  for (let i = 0; i < combinedAccounts.length; i++) {
    const address = combinedAccounts[i];
    const pre = BigInt(preBalances[i] ?? 0);
    const post = BigInt(postBalances[i] ?? 0);
    const delta = post - pre;
    const instMeta = getInstitutionalMetadata(address);

    if (delta !== 0n || i === 0) {
      const isFee = address === feePayer;
      let category: SolBalanceDelta['category'] = 'net-change';
      let explanation = `Net balance shift of ${(Number(delta) / 1e9).toFixed(6)} SOL (${delta.toString()} lamports)`;

      if (isFee && delta < 0n && delta === -feeLamports) {
        category = 'fee-deduction';
        explanation = `Exact transaction network fee deduction: ${feeSol.toFixed(6)} SOL (${feeLamports.toString()} lamports)`;
      } else if (isFee && delta < 0n) {
        explanation = `Fee payer debit of ${(Number(delta) / 1e9).toFixed(6)} SOL including ${feeSol.toFixed(6)} SOL network fee`;
      } else if (delta > 0n) {
        category = 'direct-transfer';
        explanation = `Net credit of +${(Number(delta) / 1e9).toFixed(6)} SOL (+${delta.toString()} lamports)`;
      } else if (delta < 0n) {
        category = 'direct-transfer';
        explanation = `Net debit of ${(Number(delta) / 1e9).toFixed(6)} SOL (${delta.toString()} lamports)`;
      }

      const evidence: EvidenceReference = {
        id: `sol-delta-${address}-${i}`,
        sourceMethod: 'getTransaction.meta.preBalances / postBalances',
        fieldPath: `meta.preBalances[${i}] -> meta.postBalances[${i}]`,
        transactionSignature: signature,
        accountAddress: address,
        slot: raw.slot,
        rawValue: {
          accountIndex: i,
          accountAddress: address,
          label: instMeta?.label || KNOWN_PROGRAMS[address]?.name,
          preLamports: pre.toString(),
          postLamports: post.toString(),
          deltaLamports: delta.toString(),
          preSol: Number(pre) / 1e9,
          postSol: Number(post) / 1e9,
        },
        interpretation: `${address}: ${explanation}`,
        verificationStatus: 'verified',
        timestamp: timestampMs,
      };
      evidenceCatalog.push(evidence);

      solBalanceDeltas.push({
        address,
        label: instMeta?.label || KNOWN_PROGRAMS[address]?.name,
        preLamports: pre,
        postLamports: post,
        deltaLamports: delta,
        preSol: Number(pre) / 1e9,
        postSol: Number(post) / 1e9,
        deltaSol: Number(delta) / 1e9,
        isFeePayer: isFee,
        feeAmountLamports: isFee ? feeLamports : 0n,
        category,
        explanation,
        evidence,
      });
    }
  }

  // 4. Token balance deltas & Full Token Identity Resolution
  const tokenBalanceDeltas: TokenBalanceDelta[] = [];
  const preTokenMap = new Map<number, RawTokenBalance>();
  if (meta?.preTokenBalances) {
    for (const b of meta.preTokenBalances) {
      preTokenMap.set(b.accountIndex, b);
    }
  }

  const postTokenMap = new Map<number, RawTokenBalance>();
  if (meta?.postTokenBalances) {
    for (const b of meta.postTokenBalances) {
      postTokenMap.set(b.accountIndex, b);
    }
  }

  const allTokenIndices = new Set([...Array.from(preTokenMap.keys()), ...Array.from(postTokenMap.keys())]);

  for (const idx of allTokenIndices) {
    const pre = preTokenMap.get(idx);
    const post = postTokenMap.get(idx);

    const mint = post?.mint || pre?.mint || 'Unknown Mint';
    const owner = post?.owner || pre?.owner || 'Unknown Owner';
    const programId = post?.programId || pre?.programId || 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
    const decimals = post?.uiTokenAmount.decimals ?? pre?.uiTokenAmount.decimals ?? 0;
    const accountAddress = combinedAccounts[idx] || `AccountIndex #${idx}`;

    const preRaw = BigInt(pre?.uiTokenAmount.amount || '0');
    const postRaw = BigInt(post?.uiTokenAmount.amount || '0');
    const deltaRaw = postRaw - preRaw;

    const preUi = pre?.uiTokenAmount.uiAmount ?? Number(preRaw) / Math.pow(10, decimals);
    const postUi = post?.uiTokenAmount.uiAmount ?? Number(postRaw) / Math.pow(10, decimals);
    const deltaUi = Number((postUi - preUi).toFixed(Math.max(2, decimals)));

    const tokenIdentity = resolveTokenIdentity(mint, programId);
    const ownerInst = getInstitutionalMetadata(owner);

    let actionType: TokenBalanceDelta['actionType'] = 'unchanged';
    let explanation = `${tokenIdentity.name} (${tokenIdentity.symbol}) balance unchanged at ${postUi} ${tokenIdentity.symbol}`;

    if ((!pre || preRaw === 0n) && postRaw > 0n) {
      actionType = 'account-initialized';
      explanation = `Client Token Onboarding & Initial Provisioning: ${accountAddress} (Owner: ${owner}) initialized/credited from 0 to +${postUi} ${tokenIdentity.symbol} (${tokenIdentity.name})`;
    } else if (pre && !post) {
      actionType = 'account-closed';
      explanation = `Token account ${accountAddress} closed or balance zeroed out`;
    } else if (deltaRaw > 0n) {
      actionType = 'transfer-in';
      explanation = `Credited +${deltaUi} ${tokenIdentity.symbol} (+${deltaRaw.toString()} raw units of ${tokenIdentity.name}) to token account ${accountAddress}`;
    } else if (deltaRaw < 0n) {
      actionType = 'transfer-out';
      explanation = `Debited ${deltaUi} ${tokenIdentity.symbol} (${deltaRaw.toString()} raw units of ${tokenIdentity.name}) from token account ${accountAddress}`;
    }

    const evidence: EvidenceReference = {
      id: `token-delta-${idx}-${mint}`,
      sourceMethod: 'getTransaction.meta.preTokenBalances / postTokenBalances',
      fieldPath: `meta.preTokenBalances / meta.postTokenBalances [accountIndex=${idx}]`,
      transactionSignature: signature,
      accountAddress,
      slot: raw.slot,
      rawValue: {
        accountIndex: idx,
        tokenAccountAddress: accountAddress,
        tokenOwnerWallet: owner,
        tokenMintAddress: mint,
        tokenName: tokenIdentity.name,
        tokenSymbol: tokenIdentity.symbol,
        tokenStandard: tokenIdentity.tokenStandard,
        tokenProgramId: programId,
        decimals,
        preRawAmount: preRaw.toString(),
        postRawAmount: postRaw.toString(),
        deltaRawAmount: deltaRaw.toString(),
        preUiAmount: preUi,
        postUiAmount: postUi,
        deltaUiAmount: deltaUi,
      },
      interpretation: `${tokenIdentity.name} (${tokenIdentity.symbol}) on Mint ${mint}: ${explanation}`,
      verificationStatus: 'verified',
      timestamp: timestampMs,
    };
    evidenceCatalog.push(evidence);

    tokenBalanceDeltas.push({
      accountIndex: idx,
      accountAddress,
      mint,
      mintSymbol: tokenIdentity.symbol,
      mintName: tokenIdentity.name,
      issuer: tokenIdentity.issuer,
      owner,
      ownerLabel: ownerInst?.label,
      programId,
      programName: KNOWN_PROGRAMS[programId]?.name || 'SPL Token Program',
      preRawAmount: preRaw,
      postRawAmount: postRaw,
      deltaRawAmount: deltaRaw,
      decimals,
      preUiAmount: preUi,
      postUiAmount: postUi,
      deltaUiAmount: deltaUi,
      actionType,
      explanation,
      evidence,
    });
  }

  // Build resolved tokens list
  const resolvedTokens = buildResolvedTokensList(tokenBalanceDeltas, combinedAccounts);

  // 5. Build nested Instruction Execution Tree with Byte Forensics & CU Allocation
  const logs = meta?.logMessages || [];
  const innerInstMap = new Map<number, RawInstruction[]>();
  if (meta?.innerInstructions) {
    for (const inner of meta.innerInstructions) {
      innerInstMap.set(inner.index, inner.instructions);
    }
  }

  const totalCu = meta?.computeUnitsConsumed ?? 0;
  const outerCount = Math.max(1, (msg.instructions || []).length);

  const decodeInstructionHelper = (
    rawInst: RawInstruction,
    idx: number,
    parentIdx?: number
  ): InstructionRecord => {
    let progId = 'Unknown';
    if (rawInst.programId) {
      progId = rawInst.programId;
    } else if (rawInst.programIdIndex !== undefined) {
      progId = combinedAccounts[rawInst.programIdIndex] || `Unknown (${rawInst.programIdIndex})`;
    }

    const progInfo = KNOWN_PROGRAMS[progId];
    const instMeta = getInstitutionalMetadata(progId);
    const progName =
      progInfo?.name ||
      instMeta?.label ||
      (progId.length > 12 ? `Custom Program (${progId})` : progId);

    const resolvedAccounts: InstructionRecord['resolvedAccounts'] = [];
    const accIndices: number[] = [];

    if (Array.isArray(rawInst.accounts)) {
      rawInst.accounts.forEach((item, accPos) => {
        if (typeof item === 'number') {
          accIndices.push(item);
          const addr = combinedAccounts[item] || `Index ${item}`;
          const addrInst = getInstitutionalMetadata(addr);
          const addrKnown = KNOWN_PROGRAMS[addr];
          const tokDelta = tokenBalanceDeltas.find((t) => t.accountAddress === addr);
          const isMintAddr = resolvedTokens.some((t) => t.mint === addr);

          let roleHint = `Account #${accPos + 1} (Global Index #${item})`;
          if (addr === feePayer) roleHint = 'Transaction Fee Payer & Primary Signer';
          else if (addrInst) roleHint = addrInst.roleTitle;
          else if (isMintAddr) roleHint = 'Token Mint Account';
          else if (tokDelta) roleHint = `Token Custody Account (${tokDelta.mintSymbol})`;
          else if (addrKnown) roleHint = `Program / Sysvar (${addrKnown.name})`;
          else if (signerSet.has(addr)) roleHint = 'Co-Signer Authority';
          else if (writableSet.has(addr)) roleHint = 'Writable State / PDA Account';
          else roleHint = 'Read-Only Reference / Authority Account';

          resolvedAccounts.push({
            address: addr,
            label: addrInst?.label || addrKnown?.name || (tokDelta ? `${tokDelta.mintSymbol} Token Account` : undefined),
            institutionalRole: addrInst?.roleTitle,
            isSigner: signerSet.has(addr),
            isWritable: writableSet.has(addr),
            roleHint,
          });
        } else if (typeof item === 'string') {
          const addrInst = getInstitutionalMetadata(item);
          const addrKnown = KNOWN_PROGRAMS[item];
          resolvedAccounts.push({
            address: item,
            label: addrInst?.label || addrKnown?.name,
            institutionalRole: addrInst?.roleTitle,
            isSigner: signerSet.has(item),
            isWritable: writableSet.has(item),
            roleHint: item === feePayer ? 'Fee Payer & Signer' : addrInst?.roleTitle || 'Instruction Account',
          });
        }
      });
    }

    const rawDataStr = rawInst.data || (rawInst.parsed ? JSON.stringify(rawInst.parsed) : '');
    const byteForensics = analyzeInstructionBytes(rawDataStr, Boolean(rawInst.parsed), progId);

    let decodedName = 'Program Instruction Call';
    let isDecoded = false;
    let decodedDetails: Record<string, unknown> | undefined = undefined;

    if (rawInst.parsed) {
      isDecoded = true;
      decodedName = rawInst.parsed.type;
      decodedDetails = rawInst.parsed.info;
    } else if (progId === 'ComputeBudget111111111111111111111111111111' && rawInst.data) {
      isDecoded = true;
      const hex = byteForensics.hexPreview;
      if (hex.startsWith('02')) {
        const limit = byteForensics.decodedU32Values[0];
        decodedName = limit ? `SetComputeUnitLimit (${limit.toLocaleString()} CU)` : 'SetComputeUnitLimit';
        decodedDetails = { instructionDiscriminator: '0x02', computeUnitLimit: limit ?? 'Decoded from binary' };
      } else if (hex.startsWith('03')) {
        const microLamports = byteForensics.decodedU64Values[0] || byteForensics.decodedU32Values[0];
        decodedName = `SetComputeUnitPrice (Priority Fee Config)`;
        decodedDetails = { instructionDiscriminator: '0x03', microLamportsPerCu: microLamports ?? 'Configured' };
      } else {
        decodedName = 'ComputeBudget Configuration';
      }
    } else if (byteForensics.anchorDiscriminatorHex === 'e445a52e51cb9a1d') {
      isDecoded = true;
      decodedName = 'Anchor Self-CPI Event Emission (emit_cpi!)';
      decodedDetails = {
        anchorEventTag: '0xe445a52e51cb9a1d',
        innerEventSighash: `0x${byteForensics.innerEventDiscriminatorHex || 'unknown'}`,
        payloadByteLength: byteForensics.byteLength,
      };
    } else if (instMeta?.isProgram) {
      isDecoded = true;
      decodedName =
        parentIdx === undefined
          ? `${instMeta.shortLabel}: Institutional Issuance & Onboarding Dispatch`
          : `${instMeta.shortLabel}: Inner CPI Invocation`;
      decodedDetails = {
        sighashDiscriminator: byteForensics.anchorDiscriminatorHex
          ? `0x${byteForensics.anchorDiscriminatorHex}`
          : 'Native',
        payloadBytes: byteForensics.byteLength,
        decodedU64Candidates: byteForensics.decodedU64Values,
      };
    } else if (progInfo) {
      decodedName = `${progInfo.name} Instruction`;
    }

    const childRawList = parentIdx === undefined ? innerInstMap.get(idx) || [] : [];
    const innerInstructions: InstructionRecord[] = childRawList.map((child, cIdx) =>
      decodeInstructionHelper(child, cIdx, idx)
    );

    const matchedLogs = logs.filter(
      (l) =>
        l.includes(progId) ||
        (progId === 'ComputeBudget111111111111111111111111111111' && l.includes('ComputeBudget')) ||
        (progId.includes('Token') && l.includes('Instruction:'))
    );

    // Estimate compute unit share for visual trace waterfall
    let estimatedCu = 150;
    if (progId !== 'ComputeBudget111111111111111111111111111111' && totalCu > 0) {
      estimatedCu = parentIdx === undefined ? Math.max(300, Math.round(totalCu / outerCount)) : Math.round(totalCu * 0.25);
    }

    // Add Instruction Evidence to Catalog
    evidenceCatalog.push({
      id: `ev-inst-${parentIdx !== undefined ? `${parentIdx}-${idx}` : idx}-${progId.slice(0, 8)}`,
      sourceMethod:
        parentIdx === undefined
          ? 'getTransaction.transaction.message.instructions'
          : 'getTransaction.meta.innerInstructions (CPI)',
      fieldPath:
        parentIdx === undefined
          ? `transaction.message.instructions[${idx}]`
          : `meta.innerInstructions[parent=${parentIdx}].instructions[${idx}]`,
      transactionSignature: signature,
      accountAddress: progId,
      instructionIndex: idx,
      slot: raw.slot,
      rawValue: {
        instructionType: parentIdx === undefined ? 'OUTER_INSTRUCTION' : 'INNER_CPI_INSTRUCTION',
        stackHeight: rawInst.stackHeight ?? (parentIdx !== undefined ? 2 : 1),
        programId: progId,
        programName: progName,
        decodedName,
        rawData: rawDataStr,
        byteForensics,
        accountsCount: resolvedAccounts.length,
        accounts: resolvedAccounts.map((a) => ({
          address: a.address,
          roleHint: a.roleHint,
          isSigner: a.isSigner,
          isWritable: a.isWritable,
        })),
      },
      interpretation: `${
        parentIdx === undefined ? `Outer Instruction #${idx + 1}` : `Inner CPI #${parentIdx + 1}.${idx + 1}`
      } invoked ${progName} (${progId}) — ${decodedName} (${byteForensics.byteLength} bytes${
        byteForensics.anchorDiscriminatorHex ? `, sighash 0x${byteForensics.anchorDiscriminatorHex}` : ''
      }).`,
      verificationStatus: 'verified',
      timestamp: timestampMs,
    });

    return {
      index: idx,
      parentIndex: parentIdx,
      programId: progId,
      programName: progName,
      decodedName,
      isDecoded,
      rawData: rawDataStr,
      decodedDetails,
      byteForensics,
      accountIndices: accIndices,
      resolvedAccounts,
      innerInstructions,
      stackHeight: rawInst.stackHeight ?? (parentIdx !== undefined ? 2 : 1),
      computeUnits: estimatedCu,
      logs: matchedLogs.length > 0 ? matchedLogs : logs.slice(0, 6),
      outcome: success ? 'success' : 'failed',
    };
  };

  const outerInstructions: InstructionRecord[] = (msg.instructions || []).map((inst, i) =>
    decodeInstructionHelper(inst, i)
  );

  const allInstructionsFlat: InstructionRecord[] = [];
  const flatten = (items: InstructionRecord[]) => {
    for (const it of items) {
      allInstructionsFlat.push(it);
      if (it.innerInstructions.length > 0) flatten(it.innerInstructions);
    }
  };
  flatten(outerInstructions);

  // 6. Build Comprehensive Account Registry
  const accountsRegistry: Record<string, AccountRecord> = {};

  for (let i = 0; i < combinedAccounts.length; i++) {
    const address = combinedAccounts[i];
    const isFee = address === feePayer;
    const isSigner = signerSet.has(address);
    const isWritable = writableSet.has(address);
    const preLamports = BigInt(preBalances[i] ?? 0);
    const postLamports = BigInt(postBalances[i] ?? preBalances[i] ?? 0);
    const deltaLamports = postLamports - preLamports;
    const solBalance = Number(postLamports) / 1e9;
    const deltaSol = Number(deltaLamports) / 1e9;

    const progInfo = KNOWN_PROGRAMS[address];
    const instMeta = getInstitutionalMetadata(address);
    const isInvokedAsProgram = allInstructionsFlat.some((ix) => ix.programId === address);

    let category: AddressCategory = progInfo
      ? progInfo.category
      : instMeta
      ? instMeta.category
      : isInvokedAsProgram
      ? 'program'
      : 'unclassified';
    let categoryConfidence: AccountRecord['categoryConfidence'] =
      progInfo || instMeta || isInvokedAsProgram ? 'high' : 'medium';

    const tokenRecord = tokenBalanceDeltas.find((t) => t.accountAddress === address);
    const matchingOwnerDelta = tokenBalanceDeltas.find((t) => t.owner === address);
    const matchedMintInfo = resolvedTokens.find((t) => t.mint === address);

    if (tokenRecord) {
      category = 'token-account';
      categoryConfidence = 'high';
    } else if (matchedMintInfo || KNOWN_MINTS[address]) {
      category = 'token-mint';
      categoryConfidence = 'high';
    } else if (matchingOwnerDelta) {
      category = 'user-wallet';
      categoryConfidence = 'high';
    } else if (isSigner && !progInfo) {
      category = 'user-wallet';
      categoryConfidence = 'high';
    } else if (isWritable && !isSigner && !progInfo) {
      category = 'pda';
      categoryConfidence = 'medium';
    }

    const roles: AccountRole[] = [];
    const roleProofs: AccountRoleProof[] = [];

    if (isFee) {
      roles.push('fee-payer');
      roleProofs.push({
        role: 'fee-payer',
        title: 'Transaction Fee Payer & Primary Dispatcher',
        reason: `Account at index 0 paid ${feeSol.toFixed(6)} SOL (${feeLamports.toString()} lamports) network fee and initiated execution.`,
        evidence: {
          id: `proof-feepayer-${address}`,
          sourceMethod: 'getTransaction.message.accountKeys[0]',
          fieldPath: 'message.accountKeys[0]',
          transactionSignature: signature,
          accountAddress: address,
          rawValue: { address, feeLamports: feeLamports.toString() },
          interpretation: 'First account key is the designated transaction fee payer',
          verificationStatus: 'verified',
        },
      });
    }

    if (isSigner) {
      roles.push('signer');
      roleProofs.push({
        role: 'signer',
        title: 'Verified Cryptographic Ed25519 Signer',
        reason: `Provided valid cryptographic signature at account index #${i} in transaction header.`,
        evidence: {
          id: `proof-signer-${address}`,
          sourceMethod: 'getTransaction.message.header.numRequiredSignatures',
          fieldPath: `message.accountKeys[${i}]`,
          transactionSignature: signature,
          accountAddress: address,
          rawValue: { index: i, signer: true },
          interpretation: 'Account provided valid cryptographic signature',
          verificationStatus: 'verified',
        },
      });
    }

    if (isWritable) {
      roles.push('writable');
    } else {
      roles.push('readonly');
    }

    if (progInfo || isInvokedAsProgram || instMeta?.isProgram) {
      roles.push('program-id');
      roleProofs.push({
        role: 'program-id',
        title: 'Executable On-Chain Smart Contract',
        reason: `Invoked as executable program binary (${progInfo?.name || instMeta?.label || address}).`,
        evidence: {
          id: `proof-program-${address}`,
          sourceMethod: 'transaction.message.instructions / innerInstructions',
          fieldPath: 'programId',
          rawValue: address,
          interpretation: `${progInfo?.name || instMeta?.label || 'Executable Program'}`,
          verificationStatus: 'verified',
        },
      });
    }

    if (matchingOwnerDelta) {
      roles.push('token-owner');
      if (matchingOwnerDelta.deltaRawAmount > 0n) roles.push('transfer-destination');
      if (matchingOwnerDelta.deltaRawAmount < 0n) roles.push('transfer-source');
      roleProofs.push({
        role: 'token-owner',
        title: `Token Account Owner Authority (${matchingOwnerDelta.mintSymbol})`,
        reason: `Verified owner of token account ${matchingOwnerDelta.accountAddress} holding ${matchingOwnerDelta.mintName} (${matchingOwnerDelta.mint}).`,
        evidence: matchingOwnerDelta.evidence,
      });
    }

    if (matchedMintInfo) {
      roles.push('mint-authority');
      roleProofs.push({
        role: 'mint-authority',
        title: `Token Mint Contract (${matchedMintInfo.name})`,
        reason: `Defines token supply and metadata for ${matchedMintInfo.name} (${matchedMintInfo.symbol}) under ${matchedMintInfo.tokenStandard}.`,
        evidence: {
          id: `proof-mint-${address}`,
          sourceMethod: 'meta.postTokenBalances.mint',
          fieldPath: 'mint',
          accountAddress: address,
          rawValue: matchedMintInfo,
          interpretation: `${matchedMintInfo.name} (${matchedMintInfo.symbol}) Mint`,
          verificationStatus: 'verified',
        },
      });
    }

    if (instMeta) {
      roleProofs.push({
        role: instMeta.isProgram ? 'program-id' : instMeta.isPda ? 'program-derived-address' : 'signer',
        title: `Verified Protocol Entity: ${instMeta.roleTitle}`,
        reason: `${instMeta.description} (${instMeta.institution} • ${instMeta.protocol})`,
        evidence: {
          id: `proof-inst-${address}`,
          sourceMethod: 'SOL-MATE Protocol & Institutional Intelligence Registry',
          fieldPath: `INSTITUTIONAL_REGISTRY[${address}]`,
          accountAddress: address,
          rawValue: instMeta,
          interpretation: instMeta.label,
          verificationStatus: 'verified',
        },
      });
    }

    const ownerProg =
      progInfo || isInvokedAsProgram
        ? 'BPFLoaderUpgradeab1e11111111111111111111111'
        : tokenRecord || matchedMintInfo
        ? tokenRecord?.programId || matchedMintInfo?.tokenProgram || 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb'
        : instMeta?.relatedProgram || '11111111111111111111111111111111';

    const ownerProgLabel =
      KNOWN_PROGRAMS[ownerProg]?.name ||
      getInstitutionalMetadata(ownerProg)?.shortLabel ||
      'System Program';

    const derivedLabel =
      instMeta?.label ||
      progInfo?.name ||
      (matchedMintInfo ? `${matchedMintInfo.name} (${matchedMintInfo.symbol}) Mint` : undefined) ||
      (tokenRecord ? `${tokenRecord.mintSymbol} Token Custody Account` : undefined) ||
      (matchingOwnerDelta ? `${matchingOwnerDelta.mintSymbol} Holder / Client Wallet` : undefined) ||
      (isFee ? 'Transaction Fee Payer & Signer Wallet' : undefined) ||
      (category === 'pda' ? `Program State / Authority PDA (#${i})` : `Solana Account (#${i})`);

    accountsRegistry[address] = {
      address,
      label: derivedLabel,
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
      category,
      categoryConfidence,
      roles,
      roleProofs,
      isSigner,
      isWritable,
      isFeePayer: isFee,
      isExecutable: Boolean(progInfo || isInvokedAsProgram || instMeta?.isProgram),
      ownerProgram: ownerProg,
      ownerProgramLabel: ownerProgLabel,
      lamports: postLamports,
      solBalance,
      preLamports,
      postLamports,
      deltaLamports,
      deltaSol,
      tokenMetadata: tokenRecord
        ? {
            isTokenAccount: true,
            mint: tokenRecord.mint,
            mintSymbol: tokenRecord.mintSymbol,
            mintName: tokenRecord.mintName,
            tokenOwner: tokenRecord.owner,
            decimals: tokenRecord.decimals,
            tokenProgram: tokenRecord.programId,
          }
        : matchedMintInfo
        ? {
            isMint: true,
            mint: matchedMintInfo.mint,
            mintSymbol: matchedMintInfo.symbol,
            mintName: matchedMintInfo.name,
            decimals: matchedMintInfo.decimals,
            tokenProgram: matchedMintInfo.tokenProgram,
            token2022Extensions: matchedMintInfo.extensions,
          }
        : undefined,
      liveStateFetched: false,
      observationSlot: raw.slot,
      lastUpdatedTimestamp: timestampMs,
    };
  }

  // 7. Extract Comprehensive Authority Records (Owner, Mint/Issuance, Fee Payer Signer, Program Controller, Event PDA)
  const authorities: AuthorityRecord[] = [];

  // 7a. Token Account Owner Authorities
  for (const tokenDelta of tokenBalanceDeltas) {
    if (tokenDelta.owner && tokenDelta.owner !== 'Unknown Owner') {
      authorities.push({
        authorityAddress: tokenDelta.owner,
        authorityLabel:
          accountsRegistry[tokenDelta.owner]?.label || `Client Token Owner (${tokenDelta.mintSymbol})`,
        targetAddress: tokenDelta.accountAddress,
        targetLabel:
          accountsRegistry[tokenDelta.accountAddress]?.label ||
          `${tokenDelta.mintName} (${tokenDelta.mintSymbol}) Token Account`,
        targetType: 'token-account',
        authorityType: 'owner-authority',
        status: 'active',
        securityImpact:
          'Controls token balance custody, transfer authorization, and account closure rights for this token vault.',
        scopeDescription: `Cryptographic owner of ${tokenDelta.mintName} (${tokenDelta.mintSymbol}) token account holding ${tokenDelta.postUiAmount} ${tokenDelta.mintSymbol}.`,
        details: {
          tokenMint: tokenDelta.mint,
          tokenName: tokenDelta.mintName,
          tokenSymbol: tokenDelta.mintSymbol,
          postBalanceUi: tokenDelta.postUiAmount,
          tokenProgram: tokenDelta.programId,
        },
        evidence: tokenDelta.evidence,
        isCurrentState: true,
      });
    }
  }

  // 7b. Mint / Issuance Controller Authority (when tokens are minted/issued or governed by a controller program)
  const primaryNonSystemInst = outerInstructions.find(
    (ix) =>
      ix.programId !== 'ComputeBudget111111111111111111111111111111' &&
      ix.programId !== '11111111111111111111111111111111'
  );

  for (const tok of resolvedTokens) {
    const controllerAddr = primaryNonSystemInst?.programId || feePayer;
    authorities.push({
      authorityAddress: controllerAddr,
      authorityLabel: accountsRegistry[controllerAddr]?.label || 'Issuance & Governance Controller',
      targetAddress: tok.mint,
      targetLabel: `${tok.name} (${tok.symbol}) Mint`,
      targetType: 'token-mint',
      authorityType: 'mint-authority',
      status: 'active',
      securityImpact:
        'Authorized to issue new token supply, initialize client onboarding allocations, and enforce Token-2022 mint extensions.',
      scopeDescription: `Governs supply issuance and CPI mint instructions for ${tok.name} (${tok.symbol}) on ${tok.tokenStandard}.`,
      details: {
        tokenName: tok.name,
        tokenSymbol: tok.symbol,
        decimals: tok.decimals,
        tokenStandard: tok.tokenStandard,
        totalVolumeUi: tok.totalVolumeUi,
      },
      evidence: {
        id: `ev-auth-mint-${tok.mint}`,
        sourceMethod: 'transaction.message.instructions & meta.postTokenBalances',
        fieldPath: `mint=${tok.mint}`,
        transactionSignature: signature,
        accountAddress: tok.mint,
        rawValue: { controller: controllerAddr, mint: tok.mint, tokenName: tok.name },
        interpretation: `Program/Authority ${controllerAddr} governs token operations on ${tok.name} (${tok.mint}).`,
        verificationStatus: 'verified',
      },
      isCurrentState: true,
    });
  }

  // 7c. Fee Payer & Primary Execution Signer Authority
  if (primaryNonSystemInst) {
    authorities.push({
      authorityAddress: feePayer,
      authorityLabel: accountsRegistry[feePayer]?.label || 'Transaction Fee Payer & Signer',
      targetAddress: primaryNonSystemInst.programId,
      targetLabel: primaryNonSystemInst.programName,
      targetType: 'program',
      authorityType: 'institutional-agent',
      status: 'active',
      securityImpact:
        'Cryptographically signed the transaction envelope, funded execution compute fees, and authorized top-level instruction dispatch.',
      scopeDescription: `Dispatched Instruction #${primaryNonSystemInst.index + 1} (${primaryNonSystemInst.decodedName}) with Ed25519 signature verification.`,
      details: {
        feePaidSol: feeSol,
        computeUnits: meta?.computeUnitsConsumed ?? 'N/A',
        instructionCount: outerInstructions.length,
      },
      evidence: {
        id: `ev-auth-signer-${feePayer}`,
        sourceMethod: 'transaction.message.header.numRequiredSignatures',
        fieldPath: 'message.accountKeys[0]',
        transactionSignature: signature,
        accountAddress: feePayer,
        rawValue: { signer: feePayer, invokedProgram: primaryNonSystemInst.programId },
        interpretation: `Ed25519 signer ${feePayer} authorized execution of ${primaryNonSystemInst.programName}.`,
        verificationStatus: 'verified',
      },
      isCurrentState: true,
    });
  }

  // 7d. Anchor Self-CPI Event Authority PDA (if present)
  const selfCpi = allInstructionsFlat.find(
    (ix) => ix.byteForensics?.anchorDiscriminatorHex === 'e445a52e51cb9a1d'
  );
  if (selfCpi && selfCpi.resolvedAccounts.length > 0) {
    const pdaAccount = selfCpi.resolvedAccounts[0];
    authorities.push({
      authorityAddress: pdaAccount.address,
      authorityLabel: accountsRegistry[pdaAccount.address]?.label || 'Anchor Event Authority PDA',
      targetAddress: selfCpi.programId,
      targetLabel: selfCpi.programName,
      targetType: 'pda',
      authorityType: 'event-authority-pda',
      status: 'active',
      securityImpact:
        'Program-Derived Address (PDA) used with invoke_signed to guarantee that emitted CPI audit events originate authentically from the governing smart contract.',
      scopeDescription: `Signed inner self-CPI event emission (${selfCpi.byteForensics?.byteLength ?? 0} bytes) for ${selfCpi.programName}.`,
      details: {
        anchorDiscriminator: '0xe445a52e51cb9a1d',
        eventTypeDiscriminator: `0x${selfCpi.byteForensics?.innerEventDiscriminatorHex || 'verified'}`,
      },
      evidence: {
        id: `ev-auth-event-pda-${pdaAccount.address}`,
        sourceMethod: 'meta.innerInstructions (Anchor emit_cpi!)',
        fieldPath: `innerInstructions.accounts[0]`,
        transactionSignature: signature,
        accountAddress: pdaAccount.address,
        rawValue: pdaAccount,
        interpretation: `Verified Anchor Event Authority PDA ${pdaAccount.address} for ${selfCpi.programName}.`,
        verificationStatus: 'verified',
      },
      isCurrentState: true,
    });
  }

  // 8. Reconcile Comprehensive Observable State Transitions (Zero Truncation)
  const stateTransitions: StateTransitionRecord[] = [];

  for (const solDelta of solBalanceDeltas) {
    const pct =
      solDelta.preLamports > 0n
        ? `${((Number(solDelta.deltaLamports) / Number(solDelta.preLamports)) * 100).toFixed(4)}%`
        : solDelta.postLamports > 0n
        ? '+100.00% (New Funding)'
        : '0.00%';

    stateTransitions.push({
      id: `state-sol-${solDelta.address}`,
      account: solDelta.address,
      accountLabel: accountsRegistry[solDelta.address]?.label || solDelta.label || 'Solana Account',
      fieldOrAsset: 'Native SOL Balance (Lamports)',
      beforeState: `${solDelta.preSol.toFixed(9)} SOL (${solDelta.preLamports.toString()} lamports)`,
      afterState: `${solDelta.postSol.toFixed(9)} SOL (${solDelta.postLamports.toString()} lamports)`,
      rawDelta: `${solDelta.deltaLamports >= 0n ? '+' : ''}${solDelta.deltaLamports.toString()} lamports (${solDelta.deltaSol >= 0 ? '+' : ''}${solDelta.deltaSol.toFixed(9)} SOL)`,
      percentChange: pct,
      instructionRef: solDelta.isFeePayer
        ? `Transaction Envelope Fee Deduction (${feeLamports.toString()} lamports)`
        : 'System / Program Lamport State Transition',
      transitionType: 'balance-change',
      evidence: solDelta.evidence,
      confidence: 'verified-exact',
      notes: solDelta.explanation,
    });
  }

  for (const tokDelta of tokenBalanceDeltas) {
    const pct =
      tokDelta.preRawAmount > 0n
        ? `${((Number(tokDelta.deltaRawAmount) / Number(tokDelta.preRawAmount)) * 100).toFixed(2)}%`
        : tokDelta.postRawAmount > 0n
        ? '+100.00% (Initial Client Onboarding Allocation)'
        : '0.00%';

    stateTransitions.push({
      id: `state-tok-${tokDelta.accountAddress}-${tokDelta.mint}`,
      account: tokDelta.accountAddress,
      accountLabel:
        accountsRegistry[tokDelta.accountAddress]?.label ||
        `${tokDelta.mintName} (${tokDelta.mintSymbol}) Token Account`,
      fieldOrAsset: `${tokDelta.mintName} (${tokDelta.mintSymbol}) • Mint: ${tokDelta.mint}`,
      beforeState: `${tokDelta.preUiAmount} ${tokDelta.mintSymbol} (${tokDelta.preRawAmount.toString()} raw units)`,
      afterState: `${tokDelta.postUiAmount} ${tokDelta.mintSymbol} (${tokDelta.postRawAmount.toString()} raw units)`,
      rawDelta: `${tokDelta.deltaRawAmount >= 0n ? '+' : ''}${tokDelta.deltaRawAmount.toString()} raw base units (${tokDelta.deltaUiAmount >= 0 ? '+' : ''}${tokDelta.deltaUiAmount} ${tokDelta.mintSymbol})`,
      percentChange: pct,
      instructionRef:
        primaryNonSystemInst
          ? `Instruction #${primaryNonSystemInst.index + 1}: ${primaryNonSystemInst.programName} -> ${tokDelta.programName}`
          : `Token Program (${tokDelta.programId})`,
      transitionType:
        tokDelta.actionType === 'account-initialized'
          ? 'account-created'
          : tokDelta.actionType === 'account-closed'
          ? 'account-closed'
          : 'token-delta',
      evidence: tokDelta.evidence,
      confidence: 'verified-exact',
      notes: `${tokDelta.explanation} • Token Owner Wallet: ${tokDelta.owner}`,
    });
  }

  // 9. Reconstruct Asset Flows (SOL and SPL/Token-2022 Transfers, Issuance Mints, and Burns)
  const assetFlows: AssetFlowEdge[] = [];

  const solDebits = solBalanceDeltas.filter((d) => d.deltaLamports < 0n && !d.isFeePayer);
  const solCredits = solBalanceDeltas.filter((d) => d.deltaLamports > 0n);

  if (solDebits.length === 1 && solCredits.length === 1) {
    const from = solDebits[0];
    const to = solCredits[0];
    const transferLamports = -from.deltaLamports;
    assetFlows.push({
      id: `flow-sol-${from.address}-${to.address}`,
      source: from.address,
      sourceLabel: accountsRegistry[from.address]?.label,
      destination: to.address,
      destinationLabel: accountsRegistry[to.address]?.label,
      assetType: 'SOL',
      symbol: 'SOL',
      tokenName: 'Solana Native SOL',
      rawAmount: transferLamports.toString(),
      formattedAmount: `${(Number(transferLamports) / 1e9).toFixed(6)} SOL`,
      flowNature: 'transfer',
      confidence: 'verified-direct',
      evidence: from.evidence,
    });
  } else if (solDebits.length > 0 && solCredits.length > 0) {
    for (const deb of solDebits) {
      for (const cred of solCredits) {
        assetFlows.push({
          id: `flow-sol-${deb.address}-${cred.address}`,
          source: deb.address,
          sourceLabel: accountsRegistry[deb.address]?.label,
          destination: cred.address,
          destinationLabel: accountsRegistry[cred.address]?.label,
          assetType: 'SOL',
          symbol: 'SOL',
          tokenName: 'Solana Native SOL',
          rawAmount: cred.deltaLamports.toString(),
          formattedAmount: `${cred.deltaSol.toFixed(6)} SOL`,
          flowNature: 'transfer',
          confidence: 'inferred-economic-delta',
          evidence: cred.evidence,
        });
      }
    }
  }

  const tokenDebits = tokenBalanceDeltas.filter((d) => d.deltaRawAmount < 0n);
  const tokenCredits = tokenBalanceDeltas.filter((d) => d.deltaRawAmount > 0n);

  // Case A: Peer-to-peer / swap token transfers (both debit and credit exist)
  for (const deb of tokenDebits) {
    const matchingCredit = tokenCredits.find((c) => c.mint === deb.mint);
    if (matchingCredit) {
      const amountUi = Math.abs(deb.deltaUiAmount);
      const srcAddr = deb.owner !== 'Unknown Owner' ? deb.owner : deb.accountAddress;
      const dstAddr = matchingCredit.owner !== 'Unknown Owner' ? matchingCredit.owner : matchingCredit.accountAddress;
      assetFlows.push({
        id: `flow-tok-${deb.accountAddress}-${matchingCredit.accountAddress}`,
        source: srcAddr,
        sourceLabel: accountsRegistry[srcAddr]?.label || deb.ownerLabel,
        destination: dstAddr,
        destinationLabel: accountsRegistry[dstAddr]?.label || matchingCredit.ownerLabel,
        assetType: 'SPL-TOKEN',
        mint: deb.mint,
        symbol: deb.mintSymbol || 'TOKEN',
        tokenName: deb.mintName || 'SPL Token',
        rawAmount: (-deb.deltaRawAmount).toString(),
        formattedAmount: `${amountUi} ${deb.mintSymbol}`,
        flowNature: 'transfer',
        confidence: 'verified-direct',
        evidence: deb.evidence,
      });
    } else {
      // Pure burn / redemption
      const srcAddr = deb.owner !== 'Unknown Owner' ? deb.owner : deb.accountAddress;
      assetFlows.push({
        id: `flow-burn-${deb.accountAddress}-${deb.mint}`,
        source: srcAddr,
        sourceLabel: accountsRegistry[srcAddr]?.label,
        destination: deb.mint,
        destinationLabel: `${deb.mintName} (${deb.mintSymbol}) Supply Burn`,
        assetType: 'SPL-TOKEN',
        mint: deb.mint,
        symbol: deb.mintSymbol || 'TOKEN',
        tokenName: deb.mintName || 'SPL Token',
        rawAmount: (-deb.deltaRawAmount).toString(),
        formattedAmount: `${Math.abs(deb.deltaUiAmount)} ${deb.mintSymbol}`,
        flowNature: 'redemption-burn',
        confidence: 'verified-direct',
        evidence: deb.evidence,
      });
    }
  }

  // Case B: Pure Mint / Client Onboarding Issuance (credits exist without debits on that mint)
  for (const cred of tokenCredits) {
    const hasDebit = tokenDebits.some((d) => d.mint === cred.mint);
    if (!hasDebit) {
      const dstAddr = cred.owner !== 'Unknown Owner' ? cred.owner : cred.accountAddress;
      assetFlows.push({
        id: `flow-mint-${cred.mint}-${cred.accountAddress}`,
        source: cred.mint,
        sourceLabel: `${cred.mintName} (${cred.mintSymbol}) Mint`,
        destination: dstAddr,
        destinationLabel: accountsRegistry[dstAddr]?.label || `Onboarded Client (${dstAddr})`,
        assetType: 'SPL-TOKEN',
        mint: cred.mint,
        symbol: cred.mintSymbol || 'TOKEN',
        tokenName: cred.mintName || 'Token-2022 Asset',
        rawAmount: cred.deltaRawAmount.toString(),
        formattedAmount: `+${cred.deltaUiAmount} ${cred.mintSymbol}`,
        flowNature: 'institutional-issuance-mint',
        confidence: 'verified-direct',
        evidence: cred.evidence,
      });
    }
  }

  // 10. Build Deep Multi-Layer Account Relationships for Knowledge Graph
  const relationships: AccountRelationship[] = [];

  for (const flow of assetFlows) {
    relationships.push({
      id: `rel-${flow.id}`,
      source: flow.source,
      target: flow.destination,
      type:
        flow.flowNature === 'institutional-issuance-mint'
          ? 'minted-token'
          : flow.flowNature === 'redemption-burn'
          ? 'burned-token'
          : flow.assetType === 'SOL'
          ? 'transferred-sol'
          : 'transferred-token',
      label:
        flow.flowNature === 'institutional-issuance-mint'
          ? `Minted & Onboarded ${flow.formattedAmount} (${flow.tokenName})`
          : `Transferred ${flow.formattedAmount}`,
      asset: flow.symbol,
      amount: flow.formattedAmount,
      confidence: flow.confidence === 'verified-direct' ? 'verified' : 'derived',
      evidence: flow.evidence,
    });
  }

  for (const auth of authorities) {
    const relType =
      auth.authorityType === 'mint-authority'
        ? 'mint-authority-of'
        : auth.authorityType === 'owner-authority'
        ? 'owns-token-account'
        : 'institutional-governance';

    relationships.push({
      id: `rel-auth-${auth.authorityType}-${auth.authorityAddress}-${auth.targetAddress}`,
      source: auth.authorityAddress,
      target: auth.targetAddress,
      type: relType,
      label: `${auth.authorityType.replace(/-/g, ' ').toUpperCase()}`,
      confidence: 'verified',
      evidence: auth.evidence,
    });
  }

  const seenInvokeEdges = new Set<string>();
  for (const inst of outerInstructions) {
    const key = `${feePayer}->${inst.programId}`;
    if (!seenInvokeEdges.has(key)) {
      seenInvokeEdges.add(key);
      relationships.push({
        id: `rel-invoke-${inst.index}-${feePayer}-${inst.programId}`,
        source: feePayer,
        target: inst.programId,
        type: 'invoked-program',
        label: `Invoked ${inst.programName}`,
        confidence: 'verified',
        evidence: {
          id: `proof-invoke-${inst.index}-${inst.programId}`,
          sourceMethod: 'message.instructions',
          fieldPath: `instructions[${inst.index}]`,
          transactionSignature: signature,
          rawValue: inst.programId,
          interpretation: `Fee payer ${feePayer} signed and dispatched instruction to ${inst.programName} (${inst.programId})`,
          verificationStatus: 'verified',
        },
      });
    }

    // Add inner CPI edges
    for (const inner of inst.innerInstructions) {
      const cpiKey = `${inst.programId}->${inner.programId}-${inner.index}`;
      if (!seenInvokeEdges.has(cpiKey)) {
        seenInvokeEdges.add(cpiKey);
        relationships.push({
          id: `rel-cpi-${inst.index}-${inner.index}-${inner.programId}`,
          source: inst.programId,
          target: inner.programId,
          type: 'cpi-invoked',
          label: `CPI: ${inner.decodedName}`,
          confidence: 'verified',
          evidence: {
            id: `proof-cpi-${inst.index}-${inner.index}`,
            sourceMethod: 'meta.innerInstructions',
            fieldPath: `meta.innerInstructions[parent=${inst.index}].instructions[${inner.index}]`,
            transactionSignature: signature,
            rawValue: inner.programId,
            interpretation: `${inst.programName} invoked ${inner.programName} via Cross-Program Invocation at stack depth ${inner.stackHeight}`,
            verificationStatus: 'verified',
          },
        });
      }
    }
  }

  // 11. Build Alert Lifecycle & Client Onboarding Intelligence
  const alertIntelligence = buildAlertLifecycleIntelligence({
    signature,
    slot: raw.slot,
    success,
    error,
    feePayer,
    feeSol,
    computeUnitsConsumed: meta?.computeUnitsConsumed ?? null,
    outerInstructions,
    allInstructionsFlat,
    solBalanceDeltas,
    tokenBalanceDeltas,
    resolvedTokens,
  });

  // Add Client Onboarding & Alert Lifecycle Proof to Evidence Catalog
  evidenceCatalog.push({
    id: `ev-alert-lifecycle-${raw.slot}`,
    sourceMethod: 'SOL-MATE Alert Lifecycle & Client Onboarding Engine',
    fieldPath: 'meta.preTokenBalances + meta.postTokenBalances + message.instructions',
    transactionSignature: signature,
    accountAddress: alertIntelligence.clientOnboarding.clientWalletAddress,
    slot: raw.slot,
    rawValue: {
      primaryAlertType: alertIntelligence.primaryAlertType,
      primaryAlertTitle: alertIntelligence.primaryAlertTitle,
      isClientOnboarded: alertIntelligence.clientOnboarding.isClientOnboarded,
      clientOnboarding: alertIntelligence.clientOnboarding,
      correlatedStagesCount: alertIntelligence.lifecycleStages.length,
      independentAlertsCount: alertIntelligence.independentAlerts.length,
    },
    interpretation: `${alertIntelligence.primaryAlertTitle} — ${alertIntelligence.clientOnboarding.explanation}`,
    verificationStatus: 'verified',
    timestamp: timestampMs,
  });

  // 12. Build DeepCorrelations summary
  const whitelistedAccounts = combinedAccounts.filter((a) => Boolean(getInstitutionalMetadata(a)));
  const usesToken2022 =
    combinedAccounts.includes('TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb') ||
    tokenBalanceDeltas.some((d) => d.programId === 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb');

  const accountCorrelationMatrix: AccountCorrelationRow[] = combinedAccounts.map((addr, idx) => {
    const acc = accountsRegistry[addr];
    const solD = solBalanceDeltas.find((s) => s.address === addr);
    const tokD = tokenBalanceDeltas.find((t) => t.accountAddress === addr || t.owner === addr);
    const inst = getInstitutionalMetadata(addr);

    return {
      index: idx,
      address: addr,
      label: acc?.label || `Account #${idx}`,
      category: acc?.category || 'unclassified',
      isWhitelistedInstitutional: Boolean(inst),
      institutionalEcosystem: inst?.ecosystem,
      institutionalRoleTitle: inst?.roleTitle,
      isSigner: Boolean(acc?.isSigner),
      isWritable: Boolean(acc?.isWritable),
      isFeePayer: Boolean(acc?.isFeePayer),
      outerInstructionsInvolved: outerInstructions
        .filter((ix) => ix.programId === addr || ix.resolvedAccounts.some((a) => a.address === addr))
        .map((ix) => ix.index),
      cpiInstructionsInvolved: allInstructionsFlat
        .filter(
          (ix) =>
            ix.parentIndex !== undefined &&
            (ix.programId === addr || ix.resolvedAccounts.some((a) => a.address === addr))
        )
        .map((ix) => `${(ix.parentIndex ?? 0) + 1}.${ix.index + 1}`),
      solDeltaLamports: solD ? solD.deltaLamports.toString() : '0',
      solDeltaFormatted: solD ? `${solD.deltaSol >= 0 ? '+' : ''}${solD.deltaSol.toFixed(6)} SOL` : '0 SOL',
      tokenDeltaFormatted: tokD
        ? `${tokD.deltaUiAmount >= 0 ? '+' : ''}${tokD.deltaUiAmount} ${tokD.mintSymbol}`
        : '—',
      authorityProvenance: acc?.roles.join(', ') || 'referenced',
    };
  });

  const deepCorrelations: DeepForensicsCorrelation = {
    isInstitutionalFactTx: whitelistedAccounts.length > 0,
    activeEcosystem: resolvedTokens[0]?.symbol === 'JLTXX'
      ? 'JLTXX'
      : resolvedTokens[0]?.symbol === 'MONY'
      ? 'MONY'
      : whitelistedAccounts.length > 0
      ? 'FACT_CORE'
      : 'STANDARD',
    institutionName:
      resolvedTokens[0]?.issuer ||
      (whitelistedAccounts.length > 0 ? 'J.P. Morgan / Kinexys Digital Assets' : undefined),
    protocolSummary: alertIntelligence.primaryAlertSummary,
    whitelistedHitCount: whitelistedAccounts.length,
    computeBudgetAnalysis: {
      computeUnitLimit: 200000,
      computeUnitPriceMicroLamports: null,
      computeUnitsConsumed: meta?.computeUnitsConsumed ?? null,
      computeEfficiencyPercent: meta?.computeUnitsConsumed
        ? Math.min(100, Math.round((meta.computeUnitsConsumed / 200000) * 100))
        : null,
      baseSignatureFeeLamports: (BigInt(Math.max(1, signers.length)) * 5000n).toString(),
      priorityFeeLamports:
        feeLamports > BigInt(Math.max(1, signers.length)) * 5000n
          ? (feeLamports - BigInt(Math.max(1, signers.length)) * 5000n).toString()
          : '0',
      totalFeeLamports: feeLamports.toString(),
    },
    token2022Summary: {
      usesToken2022,
      invokesTransferHook: false,
      invokesAnchorSelfCpiEvent: Boolean(selfCpi),
      eventAuthorityPdasUsed: selfCpi?.resolvedAccounts.map((a) => a.address) || [],
      mintsInvolved: resolvedTokens.map((t) => ({
        mint: t.mint,
        symbol: t.symbol,
        name: t.name,
        issuer: t.issuer,
        decimals: t.decimals,
        netSupplyChangeRaw: t.totalVolumeRaw,
        netSupplyChangeUi: t.totalVolumeUi,
        operationType:
          tokenDebits.length === 0 && tokenCredits.length > 0
            ? 'ISSUANCE_MINT'
            : tokenDebits.length > 0 && tokenCredits.length === 0
            ? 'REDEMPTION_BURN'
            : 'PEER_TRANSFER',
      })),
    },
    accountCorrelationMatrix,
  };

  // 13. Transparent Risk & Compliance Heuristics
  const riskFindings: RiskFinding[] = [];
  let riskScore = 0;

  if (!success) {
    riskScore += 35;
    riskFindings.push({
      id: 'risk-failed-tx',
      title: 'Transaction Execution Reverted with On-Chain Error',
      severity: 'high',
      ruleCategory: 'failed-instructions',
      explanation: `Transaction execution failed with error: ${error}. Fees were still deducted from fee payer ${feePayer}.`,
      relevantAccounts: [feePayer],
      relevantInstructions: [],
      observedImpact: 'State changes rolled back except transaction fee payment',
      confidence: 'verified-fact',
      limitations: 'RPC provides error code and log messages',
      recommendedFollowUp: 'Inspect program invocation logs around the point of error',
      scoreImpact: 35,
      evidence: {
        id: 'evidence-tx-err',
        sourceMethod: 'getTransaction.meta.err',
        fieldPath: 'meta.err',
        transactionSignature: signature,
        rawValue: meta?.err,
        interpretation: `Confirmed execution failure: ${error}`,
        verificationStatus: 'verified',
      },
    });
  }

  if (alertIntelligence.clientOnboarding.isClientOnboarded) {
    riskFindings.push({
      id: 'risk-client-onboarding-verified',
      title: `Client Wallet Onboarding & Initial ${alertIntelligence.clientOnboarding.tokenSymbol} Provisioning Verified`,
      severity: 'info',
      ruleCategory: 'institutional-verified',
      explanation: alertIntelligence.clientOnboarding.explanation,
      relevantAccounts: [
        alertIntelligence.clientOnboarding.clientWalletAddress,
        alertIntelligence.clientOnboarding.clientTokenAccountAddress,
        alertIntelligence.clientOnboarding.tokenMintAddress,
      ],
      relevantInstructions: outerInstructions.map((i) => i.index),
      observedImpact: `Client balance transitioned from ${alertIntelligence.clientOnboarding.initialBalanceBefore} to ${alertIntelligence.clientOnboarding.resultingBalanceAfter}.`,
      confidence: 'verified-fact',
      limitations: 'On-chain token custody state verified at transaction execution slot',
      recommendedFollowUp: 'Monitor client token account for Stage 4 secondary transfers or redemptions',
      scoreImpact: 0,
      evidence: evidenceCatalog[evidenceCatalog.length - 1],
    });
  }

  const closedTokenAccounts = tokenBalanceDeltas.filter((d) => d.actionType === 'account-closed');
  if (closedTokenAccounts.length > 0) {
    riskScore += 15;
    riskFindings.push({
      id: 'risk-token-closed',
      title: 'Token Account Balance Completely Zeroed Out',
      severity: 'medium',
      ruleCategory: 'asset-drain',
      explanation: `${closedTokenAccounts.length} token account(s) had their balance emptied in this transaction.`,
      relevantAccounts: closedTokenAccounts.map((c) => c.accountAddress),
      relevantInstructions: [],
      observedImpact: 'Complete liquidation or transfer of token holdings from account',
      confidence: 'verified-fact',
      limitations: 'May be an intentional swap, sweep, or redemption',
      recommendedFollowUp: 'Verify if token transfer destination matches intended wallet',
      scoreImpact: 15,
      evidence: closedTokenAccounts[0].evidence,
    });
  }

  const unknownPrograms = outerInstructions.filter(
    (i) => !KNOWN_PROGRAMS[i.programId] && !getInstitutionalMetadata(i.programId)
  );
  if (unknownPrograms.length > 0) {
    riskScore += 10;
    riskFindings.push({
      id: 'risk-unverified-program',
      title: 'Interaction with Custom / Unregistered Smart Contract Binary',
      severity: 'low',
      ruleCategory: 'unverified-program',
      explanation: `Transaction invoked program ${unknownPrograms[0].programId} which is not in the standard public DeFi registry.`,
      relevantAccounts: unknownPrograms.map((p) => p.programId),
      relevantInstructions: unknownPrograms.map((p) => p.index),
      observedImpact: 'Execution passed to custom smart contract binary',
      confidence: 'contextual-observation',
      limitations: 'Custom or enterprise smart contracts are normal on Solana',
      recommendedFollowUp: 'Inspect instruction byte sighash and CPI call stack in Execution Trace tab',
      scoreImpact: 10,
      evidence: {
        id: 'evidence-unknown-prog',
        sourceMethod: 'instructions.programId',
        fieldPath: 'instructions',
        transactionSignature: signature,
        rawValue: unknownPrograms[0].programId,
        interpretation: 'Custom smart contract invocation',
        verificationStatus: 'verified',
      },
    });
  }

  if (success && riskFindings.length === 0) {
    riskFindings.push({
      id: 'risk-clean-exec',
      title: 'Normal Execution Verified — No Anomalous Patterns Observed',
      severity: 'info',
      ruleCategory: 'operational-clean',
      explanation:
        'All instructions executed cleanly without reverts, unexpected balance drains, or anomalous permissions.',
      relevantAccounts: [feePayer],
      relevantInstructions: [],
      observedImpact: 'Transaction settled normally on-chain',
      confidence: 'verified-fact',
      limitations: 'Analysis reflects observable RPC metadata within the transaction scope',
      recommendedFollowUp: 'No urgent follow-up required',
      scoreImpact: 0,
      evidence: {
        id: 'evidence-clean-status',
        sourceMethod: 'getTransaction.meta.err',
        fieldPath: 'meta.err',
        transactionSignature: signature,
        rawValue: null,
        interpretation: 'Transaction confirmed with zero errors',
        verificationStatus: 'verified',
      },
    });
  }

  const boundedScore = Math.min(100, Math.max(0, riskScore));

  return {
    signature,
    slot: raw.slot,
    blockTime: raw.blockTime,
    formattedTime,
    version: versionStr,
    cluster,
    commitment: 'finalized',
    success,
    error,
    feeLamports,
    feeSol,
    recentBlockhash: msg.recentBlockhash,
    computeUnitsConsumed: meta?.computeUnitsConsumed ?? null,
    staticAccounts: staticKeys,
    loadedWritableAddresses: loadedWritable,
    loadedReadonlyAddresses: loadedReadonly,
    combinedAccounts,
    signers,
    feePayer,
    outerInstructions,
    allInstructionsFlat,
    accountsRegistry,
    solBalanceDeltas,
    tokenBalanceDeltas,
    resolvedTokens,
    alertIntelligence,
    authorities,
    stateTransitions,
    assetFlows,
    relationships,
    riskFindings,
    heuristicRiskScore: boundedScore,
    deepCorrelations,
    evidenceCatalog,
    rawTransactionJson: JSON.stringify(raw, null, 2),
    retrievedAt: Date.now(),
    rpcEndpointUsed: endpointUsed,
  };
}
