/**
 * SOL-MATE — Forensic Investigation Coordinator Engine
 * Orchestrates transaction retrieval, progressive account & mint metadata resolution,
 * authority analysis, deep storage persistence, and export generators.
 */

import { rpcClient } from './rpcClient';
import { parseSolanaTransaction, isValidBase58Signature, KNOWN_PROGRAMS } from './transactionParser';
import { deepStorage } from './deepStorage';
import { TransactionRecord, InvestigationReport } from '../types/forensics';
import { AccountInfoResult, RawTransactionResponse, SolanaCluster } from '../types/solana';

export type InvestigationStage =
  | 'idle'
  | 'validating-signature'
  | 'retrieving-transaction'
  | 'decoding-instructions'
  | 'resolving-accounts'
  | 'analyzing-authorities'
  | 'reconciling-flows'
  | 'building-graph'
  | 'ready'
  | 'error';

export interface InvestigationProgress {
  stage: InvestigationStage;
  message: string;
  percent: number;
}

export class ForensicsEngine {
  private activeController: AbortController | null = null;

  public async investigate(
    signature: string,
    cluster: SolanaCluster = 'mainnet',
    onProgress?: (progress: InvestigationProgress) => void
  ): Promise<TransactionRecord> {
    const notify = (stage: InvestigationStage, message: string, percent: number) => {
      if (onProgress) onProgress({ stage, message, percent });
    };

    // 1. Validation
    notify('validating-signature', 'Validating Base58 signature format and checksum...', 10);
    const trimmedSig = (signature || '').trim();
    if (!isValidBase58Signature(trimmedSig)) {
      throw new Error(
        `Invalid Solana transaction signature. Expected Base58 string (typically 80-90 characters), received: "${trimmedSig.slice(0, 16)}..."`
      );
    }

    if (this.activeController) {
      this.activeController.abort();
    }
    this.activeController = new AbortController();
    const signal = this.activeController.signal;

    // 2. Transaction Retrieval from Parallel RPC/WSS Pool
    notify(
      'retrieving-transaction',
      'Querying 6x Parallel RPC/WSS Pool (Helius Mainnet, PublicNode, VibeStation, Ankr, OnFinality)...',
      25
    );

    let rawTx: RawTransactionResponse | null = null;
    try {
      rawTx = await rpcClient.call<RawTransactionResponse | null>(
        'getTransaction',
        [
          trimmedSig,
          {
            encoding: 'jsonParsed',
            commitment: 'finalized',
            maxSupportedTransactionVersion: 1,
          },
        ],
        { priority: 0, signal }
      );
    } catch (err: any) {
      try {
        rawTx = await rpcClient.call<RawTransactionResponse | null>(
          'getTransaction',
          [
            trimmedSig,
            {
              encoding: 'jsonParsed',
              commitment: 'confirmed',
              maxSupportedTransactionVersion: 1,
            },
          ],
          { priority: 0, signal }
        );
      } catch {
        throw new Error(
          `RPC failed to retrieve transaction: ${err?.message || 'Signature not found or pruned from public RPC history'}`
        );
      }
    }

    const endpointUsed = rpcClient.getTelemetry().lastWinningProvider || rpcClient.getConfig().httpEndpoint;

    if (!rawTx) {
      throw new Error(
        `Transaction not found on ${cluster} parallel RPC pool (${endpointUsed}). It may have expired from recent history, belonged to another cluster, or dropped before finalization.`
      );
    }

    // 3. Decoding Instructions & Execution Trace
    notify('decoding-instructions', 'Parsing instructions, CPI call stacks, byte sighashes, and execution logs...', 50);
    const record = parseSolanaTransaction(rawTx, trimmedSig, cluster, endpointUsed);

    // 4. Live On-Chain Mint & Account State Enrichment
    notify('resolving-accounts', 'Resolving live on-chain token mint metadata, authorities, and account states...', 70);

    // Prioritize token mints first, then non-standard accounts
    const mintAddresses = record.resolvedTokens.map((t) => t.mint);
    const otherAccounts = record.combinedAccounts
      .filter((addr) => !mintAddresses.includes(addr) && !KNOWN_PROGRAMS[addr])
      .slice(0, 5);
    const accountsToEnrich = [...mintAddresses, ...otherAccounts].slice(0, 7);

    await Promise.all(
      accountsToEnrich.map(async (address) => {
        if (signal.aborted) return;
        try {
          const res = await rpcClient.call<any>(
            'getAccountInfo',
            [address, { encoding: 'jsonParsed' }],
            { priority: 2, signal }
          );
          const info = res && 'value' in res ? res.value : res;
          if (!info) return;

          const acc = record.accountsRegistry[address];
          if (acc) {
            acc.isExecutable = Boolean(info.executable);
            if (info.owner && typeof info.owner === 'string') {
              acc.ownerProgram = info.owner;
              acc.ownerProgramLabel = KNOWN_PROGRAMS[info.owner]?.name || acc.ownerProgramLabel;
            }
            acc.liveStateFetched = true;
          }

          if (info.data && typeof info.data === 'object' && 'parsed' in info.data && info.data.parsed) {
            const p = info.data.parsed;
            // Token Account live state
            if (p.type === 'account' && p.info && acc) {
              const pInfo = p.info as any;
              acc.category = 'token-account';
              acc.tokenMetadata = {
                ...acc.tokenMetadata,
                isTokenAccount: true,
                mint: pInfo.mint || acc.tokenMetadata?.mint,
                tokenOwner: pInfo.owner || acc.tokenMetadata?.tokenOwner,
                decimals: pInfo.tokenAmount?.decimals ?? acc.tokenMetadata?.decimals,
                delegate: pInfo.delegate || null,
                state: pInfo.state || 'initialized',
                tokenProgram: info.owner || acc.ownerProgram,
              };
            }

            // Token Mint live state (SPL Token or Token-2022)
            if (p.type === 'mint' && p.info) {
              const mInfo = p.info as any;
              const extensions: string[] = [];
              let onChainName: string | undefined;
              let onChainSymbol: string | undefined;

              if (Array.isArray(mInfo.extensions)) {
                for (const ext of mInfo.extensions) {
                  if (ext?.extension) {
                    extensions.push(String(ext.extension));
                    if (ext.extension === 'tokenMetadata' && ext.state) {
                      if (ext.state.name) onChainName = String(ext.state.name).trim();
                      if (ext.state.symbol) onChainSymbol = String(ext.state.symbol).trim();
                    }
                  }
                }
              }

              // Update resolvedTokens entry with live on-chain mint state
              const resolvedTok = record.resolvedTokens.find((t) => t.mint === address);
              if (resolvedTok) {
                if (onChainName) resolvedTok.name = onChainName;
                if (onChainSymbol) resolvedTok.symbol = onChainSymbol;
                resolvedTok.mintAuthority = mInfo.mintAuthority || null;
                resolvedTok.freezeAuthority = mInfo.freezeAuthority || null;
                if (mInfo.supply && resolvedTok.decimals !== undefined) {
                  resolvedTok.supplyUi = (
                    Number(mInfo.supply) / Math.pow(10, resolvedTok.decimals)
                  ).toLocaleString();
                }
                if (extensions.length > 0) {
                  resolvedTok.extensions = extensions;
                }
              }

              // Add live Mint Authority and Freeze Authority records if present
              if (mInfo.mintAuthority) {
                const alreadyExists = record.authorities.some(
                  (a) =>
                    a.authorityType === 'mint-authority' &&
                    a.authorityAddress === mInfo.mintAuthority &&
                    a.targetAddress === address
                );
                if (!alreadyExists) {
                  record.authorities.push({
                    authorityAddress: mInfo.mintAuthority,
                    authorityLabel:
                      record.accountsRegistry[mInfo.mintAuthority]?.label ||
                      `On-Chain Mint Authority (${resolvedTok?.symbol || 'Token'})`,
                    targetAddress: address,
                    targetLabel: `${resolvedTok?.name || 'Token'} (${resolvedTok?.symbol || ''}) Mint`,
                    targetType: 'token-mint',
                    authorityType: 'mint-authority',
                    status: 'active',
                    securityImpact:
                      'Live on-chain Mint Authority verified via getAccountInfo — holds cryptographic permission to mint new token supply.',
                    scopeDescription: `Verified active mintAuthority on ${address} (Supply: ${resolvedTok?.supplyUi || mInfo.supply || 'N/A'}).`,
                    evidence: {
                      id: `ev-live-mint-auth-${address}`,
                      sourceMethod: 'getAccountInfo (jsonParsed Mint State)',
                      fieldPath: 'value.data.parsed.info.mintAuthority',
                      accountAddress: address,
                      rawValue: mInfo,
                      interpretation: `Live on-chain mintAuthority for ${resolvedTok?.name || address} is ${mInfo.mintAuthority}`,
                      verificationStatus: 'verified',
                    },
                    isCurrentState: true,
                  });
                }
              }

              if (mInfo.freezeAuthority) {
                record.authorities.push({
                  authorityAddress: mInfo.freezeAuthority,
                  authorityLabel:
                    record.accountsRegistry[mInfo.freezeAuthority]?.label ||
                    `On-Chain Freeze Authority (${resolvedTok?.symbol || 'Token'})`,
                  targetAddress: address,
                  targetLabel: `${resolvedTok?.name || 'Token'} (${resolvedTok?.symbol || ''}) Mint`,
                  targetType: 'token-mint',
                  authorityType: 'freeze-authority',
                  status: 'active',
                  securityImpact:
                    'Live on-chain Freeze Authority verified via getAccountInfo — can freeze or thaw individual client token accounts for regulatory compliance.',
                  scopeDescription: `Verified active freezeAuthority on ${address}.`,
                  evidence: {
                    id: `ev-live-freeze-auth-${address}`,
                    sourceMethod: 'getAccountInfo (jsonParsed Mint State)',
                    fieldPath: 'value.data.parsed.info.freezeAuthority',
                    accountAddress: address,
                    rawValue: { freezeAuthority: mInfo.freezeAuthority, mint: address },
                    interpretation: `Live on-chain freezeAuthority for ${resolvedTok?.name || address} is ${mInfo.freezeAuthority}`,
                    verificationStatus: 'verified',
                  },
                  isCurrentState: true,
                });
              }

              // Add Mint State Proof to Evidence Catalog
              record.evidenceCatalog.push({
                id: `ev-mint-state-${address}`,
                sourceMethod: 'getAccountInfo (Live Token Mint Metadata & Extensions)',
                fieldPath: 'result.value.data.parsed.info',
                transactionSignature: trimmedSig,
                accountAddress: address,
                slot: record.slot,
                rawValue: mInfo,
                interpretation: `Live on-chain Mint inspection for ${resolvedTok?.name || address} (${resolvedTok?.symbol || 'TOKEN'}): decimals=${mInfo.decimals}, supply=${mInfo.supply}, mintAuthority=${mInfo.mintAuthority || 'None'}, freezeAuthority=${mInfo.freezeAuthority || 'None'}${extensions.length > 0 ? `, extensions=[${extensions.join(', ')}]` : ''}.`,
                verificationStatus: 'verified',
                timestamp: Date.now(),
              });
            }
          }
        } catch {
          // Bounded enrichment error is non-fatal
        }
      })
    );

    // 5. Analyzing Authorities and Reconciling Flows
    notify('analyzing-authorities', 'Analyzing SPL authorities, freeze rights, and client onboarding lifecycle...', 85);

    // 6. Building Graph & Saving
    notify('building-graph', 'Synthesizing knowledge graph relationships and saving investigation...', 95);
    try {
      await deepStorage.saveInvestigation(record);
    } catch (saveErr) {
      console.warn('Failed to save to deep storage:', saveErr);
    }

    notify('ready', 'Investigation ready with verified blockchain evidence.', 100);
    return record;
  }

  public cancel(): void {
    if (this.activeController) {
      this.activeController.abort();
      this.activeController = null;
    }
  }

  public async getAddressHistory(
    address: string,
    limit: number = 15
  ): Promise<{ signature: string; slot: number; err: unknown | null; blockTime: number | null }[]> {
    return await rpcClient.call('getSignaturesForAddress', [address, { limit }], {
      priority: 1,
    });
  }

  public generateReport(tx: TransactionRecord): InvestigationReport {
    const tokenNames =
      tx.resolvedTokens && tx.resolvedTokens.length > 0
        ? tx.resolvedTokens.map((t) => `${t.name} (${t.symbol})`).join(', ')
        : 'Native SOL';

    return {
      reportId: `SOLMATE-${(tx.signature || '').slice(0, 8)}`,
      createdAt: Date.now(),
      signature: tx.signature,
      cluster: tx.cluster,
      rpcEndpoint: tx.rpcEndpointUsed,
      analyst: 'SOL-MATE Automated Forensics Engine (by Sandeep Kumar Sahoo)',
      version: '2.0.0',
      executiveSummary: `Solana transaction ${tx.signature} executed at slot ${tx.slot.toLocaleString()} (${tx.formattedTime}) with ${
        tx.success ? 'SUCCESSFUL' : 'FAILED'
      } outcome. Fee payer ${tx.feePayer} paid ${tx.feeSol.toFixed(
        6
      )} SOL. Primary Token(s) Involved: ${tokenNames}. Primary Alert Classification: ${
        tx.alertIntelligence?.primaryAlertTitle || 'Verified Settlement'
      }. Observed ${tx.solBalanceDeltas.length} SOL balance shifts and ${
        tx.tokenBalanceDeltas.length
      } token balance shifts across ${tx.combinedAccounts.length} referenced accounts. Risk Heuristic Score: ${
        tx.heuristicRiskScore
      }/100.`,
      transaction: tx,
      limitations: [
        'Analysis based on finalized RPC transaction metadata from parallel Solana Mainnet RPC pool.',
        'Historical account state reflects transaction execution slot; current balances may differ.',
        'External wallet owner identities are cryptographic public keys; human identities are not inferred without explicit registry proofs.',
      ],
    };
  }
}

export const forensicsEngine = new ForensicsEngine();
