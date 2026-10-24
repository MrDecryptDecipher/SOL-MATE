/**
 * SOL-MATE — Solana Core Type Definitions
 * Strict types for Solana RPC responses, versioned transactions, and account metadata.
 */

export type Commitment = 'processed' | 'confirmed' | 'finalized';

export type SolanaCluster = 'mainnet' | 'devnet' | 'testnet' | 'custom';

export interface RpcEndpointConfig {
  name: string;
  cluster: SolanaCluster;
  httpUrl: string;
  wsUrl: string;
  maxRequestsPerSecond: number;
}

export interface RawJsonRpcResponse<T = unknown> {
  jsonrpc: '2.0';
  id: string | number;
  result?: T;
  error?: {
    code: number;
    message: string;
    data?: unknown;
  };
}

export interface UiTokenAmount {
  amount: string;
  decimals: number;
  uiAmount: number | null;
  uiAmountString: string;
}

export interface RawTokenBalance {
  accountIndex: number;
  mint: string;
  owner?: string;
  programId?: string;
  uiTokenAmount: UiTokenAmount;
}

export interface RawLoadedAddresses {
  readonly: string[];
  writable: string[];
}

export interface RawInnerInstruction {
  index: number;
  instructions: RawInstruction[];
}

export interface RawInstruction {
  programIdIndex?: number;
  programId?: string;
  accounts?: number[] | string[];
  data?: string;
  parsed?: {
    type: string;
    info: Record<string, unknown>;
  };
  stackHeight?: number;
}

export interface RawTransactionMeta {
  err: unknown | null;
  fee: number;
  preBalances: number[];
  postBalances: number[];
  preTokenBalances?: RawTokenBalance[];
  postTokenBalances?: RawTokenBalance[];
  innerInstructions?: RawInnerInstruction[];
  logMessages?: string[];
  computeUnitsConsumed?: number;
  loadedAddresses?: RawLoadedAddresses;
  returnData?: {
    programId: string;
    data: [string, string];
  };
}

export interface RawTransactionResponse {
  slot: number;
  blockTime: number | null;
  version?: 'legacy' | 0 | number;
  transaction: {
    signatures: string[];
    message: {
      accountKeys: (string | { pubkey: string; signer: boolean; writable: boolean; source?: string })[];
      header?: {
        numReadonlySignedAccounts: number;
        numReadonlyUnsignedAccounts: number;
        numRequiredSignatures: number;
      };
      instructions: RawInstruction[];
      recentBlockhash: string;
      addressTableLookups?: {
        accountKey: string;
        writableIndexes: number[];
        readonlyIndexes: number[];
      }[];
    };
  };
  meta: RawTransactionMeta | null;
}

export interface AccountInfoResult {
  context: { slot: number };
  value: {
    data: [string, string] | { parsed?: Record<string, unknown>; program?: string };
    executable: boolean;
    lamports: number;
    owner: string;
    rentEpoch?: number;
    space?: number;
  } | null;
}
