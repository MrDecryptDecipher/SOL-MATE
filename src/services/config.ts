/**
 * SOL-MATE — Centralized RPC & Parallel Multi-Endpoint Configuration
 * Manages parallel RPC + WebSocket pools (Helius, PublicNode, OnFinality, Solana Vibe Station,
 * Ankr, Solana Mainnet-Beta, Devnet, Testnet), rate limit policies, and cluster configurations.
 */

import { Commitment, SolanaCluster } from '../types/solana';

export interface ParallelEndpointConfig {
  id: string;
  name: string;
  cluster?: SolanaCluster;
  provider?: string;
  http: string;
  ws: string;
  enabled: boolean;
}

export interface AppConfig {
  network: SolanaCluster;
  httpEndpoint: string;
  wsEndpoint: string;
  enableParallelPool: boolean;
  parallelEndpoints: ParallelEndpointConfig[];
  commitment: Commitment;
  maxRequestsPerSecond: number;
  safetyMarginRequestsPerSecond: number;
  requestTimeoutMs: number;
  maxRetries: number;
  cacheTtlMs: number;
  maxHistoryLimit: number;
  maxGraphNodes: number;
}

export const DEFAULT_PARALLEL_ENDPOINTS: ParallelEndpointConfig[] = [
  {
    id: 'helius-mainnet',
    name: 'Helius Mainnet RPC (Archival)',
    cluster: 'mainnet',
    provider: 'Helius',
    http: 'https://mainnet.helius-rpc.com/?api-key=dea43e7c-2806-4d5e-9241-b010e5c96762',
    ws: 'wss://mainnet.helius-rpc.com/?api-key=dea43e7c-2806-4d5e-9241-b010e5c96762',
    enabled: true,
  },
  {
    id: 'publicnode-mainnet',
    name: 'PublicNode Mainnet',
    cluster: 'mainnet',
    provider: 'PublicNode',
    http: 'https://solana-rpc.publicnode.com',
    ws: 'wss://solana-rpc.publicnode.com',
    enabled: true,
  },
  {
    id: 'onfinality-mainnet',
    name: 'OnFinality Public',
    cluster: 'mainnet',
    provider: 'OnFinality',
    http: 'https://solana.api.onfinality.io/public',
    ws: 'wss://solana.api.onfinality.io/public-ws',
    enabled: true,
  },
  {
    id: 'solanavibestation-mainnet',
    name: 'Solana Vibe Station Public',
    cluster: 'mainnet',
    provider: 'Solana Vibe Station',
    http: 'https://public.rpc.solanavibestation.com',
    ws: 'wss://public.rpc.solanavibestation.com',
    enabled: false,
  },
  {
    id: 'ankr-mainnet',
    name: 'Ankr Mainnet Public',
    cluster: 'mainnet',
    provider: 'Ankr',
    http: 'https://rpc.ankr.com/solana',
    ws: 'wss://rpc.ankr.com/solana/ws',
    enabled: false,
  },
  {
    id: 'solana-mainnet-beta',
    name: 'Solana Official Mainnet-Beta',
    cluster: 'mainnet',
    provider: 'Solana Labs',
    http: 'https://api.mainnet-beta.solana.com',
    ws: 'wss://api.mainnet-beta.solana.com',
    enabled: false,
  },
];

export const DEVNET_PARALLEL_ENDPOINTS: ParallelEndpointConfig[] = [
  {
    id: 'solana-devnet',
    name: 'Solana Official Devnet',
    cluster: 'devnet',
    provider: 'Solana Labs',
    http: 'https://api.devnet.solana.com',
    ws: 'wss://api.devnet.solana.com',
    enabled: true,
  },
  {
    id: 'ankr-devnet',
    name: 'Ankr Devnet Public',
    cluster: 'devnet',
    provider: 'Ankr',
    http: 'https://rpc.ankr.com/solana_devnet',
    ws: 'wss://rpc.ankr.com/solana_devnet/ws',
    enabled: true,
  },
];

export const TESTNET_PARALLEL_ENDPOINTS: ParallelEndpointConfig[] = [
  {
    id: 'solana-testnet',
    name: 'Solana Official Testnet',
    cluster: 'testnet',
    provider: 'Solana Labs',
    http: 'https://api.testnet.solana.com',
    ws: 'wss://api.testnet.solana.com',
    enabled: true,
  },
];

export const DEFAULT_CONFIG: AppConfig = {
  network: 'mainnet',
  httpEndpoint: 'https://mainnet.helius-rpc.com/?api-key=dea43e7c-2806-4d5e-9241-b010e5c96762',
  wsEndpoint: 'wss://mainnet.helius-rpc.com/?api-key=dea43e7c-2806-4d5e-9241-b010e5c96762',
  enableParallelPool: true,
  parallelEndpoints: DEFAULT_PARALLEL_ENDPOINTS,
  commitment: 'finalized',
  maxRequestsPerSecond: 10,
  safetyMarginRequestsPerSecond: 8,
  requestTimeoutMs: 15000,
  maxRetries: 3,
  cacheTtlMs: 300000, // 5 minutes cache for immutable transaction data
  maxHistoryLimit: 25,
  maxGraphNodes: 60,
};

export const PRESET_ENDPOINTS: Record<
  string,
  { http: string; ws: string; label: string; cluster: SolanaCluster; provider: string }
> = {
  'helius-mainnet': {
    http: 'https://mainnet.helius-rpc.com/?api-key=dea43e7c-2806-4d5e-9241-b010e5c96762',
    ws: 'wss://mainnet.helius-rpc.com/?api-key=dea43e7c-2806-4d5e-9241-b010e5c96762',
    label: 'Helius Mainnet (Full Archival + High Speed)',
    cluster: 'mainnet',
    provider: 'Helius',
  },
  'publicnode-mainnet': {
    http: 'https://solana-rpc.publicnode.com',
    ws: 'wss://solana-rpc.publicnode.com',
    label: 'PublicNode Open Mainnet (High Throughput)',
    cluster: 'mainnet',
    provider: 'PublicNode',
  },
  'solanavibestation-mainnet': {
    http: 'https://public.rpc.solanavibestation.com',
    ws: 'wss://public.rpc.solanavibestation.com',
    label: 'Solana Vibe Station Public Mainnet',
    cluster: 'mainnet',
    provider: 'Solana Vibe Station',
  },
  'ankr-mainnet': {
    http: 'https://rpc.ankr.com/solana',
    ws: 'wss://rpc.ankr.com/solana/ws',
    label: 'Ankr Public Mainnet-Beta',
    cluster: 'mainnet',
    provider: 'Ankr',
  },
  'onfinality-mainnet': {
    http: 'https://solana.api.onfinality.io/public',
    ws: 'wss://solana.api.onfinality.io/public-ws',
    label: 'OnFinality Public Mainnet (5 req/sec)',
    cluster: 'mainnet',
    provider: 'OnFinality',
  },
  'solana-mainnet-beta': {
    http: 'https://api.mainnet-beta.solana.com',
    ws: 'wss://api.mainnet-beta.solana.com',
    label: 'Solana Labs Official Mainnet-Beta',
    cluster: 'mainnet',
    provider: 'Solana Labs',
  },
  'solana-devnet': {
    http: 'https://api.devnet.solana.com',
    ws: 'wss://api.devnet.solana.com',
    label: 'Solana Labs Official Devnet',
    cluster: 'devnet',
    provider: 'Solana Labs',
  },
  'ankr-devnet': {
    http: 'https://rpc.ankr.com/solana_devnet',
    ws: 'wss://rpc.ankr.com/solana_devnet/ws',
    label: 'Ankr Public Solana Devnet',
    cluster: 'devnet',
    provider: 'Ankr',
  },
  'solana-testnet': {
    http: 'https://api.testnet.solana.com',
    ws: 'wss://api.testnet.solana.com',
    label: 'Solana Labs Official Testnet',
    cluster: 'testnet',
    provider: 'Solana Labs',
  },
};

export const FREE_RPC_PROVIDERS_CATALOG = [
  { name: 'Helius', clusters: ['Mainnet-beta', 'Devnet'], status: 'Active in Pool', url: 'https://mainnet.helius-rpc.com' },
  { name: 'PublicNode', clusters: ['Mainnet-beta'], status: 'Active in Pool', url: 'https://solana-rpc.publicnode.com' },
  { name: 'Solana Vibe Station', clusters: ['Mainnet-beta'], status: 'Active in Pool', url: 'https://public.rpc.solanavibestation.com' },
  { name: 'Ankr', clusters: ['Mainnet-beta', 'Devnet'], status: 'Active in Pool', url: 'https://rpc.ankr.com/solana' },
  { name: 'OnFinality', clusters: ['Mainnet-beta'], status: 'Active in Pool', url: 'https://solana.api.onfinality.io/public' },
  { name: 'Solana Official Cluster', clusters: ['Mainnet-beta', 'Devnet', 'Testnet'], status: 'Active in Pool', url: 'https://api.mainnet-beta.solana.com' },
  { name: 'OrbitFlare', clusters: ['Mainnet-beta', 'Devnet'], status: 'Supported Custom Preset', url: 'https://orbitflare.com' },
  { name: 'QuickNode (x402-enabled)', clusters: ['Mainnet-beta', 'Devnet'], status: 'Supported Custom Preset', url: 'https://quicknode.com' },
  { name: 'Chainstack', clusters: ['Mainnet-beta', 'Devnet'], status: 'Supported Custom Preset', url: 'https://chainstack.com' },
  { name: 'Syndica', clusters: ['Mainnet-beta'], status: 'Supported Custom Preset', url: 'https://syndica.io' },
  { name: 'Blockdaemon', clusters: ['Mainnet-beta'], status: 'Supported Custom Preset', url: 'https://blockdaemon.com' },
  { name: 'GetBlock', clusters: ['Mainnet-beta'], status: 'Supported Custom Preset', url: 'https://getblock.io' },
  { name: 'FluxRPC', clusters: ['Mainnet-beta'], status: 'Supported Custom Preset', url: 'https://fluxrpc.com' },
  { name: 'InstantNodes', clusters: ['Mainnet-beta'], status: 'Supported Custom Preset', url: 'https://instantnodes.io' },
];

const STORAGE_KEY = 'solmate_config_v4';

export function loadAppConfig(): AppConfig {
  if (typeof window === 'undefined') return DEFAULT_CONFIG;
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return DEFAULT_CONFIG;
    const parsed = JSON.parse(raw);
    return {
      ...DEFAULT_CONFIG,
      ...parsed,
      parallelEndpoints:
        Array.isArray(parsed.parallelEndpoints) && parsed.parallelEndpoints.length > 0
          ? parsed.parallelEndpoints
          : DEFAULT_PARALLEL_ENDPOINTS,
    };
  } catch {
    return DEFAULT_CONFIG;
  }
}

export function saveAppConfig(config: AppConfig): void {
  if (typeof window === 'undefined') return;
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(config));
  } catch (err) {
    console.error('Failed to save config to localStorage:', err);
  }
}
