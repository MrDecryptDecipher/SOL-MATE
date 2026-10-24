/**
 * SOL-MATE — Parallel Multi-Endpoint Rate-Limited Robust RPC Client
 * Queries OnFinality, PublicNode, and Helius Mainnet concurrently in parallel.
 * Prioritizes the fastest non-null archival response while gracefully handling HTTP 429
 * rate limits, pruned history (result: null), in-flight deduplication, and caching.
 */

import { AppConfig, DEFAULT_PARALLEL_ENDPOINTS, loadAppConfig, ParallelEndpointConfig } from './config';
import { wsClient } from './wsClient';
import { RawJsonRpcResponse } from '../types/solana';

export interface RpcTelemetry {
  requestsInWindow: number;
  totalRequests: number;
  totalSuccess: number;
  totalRateLimits: number;
  totalErrors: number;
  queueDepth: number;
  averageLatencyMs: number;
  lastLatencyMs: number;
  providerHealth: 'healthy' | 'degraded' | 'rate-limited' | 'offline' | 'checking';
  lastHealthCheckTime: number;
  lastWinningProvider: string;
  activePoolCount: number;
}

interface QueuedRequest<T> {
  id: string;
  method: string;
  params: unknown[];
  priority: number; // 0 = highest (primary transaction), 1 = enrichment, 2 = optional
  resolve: (value: T) => void;
  reject: (reason: Error) => void;
  enqueuedAt: number;
  signal?: AbortSignal;
}

export class RpcClient {
  private config: AppConfig;
  private queue: QueuedRequest<any>[] = [];
  private isProcessing = false;
  private inFlightDedupe = new Map<string, Promise<any>>();
  private responseCache = new Map<string, { timestamp: number; data: any }>();
  private requestTimestamps: number[] = [];

  private telemetry: RpcTelemetry = {
    requestsInWindow: 0,
    totalRequests: 0,
    totalSuccess: 0,
    totalRateLimits: 0,
    totalErrors: 0,
    queueDepth: 0,
    averageLatencyMs: 0,
    lastLatencyMs: 0,
    providerHealth: 'checking',
    lastHealthCheckTime: 0,
    lastWinningProvider: 'Parallel Pool (3 Nodes)',
    activePoolCount: 3,
  };

  private telemetryListeners = new Set<(telemetry: RpcTelemetry) => void>();

  constructor(customConfig?: AppConfig) {
    this.config = customConfig || loadAppConfig();
    this.telemetry.activePoolCount = this.getActiveEndpoints().length;
    this.startRateWindowTracker();
  }

  public updateConfig(newConfig: AppConfig): void {
    this.config = newConfig;
    this.telemetry.activePoolCount = this.getActiveEndpoints().length;
    this.notifyTelemetry();
  }

  public getConfig(): AppConfig {
    return this.config;
  }

  public getActiveEndpoints(): ParallelEndpointConfig[] {
    if (this.config.network === 'mainnet' && this.config.enableParallelPool !== false) {
      const enabled = (this.config.parallelEndpoints || DEFAULT_PARALLEL_ENDPOINTS).filter((e) => e.enabled);
      if (enabled.length > 0) {
        // Also include custom primary httpEndpoint if it's not already in the list
        const hasPrimary = enabled.some((e) => e.http === this.config.httpEndpoint);
        if (!hasPrimary && this.config.httpEndpoint) {
          return [
            {
              id: 'custom-primary',
              name: 'Primary Custom RPC',
              http: this.config.httpEndpoint,
              ws: this.config.wsEndpoint,
              enabled: true,
            },
            ...enabled,
          ];
        }
        return enabled;
      }
    }

    return [
      {
        id: 'primary',
        name: 'Primary RPC',
        http: this.config.httpEndpoint,
        ws: this.config.wsEndpoint,
        enabled: true,
      },
    ];
  }

  public getTelemetry(): RpcTelemetry {
    return {
      ...this.telemetry,
      queueDepth: this.queue.length,
      activePoolCount: this.getActiveEndpoints().length,
    };
  }

  public subscribeTelemetry(listener: (telemetry: RpcTelemetry) => void): () => void {
    this.telemetryListeners.add(listener);
    listener(this.getTelemetry());
    return () => this.telemetryListeners.delete(listener);
  }

  private notifyTelemetry(): void {
    this.telemetry.queueDepth = this.queue.length;
    this.telemetry.activePoolCount = this.getActiveEndpoints().length;
    for (const listener of this.telemetryListeners) {
      try {
        listener(this.getTelemetry());
      } catch (err) {
        console.error('Error in telemetry listener:', err);
      }
    }
  }

  private startRateWindowTracker(): void {
    if (typeof window === 'undefined') return;
    setInterval(() => {
      const now = Date.now();
      this.requestTimestamps = this.requestTimestamps.filter((t) => now - t < 1000);
      this.telemetry.requestsInWindow = this.requestTimestamps.length;
      this.notifyTelemetry();
    }, 250);
  }

  private getCacheKey(method: string, params: unknown[]): string {
    return `${this.config.network}:${method}:${JSON.stringify(params)}`;
  }

  public clearCache(): void {
    this.responseCache.clear();
    this.inFlightDedupe.clear();
  }

  /**
   * Primary entry point for making JSON-RPC calls.
   */
  public async call<T>(
    method: string,
    params: unknown[] = [],
    options: {
      priority?: number;
      skipCache?: boolean;
      signal?: AbortSignal;
    } = {}
  ): Promise<T> {
    const { priority = 1, skipCache = false, signal } = options;
    const cacheKey = this.getCacheKey(method, params);

    // 1. Check cache for valid entries (never cache null results for transactions)
    if (!skipCache && this.responseCache.has(cacheKey)) {
      const cached = this.responseCache.get(cacheKey)!;
      if (Date.now() - cached.timestamp < this.config.cacheTtlMs && cached.data !== null) {
        return cached.data as T;
      } else {
        this.responseCache.delete(cacheKey);
      }
    }

    // 2. Request deduplication for matching in-flight calls
    if (this.inFlightDedupe.has(cacheKey)) {
      return this.inFlightDedupe.get(cacheKey)! as Promise<T>;
    }

    // 3. Create queued promise
    const dedupePromise = new Promise<T>((resolve, reject) => {
      if (signal?.aborted) {
        return reject(new Error('RPC request aborted before dispatch'));
      }

      const req: QueuedRequest<T> = {
        id: Math.random().toString(36).substring(2, 9),
        method,
        params,
        priority,
        resolve: (val) => {
          if (val !== null && val !== undefined) {
            this.responseCache.set(cacheKey, { timestamp: Date.now(), data: val });
          }
          resolve(val);
        },
        reject,
        enqueuedAt: Date.now(),
        signal,
      };

      // Insert by priority (lower number = higher priority)
      const insertIndex = this.queue.findIndex((item) => item.priority > priority);
      if (insertIndex === -1) {
        this.queue.push(req);
      } else {
        this.queue.splice(insertIndex, 0, req);
      }

      this.notifyTelemetry();
      this.processQueue();
    });

    this.inFlightDedupe.set(cacheKey, dedupePromise);

    try {
      return await dedupePromise;
    } finally {
      this.inFlightDedupe.delete(cacheKey);
    }
  }

  private async processQueue(): Promise<void> {
    if (this.isProcessing) return;
    this.isProcessing = true;

    try {
      while (this.queue.length > 0) {
        const now = Date.now();
        this.requestTimestamps = this.requestTimestamps.filter((t) => now - t < 1000);

        const limit = this.config.safetyMarginRequestsPerSecond || 5;
        if (this.requestTimestamps.length >= limit) {
          const earliest = this.requestTimestamps[0];
          const waitTime = Math.max(40, 1000 - (now - earliest) + 15);
          await new Promise((res) => setTimeout(res, waitTime));
          continue;
        }

        const request = this.queue.shift();
        if (!request) break;

        if (request.signal?.aborted) {
          request.reject(new Error('RPC request cancelled by user'));
          this.notifyTelemetry();
          continue;
        }

        this.requestTimestamps.push(Date.now());
        this.telemetry.requestsInWindow = this.requestTimestamps.length;
        this.notifyTelemetry();

        // Dispatch parallel multi-endpoint request asynchronously
        this.executeRequestWithRetry(request);
      }
    } finally {
      this.isProcessing = false;
      this.notifyTelemetry();
    }
  }

  /**
   * Queries a single HTTP endpoint and returns { result, providerName, latencyMs }
   */
  private async callSingleEndpoint<T>(
    endpoint: ParallelEndpointConfig,
    request: QueuedRequest<T>,
    parentSignal: AbortSignal
  ): Promise<{ result: T; providerName: string; latencyMs: number }> {
    const startTime = Date.now();
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.config.requestTimeoutMs);

    const onAbort = () => controller.abort();
    parentSignal.addEventListener('abort', onAbort);

    try {
      const payload = {
        jsonrpc: '2.0',
        id: request.id,
        method: request.method,
        params: request.params,
      };

      const response = await fetch(endpoint.http, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });

      const latencyMs = Date.now() - startTime;

      if (response.status === 429) {
        this.telemetry.totalRateLimits++;
        throw new Error(`${endpoint.name}: Rate limit exceeded (HTTP 429)`);
      }

      if (!response.ok) {
        throw new Error(`${endpoint.name}: HTTP ${response.status} ${response.statusText}`);
      }

      const json: RawJsonRpcResponse<T> = await response.json();

      if (json.error) {
        const errMessage = json.error.message || 'JSON-RPC error';
        if (json.error.code === 429 || json.error.code === -32029 || errMessage.toLowerCase().includes('rate') || errMessage.toLowerCase().includes('many requests')) {
          this.telemetry.totalRateLimits++;
        }
        throw new Error(`${endpoint.name} [${json.error.code}]: ${errMessage}`);
      }

      return {
        result: json.result as T,
        providerName: endpoint.name,
        latencyMs,
      };
    } finally {
      clearTimeout(timeoutId);
      parentSignal.removeEventListener('abort', onAbort);
    }
  }

  /**
   * Fires the JSON-RPC call across all active endpoints in parallel.
   * - Immediately resolves on the first NON-NULL result and aborts slower in-flight legs.
   * - If an endpoint returns `null` (e.g. non-archival pruned slot on PublicNode), waits for
   *   other parallel endpoints (e.g. Helius archival) to see if they have the non-null data.
   * - If all endpoints finish and at least one returned `null` without errors, resolves `null`.
   */
  private async raceParallelEndpoints<T>(
    endpoints: ParallelEndpointConfig[],
    request: QueuedRequest<T>
  ): Promise<{ result: T; providerName: string; latencyMs: number }> {
    const raceAbortController = new AbortController();
    const onUserAbort = () => raceAbortController.abort();
    request.signal?.addEventListener('abort', onUserAbort);

    return new Promise((resolve, reject) => {
      let settled = false;
      const candidatePromises: Promise<{ result: T; providerName: string; latencyMs: number }>[] = [];

      for (const endpoint of endpoints) {
        candidatePromises.push(this.callSingleEndpoint<T>(endpoint, request, raceAbortController.signal));
        if (wsClient.isSocketOpen(endpoint.id)) {
          candidatePromises.push(
            wsClient.callRpcOverWs<T>(endpoint.id, request.method, request.params, this.config.requestTimeoutMs)
          );
        }
      }

      let pendingCount = candidatePromises.length;
      let fallbackNullOutcome: { result: T; providerName: string; latencyMs: number } | null = null;
      const errors: string[] = [];

      const cleanup = () => {
        request.signal?.removeEventListener('abort', onUserAbort);
      };

      for (const p of candidatePromises) {
        p.then((outcome) => {
          if (settled) return;
          pendingCount--;

          // If we got a non-null, non-undefined result, win immediately!
          if (outcome.result !== null && outcome.result !== undefined) {
            settled = true;
            cleanup();
            raceAbortController.abort(); // Cancel remaining slower parallel legs
            resolve(outcome);
            return;
          }

          // Otherwise outcome.result is null (e.g., pruned archival history on one node).
          // Save it as fallback in case no other parallel node has a non-null result.
          if (!fallbackNullOutcome) {
            fallbackNullOutcome = outcome;
          }

          if (pendingCount === 0 && !settled) {
            settled = true;
            cleanup();
            resolve(fallbackNullOutcome!);
          }
        }).catch((err: any) => {
          if (settled) return;
          pendingCount--;
          errors.push(err?.message || String(err));

          if (pendingCount === 0 && !settled) {
            settled = true;
            cleanup();
            if (fallbackNullOutcome) {
              resolve(fallbackNullOutcome);
            } else {
              reject(new Error(`All parallel RPC/WSS endpoints failed: ${errors.join(' | ')}`));
            }
          }
        });
      }
    });
  }

  private async executeRequestWithRetry<T>(request: QueuedRequest<T>): Promise<void> {
    let attempt = 0;
    const maxRetries = this.config.maxRetries || 3;
    const endpoints = this.getActiveEndpoints();

    while (attempt <= maxRetries) {
      if (request.signal?.aborted) {
        request.reject(new Error('RPC request cancelled'));
        return;
      }

      attempt++;
      this.telemetry.totalRequests++;

      try {
        const outcome = await this.raceParallelEndpoints<T>(endpoints, request);

        this.telemetry.lastLatencyMs = outcome.latencyMs;
        this.telemetry.averageLatencyMs =
          this.telemetry.averageLatencyMs === 0
            ? outcome.latencyMs
            : Math.round(this.telemetry.averageLatencyMs * 0.8 + outcome.latencyMs * 0.2);

        this.telemetry.totalSuccess++;
        this.telemetry.providerHealth = 'healthy';
        this.telemetry.lastWinningProvider = outcome.providerName;
        this.notifyTelemetry();
        request.resolve(outcome.result);
        return;
      } catch (err: any) {
        if (request.signal?.aborted) {
          request.reject(new Error('RPC request cancelled'));
          return;
        }

        if (attempt <= maxRetries) {
          const backoff = 700 * attempt + Math.floor(Math.random() * 250);
          await new Promise((res) => setTimeout(res, backoff));
          continue;
        }

        this.telemetry.totalErrors++;
        this.telemetry.providerHealth = 'degraded';
        this.notifyTelemetry();
        request.reject(err instanceof Error ? err : new Error(String(err)));
        return;
      }
    }
  }

  /**
   * Health check across the parallel RPC pool
   */
  public async checkHealth(): Promise<{
    healthy: boolean;
    slot?: number;
    latencyMs: number;
    provider?: string;
    error?: string;
  }> {
    const start = Date.now();
    try {
      this.telemetry.providerHealth = 'checking';
      this.notifyTelemetry();
      const slot = await this.call<number>('getSlot', [{ commitment: 'processed' }], {
        priority: 0,
        skipCache: true,
      });
      const latencyMs = Date.now() - start;
      this.telemetry.providerHealth = 'healthy';
      this.telemetry.lastHealthCheckTime = Date.now();
      this.notifyTelemetry();
      return {
        healthy: true,
        slot,
        latencyMs,
        provider: this.telemetry.lastWinningProvider,
      };
    } catch (err: any) {
      const latencyMs = Date.now() - start;
      this.telemetry.providerHealth = 'offline';
      this.telemetry.lastHealthCheckTime = Date.now();
      this.notifyTelemetry();
      return { healthy: false, latencyMs, error: err.message || 'RPC unreachable' };
    }
  }
}

// Global Singleton Client
export const rpcClient = new RpcClient();
