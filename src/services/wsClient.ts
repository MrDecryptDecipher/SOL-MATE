/**
 * SOL-MATE — Parallel Multi-Endpoint WebSocket Real-Time Streaming & JSON-RPC Client
 * Connects simultaneously to:
 *  - wss://mainnet.helius-rpc.com/?api-key=dea43e7c-2806-4d5e-9241-b010e5c96762
 *  - wss://solana-rpc.publicnode.com
 *  - wss://solana.api.onfinality.io/public-ws
 * Supports both real-time subscriptions (slotSubscribe, logsSubscribe, accountSubscribe)
 * and direct low-latency JSON-RPC calls over persistent WSS connections.
 */

import { DEFAULT_PARALLEL_ENDPOINTS, loadAppConfig } from './config';

export type WsConnectionStatus = 'connecting' | 'connected' | 'disconnected' | 'reconnecting' | 'paused' | 'error';

export interface LiveSlotNotification {
  parent: number;
  root: number;
  slot: number;
  provider?: string;
}

export interface LiveLogNotification {
  signature: string;
  err: unknown | null;
  logs: string[];
  provider?: string;
}

export interface LiveAccountNotification {
  slot: number;
  lamports: number;
  owner: string;
  executable: boolean;
  data: string | [string, string];
  provider?: string;
}

type MessageHandler = (data: any, providerName: string) => void;

interface PendingWsRpc {
  resolve: (value: any) => void;
  reject: (reason: Error) => void;
  timer: any;
}

interface WsSocketEntry {
  id: string;
  name: string;
  url: string;
  ws: WebSocket | null;
  status: WsConnectionStatus;
  reconnectAttempts: number;
  reconnectTimer: any;
  reqIdToKey: Map<number, string>;
  subIdToKey: Map<number, string>;
  keyToSubId: Map<string, number>;
  pendingRpc: Map<number, PendingWsRpc>;
}

export class SolanaWsClient {
  private sockets = new Map<string, WsSocketEntry>();
  private status: WsConnectionStatus = 'disconnected';
  private statusListeners = new Set<(status: WsConnectionStatus) => void>();
  private isPaused = false;
  private lastUpdateTime = 0;
  private nextReqId = 1;

  // Deduplication state across parallel WSS connections
  private highestSlot = 0;
  private seenSignatures = new Set<string>();
  private seenSignatureQueue: string[] = [];

  // Active logical subscriptions: key -> { method, params, handler }
  private subscriptions = new Map<
    string,
    {
      method: string;
      params: unknown[];
      handler: MessageHandler;
    }
  >();

  constructor(customWsUrl?: string) {
    this.initSocketsFromConfig(customWsUrl);
  }

  private initSocketsFromConfig(customWsUrl?: string): void {
    const config = loadAppConfig();
    this.sockets.clear();

    if (customWsUrl) {
      this.sockets.set('custom', {
        id: 'custom',
        name: 'Custom WSS',
        url: customWsUrl,
        ws: null,
        status: 'disconnected',
        reconnectAttempts: 0,
        reconnectTimer: null,
        reqIdToKey: new Map(),
        subIdToKey: new Map(),
        keyToSubId: new Map(),
        pendingRpc: new Map(),
      });
      return;
    }

    const endpoints =
      config.network === 'mainnet' && config.enableParallelPool !== false
        ? (config.parallelEndpoints || DEFAULT_PARALLEL_ENDPOINTS).filter((e) => e.enabled)
        : [
            {
              id: 'primary',
              name: 'Primary WSS',
              http: config.httpEndpoint,
              ws: config.wsEndpoint,
              enabled: true,
            },
          ];

    for (const ep of endpoints) {
      this.sockets.set(ep.id, {
        id: ep.id,
        name: ep.name,
        url: ep.ws,
        ws: null,
        status: 'disconnected',
        reconnectAttempts: 0,
        reconnectTimer: null,
        reqIdToKey: new Map(),
        subIdToKey: new Map(),
        keyToSubId: new Map(),
        pendingRpc: new Map(),
      });
    }
  }

  public updateWsUrl(newUrl: string): void {
    this.disconnect();
    this.initSocketsFromConfig();
    const hasUrl = Array.from(this.sockets.values()).some((s) => s.url === newUrl);
    if (!hasUrl && newUrl) {
      this.sockets.set('custom-ws', {
        id: 'custom-ws',
        name: 'Primary Custom WSS',
        url: newUrl,
        ws: null,
        status: 'disconnected',
        reconnectAttempts: 0,
        reconnectTimer: null,
        reqIdToKey: new Map(),
        subIdToKey: new Map(),
        keyToSubId: new Map(),
        pendingRpc: new Map(),
      });
    }
    this.connect();
  }

  public getStatus(): WsConnectionStatus {
    return this.isPaused ? 'paused' : this.status;
  }

  public getConnectedProviders(): { id: string; name: string; url: string; status: WsConnectionStatus }[] {
    return Array.from(this.sockets.values()).map((s) => ({
      id: s.id,
      name: s.name,
      url: s.url,
      status: this.isPaused ? 'paused' : s.status,
    }));
  }

  public isSocketOpen(endpointId: string): boolean {
    const entry = this.sockets.get(endpointId);
    return Boolean(entry && entry.ws && entry.ws.readyState === WebSocket.OPEN);
  }

  /**
   * Executes a standard JSON-RPC request directly over an open WSS socket in the pool.
   */
  public callRpcOverWs<T>(
    endpointId: string,
    method: string,
    params: unknown[],
    timeoutMs: number = 10000
  ): Promise<{ result: T; providerName: string; latencyMs: number }> {
    const entry = this.sockets.get(endpointId);
    if (!entry || !entry.ws || entry.ws.readyState !== WebSocket.OPEN) {
      return Promise.reject(new Error(`WSS socket ${endpointId} not open`));
    }

    const startTime = Date.now();
    const reqId = this.nextReqId++;

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        entry.pendingRpc.delete(reqId);
        reject(new Error(`${entry.name} WSS RPC timeout`));
      }, timeoutMs);

      entry.pendingRpc.set(reqId, {
        resolve: (result: T) => {
          clearTimeout(timer);
          resolve({
            result,
            providerName: `${entry.name} (WSS)`,
            latencyMs: Date.now() - startTime,
          });
        },
        reject: (err: Error) => {
          clearTimeout(timer);
          reject(err);
        },
        timer,
      });

      try {
        entry.ws!.send(
          JSON.stringify({
            jsonrpc: '2.0',
            id: reqId,
            method,
            params,
          })
        );
      } catch (err: any) {
        clearTimeout(timer);
        entry.pendingRpc.delete(reqId);
        reject(err instanceof Error ? err : new Error(String(err)));
      }
    });
  }

  public getLastUpdateTime(): number {
    return this.lastUpdateTime;
  }

  public subscribeStatus(listener: (status: WsConnectionStatus) => void): () => void {
    this.statusListeners.add(listener);
    listener(this.getStatus());
    return () => this.statusListeners.delete(listener);
  }

  private recomputeAggregateStatus(): void {
    if (this.isPaused) {
      this.status = 'paused';
    } else {
      const states = Array.from(this.sockets.values()).map((s) => s.status);
      if (states.includes('connected')) {
        this.status = 'connected';
      } else if (states.includes('connecting') || states.includes('reconnecting')) {
        this.status = 'connecting';
      } else if (states.includes('error')) {
        this.status = 'error';
      } else {
        this.status = 'disconnected';
      }
    }

    for (const listener of this.statusListeners) {
      try {
        listener(this.getStatus());
      } catch (err) {
        console.error('Error in WS status listener:', err);
      }
    }
  }

  public connect(): void {
    if (typeof window === 'undefined' || this.isPaused) return;
    if (this.sockets.size === 0) {
      this.initSocketsFromConfig();
    }

    for (const entry of this.sockets.values()) {
      this.connectSingleSocket(entry);
    }
  }

  private connectSingleSocket(entry: WsSocketEntry): void {
    if (this.isPaused) return;
    if (entry.ws && (entry.ws.readyState === WebSocket.OPEN || entry.ws.readyState === WebSocket.CONNECTING)) {
      return;
    }

    entry.status = entry.reconnectAttempts > 0 ? 'reconnecting' : 'connecting';
    this.recomputeAggregateStatus();

    try {
      const ws = new WebSocket(entry.url);
      entry.ws = ws;

      ws.onopen = () => {
        entry.reconnectAttempts = 0;
        entry.status = 'connected';
        this.lastUpdateTime = Date.now();
        this.recomputeAggregateStatus();
        this.resubscribeSocket(entry);
      };

      ws.onmessage = (event) => {
        this.handleSocketMessage(entry, event.data);
      };

      ws.onerror = () => {
        entry.status = 'error';
        this.recomputeAggregateStatus();
      };

      ws.onclose = () => {
        entry.status = 'disconnected';
        entry.ws = null;
        // Reject any pending RPC calls on this closed socket
        for (const [, pending] of entry.pendingRpc.entries()) {
          clearTimeout(pending.timer);
          pending.reject(new Error(`${entry.name} WSS closed`));
        }
        entry.pendingRpc.clear();
        this.recomputeAggregateStatus();
        if (!this.isPaused) {
          this.scheduleSocketReconnect(entry);
        }
      };
    } catch {
      entry.status = 'error';
      this.recomputeAggregateStatus();
      this.scheduleSocketReconnect(entry);
    }
  }

  private scheduleSocketReconnect(entry: WsSocketEntry): void {
    if (entry.reconnectTimer) clearTimeout(entry.reconnectTimer);
    if (this.isPaused) return;

    entry.reconnectAttempts++;
    const delay = Math.min(1000 * Math.pow(1.5, entry.reconnectAttempts), 15000);
    entry.reconnectTimer = setTimeout(() => {
      this.connectSingleSocket(entry);
    }, delay);
  }

  public reconnect(): void {
    this.disconnect();
    this.connect();
  }

  public disconnect(): void {
    for (const entry of this.sockets.values()) {
      if (entry.reconnectTimer) clearTimeout(entry.reconnectTimer);
      for (const [, pending] of entry.pendingRpc.entries()) {
        clearTimeout(pending.timer);
        pending.reject(new Error('WSS disconnected'));
      }
      entry.pendingRpc.clear();
      if (entry.ws) {
        entry.ws.onclose = null;
        entry.ws.onerror = null;
        entry.ws.onmessage = null;
        try {
          entry.ws.close();
        } catch {
          // ignore close error
        }
        entry.ws = null;
      }
      entry.status = 'disconnected';
      entry.reqIdToKey.clear();
      entry.subIdToKey.clear();
      entry.keyToSubId.clear();
    }
    this.recomputeAggregateStatus();
  }

  public pause(): void {
    this.isPaused = true;
    this.disconnect();
    this.recomputeAggregateStatus();
  }

  public resume(): void {
    this.isPaused = false;
    this.connect();
  }

  public isStreamPaused(): boolean {
    return this.isPaused;
  }

  private resubscribeSocket(entry: WsSocketEntry): void {
    if (!entry.ws || entry.ws.readyState !== WebSocket.OPEN) return;

    for (const [key, sub] of this.subscriptions.entries()) {
      const reqId = this.nextReqId++;
      entry.reqIdToKey.set(reqId, key);

      const payload = {
        jsonrpc: '2.0',
        id: reqId,
        method: sub.method,
        params: sub.params,
      };

      try {
        entry.ws.send(JSON.stringify(payload));
      } catch (err) {
        console.warn(`Failed to send WS subscription on ${entry.name}:`, err);
      }
    }
  }

  private handleSocketMessage(entry: WsSocketEntry, rawData: string): void {
    try {
      this.lastUpdateTime = Date.now();
      const message = JSON.parse(rawData);

      // 0. Direct JSON-RPC over WSS response
      if (message.id !== undefined && entry.pendingRpc.has(message.id)) {
        const pending = entry.pendingRpc.get(message.id)!;
        entry.pendingRpc.delete(message.id);
        if (message.error) {
          pending.reject(new Error(`${entry.name} WSS [${message.error.code}]: ${message.error.message}`));
        } else {
          pending.resolve(message.result);
        }
        return;
      }

      // 1. Subscription confirmation response
      if (message.id !== undefined && message.result !== undefined) {
        const key = entry.reqIdToKey.get(message.id);
        if (key && this.subscriptions.has(key)) {
          entry.subIdToKey.set(message.result, key);
          entry.keyToSubId.set(key, message.result);
          entry.reqIdToKey.delete(message.id);
        }
        return;
      }

      // 2. Stream notification
      if (message.method && message.params) {
        const subId = message.params.subscription;
        const key = entry.subIdToKey.get(subId);
        if (key && this.subscriptions.has(key)) {
          const sub = this.subscriptions.get(key)!;
          sub.handler(message.params.result, entry.name);
        }
      }
    } catch {
      // ignore malformed frame
    }
  }

  private sendSubscriptionToOpenSockets(key: string, method: string, params: unknown[]): void {
    let anyOpen = false;
    for (const entry of this.sockets.values()) {
      if (entry.ws && entry.ws.readyState === WebSocket.OPEN) {
        anyOpen = true;
        const reqId = this.nextReqId++;
        entry.reqIdToKey.set(reqId, key);
        try {
          entry.ws.send(JSON.stringify({ jsonrpc: '2.0', id: reqId, method, params }));
        } catch {
          // ignore send error
        }
      }
    }
    if (!anyOpen) {
      this.connect();
    }
  }

  /**
   * Subscribe to global slot progression across all parallel WSS endpoints (deduplicated by monotonic slot)
   */
  public subscribeSlot(handler: (slotInfo: LiveSlotNotification) => void): () => void {
    const key = `slot_${Date.now()}_${Math.random()}`;
    this.subscriptions.set(key, {
      method: 'slotSubscribe',
      params: [],
      handler: (rawSlot: LiveSlotNotification, providerName: string) => {
        if (rawSlot && typeof rawSlot.slot === 'number') {
          if (rawSlot.slot > this.highestSlot) {
            this.highestSlot = rawSlot.slot;
            handler({ ...rawSlot, provider: providerName });
          }
        }
      },
    });

    this.sendSubscriptionToOpenSockets(key, 'slotSubscribe', []);
    return () => this.unsubscribe(key, 'slotUnsubscribe');
  }

  /**
   * Subscribe to real-time transaction logs across all parallel WSS endpoints (deduplicated by signature)
   */
  public subscribeLogs(
    filter: 'all' | { mentions: string[] },
    handler: (logInfo: LiveLogNotification) => void
  ): () => void {
    const key = `logs_${JSON.stringify(filter)}_${Date.now()}`;
    const params = [filter, { commitment: 'confirmed' }];

    this.subscriptions.set(key, {
      method: 'logsSubscribe',
      params,
      handler: (resultWrapper: any, providerName: string) => {
        const value: LiveLogNotification = resultWrapper?.value || resultWrapper;
        if (!value || !value.signature) return;

        // Deduplicate across parallel WSS streams
        if (this.seenSignatures.has(value.signature)) return;
        this.seenSignatures.add(value.signature);
        this.seenSignatureQueue.push(value.signature);
        if (this.seenSignatureQueue.length > 500) {
          const oldest = this.seenSignatureQueue.shift();
          if (oldest) this.seenSignatures.delete(oldest);
        }

        handler({
          signature: value.signature,
          err: value.err ?? null,
          logs: Array.isArray(value.logs) ? value.logs : [],
          provider: providerName,
        });
      },
    });

    this.sendSubscriptionToOpenSockets(key, 'logsSubscribe', params);
    return () => this.unsubscribe(key, 'logsUnsubscribe');
  }

  /**
   * Subscribe to live account balance & data changes
   */
  public subscribeAccount(
    pubkey: string,
    handler: (accountInfo: LiveAccountNotification) => void
  ): () => void {
    const key = `account_${pubkey}`;
    const params = [pubkey, { encoding: 'jsonParsed', commitment: 'confirmed' }];

    this.subscriptions.set(key, {
      method: 'accountSubscribe',
      params,
      handler: (resultWrapper: any, providerName: string) => {
        const slot = resultWrapper?.context?.slot || 0;
        const val = resultWrapper?.value || resultWrapper;
        if (!val) return;
        handler({
          slot,
          lamports: val.lamports ?? 0,
          owner: val.owner ?? '',
          executable: Boolean(val.executable),
          data: val.data,
          provider: providerName,
        });
      },
    });

    this.sendSubscriptionToOpenSockets(key, 'accountSubscribe', params);
    return () => this.unsubscribe(key, 'accountUnsubscribe');
  }

  private unsubscribe(key: string, unsubscribeMethod: string): void {
    const sub = this.subscriptions.get(key);
    if (!sub) return;

    for (const entry of this.sockets.values()) {
      const subId = entry.keyToSubId.get(key);
      if (subId !== undefined && entry.ws && entry.ws.readyState === WebSocket.OPEN) {
        const reqId = this.nextReqId++;
        try {
          entry.ws.send(
            JSON.stringify({
              jsonrpc: '2.0',
              id: reqId,
              method: unsubscribeMethod,
              params: [subId],
            })
          );
        } catch {
          // ignore
        }
        entry.subIdToKey.delete(subId);
        entry.keyToSubId.delete(key);
      }
    }

    this.subscriptions.delete(key);
  }
}

// Global WebSocket Singleton
export const wsClient = new SolanaWsClient();
