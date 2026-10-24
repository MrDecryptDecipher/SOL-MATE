/**
 * SOL-MATE — Deep State Persistence Engine
 * Browser IndexedDB storage for historical forensic investigations, monitored accounts,
 * knowledge graph snapshots, live logs, and trend reporting.
 */

import { InvestigationReport, TransactionRecord } from '../types/forensics';

export interface MonitoredAccount {
  address: string;
  label: string;
  addedAt: number;
  lastActiveSlot?: number;
  lastCheckedAt?: number;
  lastLamports?: string;
  notes?: string;
  alertRules?: {
    minSolTransfer?: number;
    flagAuthorities?: boolean;
    notifyOnCpi?: boolean;
  };
}

export interface SavedInvestigationSummary {
  reportId: string;
  signature: string;
  slot: number;
  blockTime: number | null;
  formattedTime: string;
  cluster: string;
  status: 'success' | 'failed';
  feeSol: number;
  accountsCount: number;
  instructionsCount: number;
  riskScore: number;
  savedAt: number;
  analystTags: string[];
}

export class DeepStorage {
  private dbPromise: Promise<IDBDatabase> | null = null;
  private readonly DB_NAME = 'solmate_forensics_db';
  private readonly DB_VERSION = 1;

  constructor() {
    if (typeof window !== 'undefined') {
      this.initDb();
    }
  }

  private initDb(): Promise<IDBDatabase> {
    if (this.dbPromise) return this.dbPromise;

    this.dbPromise = new Promise((resolve, reject) => {
      const request = indexedDB.open(this.DB_NAME, this.DB_VERSION);

      request.onupgradeneeded = (event: any) => {
        const db = event.target.result as IDBDatabase;

        // Investigations Store
        if (!db.objectStoreNames.contains('investigations')) {
          const invStore = db.createObjectStore('investigations', { keyPath: 'signature' });
          invStore.createIndex('savedAt', 'savedAt', { unique: false });
          invStore.createIndex('slot', 'slot', { unique: false });
          invStore.createIndex('riskScore', 'heuristicRiskScore', { unique: false });
        }

        // Monitored Accounts Store
        if (!db.objectStoreNames.contains('monitored_accounts')) {
          const accStore = db.createObjectStore('monitored_accounts', { keyPath: 'address' });
          accStore.createIndex('addedAt', 'addedAt', { unique: false });
        }

        // Real-Time Log Feeds Store
        if (!db.objectStoreNames.contains('live_logs')) {
          const logStore = db.createObjectStore('live_logs', { keyPath: 'id', autoIncrement: true });
          logStore.createIndex('timestamp', 'timestamp', { unique: false });
          logStore.createIndex('signature', 'signature', { unique: false });
        }
      };

      request.onsuccess = (event: any) => {
        resolve(event.target.result);
      };

      request.onerror = (event: any) => {
        console.error('IndexedDB error:', event.target.error);
        reject(event.target.error);
      };
    });

    return this.dbPromise;
  }

  public async saveInvestigation(tx: TransactionRecord, tags: string[] = []): Promise<void> {
    const db = await this.initDb();
    return new Promise((resolve, reject) => {
      const txStore = db.transaction('investigations', 'readwrite').objectStore('investigations');
      const item = {
        ...tx,
        savedAt: Date.now(),
        analystTags: tags,
      };
      const req = txStore.put(item);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  }

  public async getInvestigation(signature: string): Promise<TransactionRecord | null> {
    const db = await this.initDb();
    return new Promise((resolve, reject) => {
      const txStore = db.transaction('investigations', 'readonly').objectStore('investigations');
      const req = txStore.get(signature);
      req.onsuccess = () => resolve(req.result || null);
      req.onerror = () => reject(req.error);
    });
  }

  public async listSavedInvestigations(): Promise<SavedInvestigationSummary[]> {
    const db = await this.initDb();
    return new Promise((resolve, reject) => {
      const txStore = db.transaction('investigations', 'readonly').objectStore('investigations');
      const req = txStore.getAll();
      req.onsuccess = () => {
        const results: SavedInvestigationSummary[] = (req.result || []).map((item: any) => ({
          reportId: item.signature.slice(0, 8),
          signature: item.signature,
          slot: item.slot,
          blockTime: item.blockTime,
          formattedTime: item.formattedTime,
          cluster: item.cluster,
          status: item.success ? 'success' : 'failed',
          feeSol: item.feeSol,
          accountsCount: item.combinedAccounts?.length || 0,
          instructionsCount: item.outerInstructions?.length || 0,
          riskScore: item.heuristicRiskScore,
          savedAt: item.savedAt || Date.now(),
          analystTags: item.analystTags || [],
        }));
        // Sort descending by saved time
        results.sort((a, b) => b.savedAt - a.savedAt);
        resolve(results);
      };
      req.onerror = () => reject(req.error);
    });
  }

  public async deleteInvestigation(signature: string): Promise<void> {
    const db = await this.initDb();
    return new Promise((resolve, reject) => {
      const txStore = db.transaction('investigations', 'readwrite').objectStore('investigations');
      const req = txStore.delete(signature);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  }

  // Monitored Accounts
  public async addMonitoredAccount(account: MonitoredAccount): Promise<void> {
    const db = await this.initDb();
    return new Promise((resolve, reject) => {
      const store = db.transaction('monitored_accounts', 'readwrite').objectStore('monitored_accounts');
      const req = store.put(account);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  }

  public async listMonitoredAccounts(): Promise<MonitoredAccount[]> {
    const db = await this.initDb();
    return new Promise((resolve, reject) => {
      const store = db.transaction('monitored_accounts', 'readonly').objectStore('monitored_accounts');
      const req = store.getAll();
      req.onsuccess = () => resolve(req.result || []);
      req.onerror = () => reject(req.error);
    });
  }

  public async removeMonitoredAccount(address: string): Promise<void> {
    const db = await this.initDb();
    return new Promise((resolve, reject) => {
      const store = db.transaction('monitored_accounts', 'readwrite').objectStore('monitored_accounts');
      const req = store.delete(address);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  }

  // Export full archive as JSON
  public async exportAllJson(): Promise<string> {
    const investigations = await this.listSavedInvestigations();
    const accounts = await this.listMonitoredAccounts();
    return JSON.stringify(
      {
        exportedAt: new Date().toISOString(),
        solmateVersion: '1.0.0',
        investigationsCount: investigations.length,
        investigations,
        monitoredAccounts: accounts,
      },
      null,
      2
    );
  }
}

export const deepStorage = new DeepStorage();
