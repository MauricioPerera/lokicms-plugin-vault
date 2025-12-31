/**
 * Audit Logger for the Vault Plugin
 *
 * Tracks all credential access and modifications for security compliance
 */

import type {
  AuditEntry,
  AuditAction,
  AuditQuery,
  PluginLogger,
} from './types.js';
import { generateId } from './crypto.js';

/**
 * In-memory audit log storage (would use LokiJS in production)
 */
interface AuditStore {
  entries: AuditEntry[];
  maxEntries: number;
  retentionDays: number;
}

export class AuditLogger {
  private store: AuditStore;
  private logger: PluginLogger;
  private enabled: boolean;
  private cleanupInterval: NodeJS.Timeout | null = null;

  constructor(logger: PluginLogger, options: { enabled?: boolean; retentionDays?: number } = {}) {
    this.logger = logger;
    this.enabled = options.enabled ?? true;
    this.store = {
      entries: [],
      maxEntries: 100000, // Max entries to keep in memory
      retentionDays: options.retentionDays ?? 90,
    };

    // Start cleanup interval (daily)
    if (this.enabled) {
      this.startCleanupInterval();
    }
  }

  /**
   * Log an audit entry
   */
  async log(entry: Omit<AuditEntry, 'id' | 'timestamp'>): Promise<AuditEntry> {
    if (!this.enabled) {
      return {
        ...entry,
        id: 'disabled',
        timestamp: new Date(),
      };
    }

    const auditEntry: AuditEntry = {
      ...entry,
      id: generateId('audit'),
      timestamp: new Date(),
    };

    // Add to store
    this.store.entries.push(auditEntry);

    // Trim if over max
    if (this.store.entries.length > this.store.maxEntries) {
      this.store.entries = this.store.entries.slice(-this.store.maxEntries);
    }

    // Log to console based on action type
    this.logToConsole(auditEntry);

    return auditEntry;
  }

  /**
   * Log a credential creation
   */
  async logCreate(
    credentialId: string,
    credentialName: string,
    project: string,
    environment: string,
    performedBy: string,
    performedByType: 'user' | 'system' | 'code' = 'user'
  ): Promise<AuditEntry> {
    return this.log({
      action: 'create',
      credentialId,
      credentialName,
      project,
      environment,
      performedBy,
      performedByType,
      success: true,
    });
  }

  /**
   * Log a credential access (value retrieved)
   */
  async logAccess(
    credentialId: string,
    credentialName: string,
    project: string,
    environment: string,
    performedBy: string,
    performedByType: 'user' | 'system' | 'code' = 'code',
    success: boolean = true,
    errorMessage?: string
  ): Promise<AuditEntry> {
    return this.log({
      action: 'access',
      credentialId,
      credentialName,
      project,
      environment,
      performedBy,
      performedByType,
      success,
      errorMessage,
    });
  }

  /**
   * Log a credential injection into environment
   */
  async logInject(
    credentialId: string,
    credentialName: string,
    project: string,
    environment: string,
    performedBy: string
  ): Promise<AuditEntry> {
    return this.log({
      action: 'inject',
      credentialId,
      credentialName,
      project,
      environment,
      performedBy,
      performedByType: 'code',
      success: true,
    });
  }

  /**
   * Log a credential update
   */
  async logUpdate(
    credentialId: string,
    credentialName: string,
    project: string,
    environment: string,
    performedBy: string,
    changes: Record<string, unknown>
  ): Promise<AuditEntry> {
    return this.log({
      action: 'update',
      credentialId,
      credentialName,
      project,
      environment,
      performedBy,
      performedByType: 'user',
      success: true,
      details: { changes },
    });
  }

  /**
   * Log a credential rotation
   */
  async logRotate(
    credentialId: string,
    credentialName: string,
    project: string,
    environment: string,
    performedBy: string
  ): Promise<AuditEntry> {
    return this.log({
      action: 'rotate',
      credentialId,
      credentialName,
      project,
      environment,
      performedBy,
      performedByType: 'user',
      success: true,
    });
  }

  /**
   * Log a credential deletion
   */
  async logDelete(
    credentialId: string,
    credentialName: string,
    project: string,
    environment: string,
    performedBy: string
  ): Promise<AuditEntry> {
    return this.log({
      action: 'delete',
      credentialId,
      credentialName,
      project,
      environment,
      performedBy,
      performedByType: 'user',
      success: true,
    });
  }

  /**
   * Log a permission change
   */
  async logPermissionChange(
    credentialId: string,
    credentialName: string,
    project: string,
    environment: string,
    performedBy: string,
    oldPermissions: unknown,
    newPermissions: unknown
  ): Promise<AuditEntry> {
    return this.log({
      action: 'permission_change',
      credentialId,
      credentialName,
      project,
      environment,
      performedBy,
      performedByType: 'user',
      success: true,
      details: { oldPermissions, newPermissions },
    });
  }

  /**
   * Log an error/failed operation
   */
  async logError(
    action: AuditAction,
    credentialId: string,
    credentialName: string,
    project: string,
    environment: string,
    performedBy: string,
    errorMessage: string
  ): Promise<AuditEntry> {
    return this.log({
      action,
      credentialId,
      credentialName,
      project,
      environment,
      performedBy,
      performedByType: 'user',
      success: false,
      errorMessage,
    });
  }

  /**
   * Query audit logs
   */
  async query(query: AuditQuery): Promise<AuditEntry[]> {
    let results = [...this.store.entries];

    // Apply filters
    if (query.credentialId) {
      results = results.filter((e) => e.credentialId === query.credentialId);
    }

    if (query.project) {
      results = results.filter((e) => e.project === query.project);
    }

    if (query.environment) {
      results = results.filter((e) => e.environment === query.environment);
    }

    if (query.action) {
      results = results.filter((e) => e.action === query.action);
    }

    if (query.performedBy) {
      results = results.filter((e) => e.performedBy === query.performedBy);
    }

    if (query.startDate) {
      results = results.filter((e) => e.timestamp >= query.startDate!);
    }

    if (query.endDate) {
      results = results.filter((e) => e.timestamp <= query.endDate!);
    }

    // Sort by timestamp descending (newest first)
    results.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());

    // Apply pagination
    const offset = query.offset ?? 0;
    const limit = query.limit ?? 100;

    return results.slice(offset, offset + limit);
  }

  /**
   * Get audit summary for a credential
   */
  async getCredentialSummary(credentialId: string): Promise<{
    totalAccesses: number;
    lastAccess?: Date;
    uniqueAccessors: string[];
    actionCounts: Record<AuditAction, number>;
  }> {
    const entries = this.store.entries.filter((e) => e.credentialId === credentialId);

    const actionCounts: Record<AuditAction, number> = {
      create: 0,
      read: 0,
      update: 0,
      delete: 0,
      rotate: 0,
      access: 0,
      inject: 0,
      export: 0,
      permission_change: 0,
    };

    const accessors = new Set<string>();
    let lastAccess: Date | undefined;

    for (const entry of entries) {
      actionCounts[entry.action]++;
      accessors.add(entry.performedBy);

      if (entry.action === 'access' || entry.action === 'inject') {
        if (!lastAccess || entry.timestamp > lastAccess) {
          lastAccess = entry.timestamp;
        }
      }
    }

    return {
      totalAccesses: actionCounts.access + actionCounts.inject,
      lastAccess,
      uniqueAccessors: Array.from(accessors),
      actionCounts,
    };
  }

  /**
   * Get recent activity across all credentials
   */
  async getRecentActivity(limit: number = 50): Promise<AuditEntry[]> {
    return this.query({ limit });
  }

  /**
   * Clean up old audit entries
   */
  async cleanup(): Promise<number> {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - this.store.retentionDays);

    const originalCount = this.store.entries.length;
    this.store.entries = this.store.entries.filter((e) => e.timestamp >= cutoffDate);
    const removedCount = originalCount - this.store.entries.length;

    if (removedCount > 0) {
      this.logger.info(`Cleaned up ${removedCount} old audit entries`);
    }

    return removedCount;
  }

  /**
   * Export audit logs
   */
  async export(query?: AuditQuery): Promise<AuditEntry[]> {
    const entries = query ? await this.query(query) : [...this.store.entries];

    // Log the export action itself
    await this.log({
      action: 'export',
      credentialId: 'all',
      credentialName: 'audit_export',
      project: query?.project ?? 'all',
      environment: query?.environment ?? 'all',
      performedBy: 'system',
      performedByType: 'system',
      success: true,
      details: { entriesExported: entries.length },
    });

    return entries;
  }

  /**
   * Enable audit logging
   */
  enable(): void {
    this.enabled = true;
    this.startCleanupInterval();
  }

  /**
   * Disable audit logging
   */
  disable(): void {
    this.enabled = false;
    this.stopCleanupInterval();
  }

  /**
   * Check if audit logging is enabled
   */
  isEnabled(): boolean {
    return this.enabled;
  }

  /**
   * Get audit statistics
   */
  getStats(): {
    enabled: boolean;
    totalEntries: number;
    retentionDays: number;
    oldestEntry?: Date;
    newestEntry?: Date;
  } {
    const entries = this.store.entries;

    return {
      enabled: this.enabled,
      totalEntries: entries.length,
      retentionDays: this.store.retentionDays,
      oldestEntry: entries.length > 0 ? entries[0].timestamp : undefined,
      newestEntry: entries.length > 0 ? entries[entries.length - 1].timestamp : undefined,
    };
  }

  /**
   * Start the cleanup interval
   */
  private startCleanupInterval(): void {
    if (this.cleanupInterval) return;

    // Run cleanup daily
    this.cleanupInterval = setInterval(
      () => {
        this.cleanup().catch((err) => {
          this.logger.error('Audit cleanup failed:', err);
        });
      },
      24 * 60 * 60 * 1000
    ); // 24 hours
  }

  /**
   * Stop the cleanup interval
   */
  private stopCleanupInterval(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
  }

  /**
   * Log to console based on action severity
   */
  private logToConsole(entry: AuditEntry): void {
    const message = `[AUDIT] ${entry.action.toUpperCase()} ${entry.credentialName} (${entry.project}/${entry.environment}) by ${entry.performedBy}`;

    if (!entry.success) {
      this.logger.warn(`${message} - FAILED: ${entry.errorMessage}`);
    } else if (entry.action === 'delete' || entry.action === 'permission_change') {
      this.logger.info(message);
    } else {
      this.logger.debug(message);
    }
  }

  /**
   * Destroy the audit logger (cleanup resources)
   */
  destroy(): void {
    this.stopCleanupInterval();
    this.store.entries = [];
  }
}

/**
 * Create a new audit logger instance
 */
export function createAuditLogger(
  logger: PluginLogger,
  options?: { enabled?: boolean; retentionDays?: number }
): AuditLogger {
  return new AuditLogger(logger, options);
}
