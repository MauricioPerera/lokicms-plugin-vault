/**
 * Core Vault Logic
 *
 * Manages credential storage, encryption, and lifecycle
 */

import type {
  Credential,
  CredentialView,
  CredentialStatus,
  CreateCredentialInput,
  UpdateCredentialInput,
  RotateCredentialInput,
  CredentialQuery,
  Project,
  VaultPluginConfig,
  PluginLogger,
} from './types.js';
import { VaultError, MASKED_VALUE } from './types.js';
import { encrypt, decrypt, generateId, validateMasterKey } from './crypto.js';
import { AuditLogger } from './audit.js';

/**
 * In-memory credential storage (would use LokiJS in production)
 */
interface CredentialStore {
  credentials: Map<string, Credential>;
  projects: Map<string, Project>;
}

export class CredentialVault {
  private store: CredentialStore;
  private masterKey: string | null = null;
  private config: VaultPluginConfig;
  private logger: PluginLogger;
  private auditLogger: AuditLogger;

  constructor(config: VaultPluginConfig, logger: PluginLogger, auditLogger: AuditLogger) {
    this.config = config;
    this.logger = logger;
    this.auditLogger = auditLogger;
    this.store = {
      credentials: new Map(),
      projects: new Map(),
    };

    // Initialize master key
    this.initializeMasterKey();
  }

  /**
   * Initialize master key from config or environment
   */
  private initializeMasterKey(): void {
    // Try config first
    if (this.config.masterKey) {
      this.masterKey = this.config.masterKey;
      this.logger.debug('Master key loaded from config');
      return;
    }

    // Try environment variable
    const envVar = this.config.masterKeyEnvVar || 'VAULT_MASTER_KEY';
    const envKey = process.env[envVar];
    if (envKey) {
      this.masterKey = envKey;
      this.logger.debug(`Master key loaded from environment variable: ${envVar}`);
      return;
    }

    this.logger.warn(
      'Master key not set. Vault operations will fail until key is configured.'
    );
  }

  /**
   * Set the master key (runtime configuration)
   */
  setMasterKey(key: string): { success: boolean; errors?: string[] } {
    const validation = validateMasterKey(key);
    if (!validation.valid) {
      return { success: false, errors: validation.errors };
    }

    this.masterKey = key;
    this.logger.info('Master key configured');
    return { success: true };
  }

  /**
   * Check if master key is set
   */
  hasMasterKey(): boolean {
    return this.masterKey !== null;
  }

  /**
   * Create a new credential
   */
  async create(
    input: CreateCredentialInput,
    performedBy: string
  ): Promise<CredentialView> {
    this.ensureMasterKey();

    // Check for duplicates
    const existing = this.findByNameProjectEnv(
      input.name,
      input.project,
      input.environment
    );
    if (existing) {
      throw new VaultError(
        `Credential "${input.name}" already exists in ${input.project}/${input.environment}`,
        'DUPLICATE_CREDENTIAL'
      );
    }

    // Encrypt the value
    const encrypted = encrypt(input.value, this.masterKey!);

    // Calculate expiration
    const expirationDays = input.expirationDays ?? this.config.defaultExpirationDays ?? 0;
    const expiresAt = expirationDays > 0
      ? new Date(Date.now() + expirationDays * 24 * 60 * 60 * 1000)
      : undefined;

    // Create credential
    const credential: Credential = {
      id: generateId('cred'),
      name: input.name,
      encryptedValue: encrypted.encryptedValue,
      iv: encrypted.iv,
      authTag: encrypted.authTag,
      project: input.project,
      environment: input.environment,
      description: input.description,
      category: input.category,
      tags: input.tags,
      expiresAt,
      rotateAfterDays: input.rotateAfterDays ?? this.config.defaultRotationDays,
      lastRotatedAt: new Date(),
      permissions: {
        read: input.permissions?.read ?? ['admin'],
        manage: input.permissions?.manage ?? ['admin'],
      },
      audit: {
        createdBy: performedBy,
        createdAt: new Date(),
        accessCount: 0,
      },
      isActive: true,
    };

    // Store credential
    this.store.credentials.set(credential.id, credential);

    // Ensure project exists
    this.ensureProject(input.project, performedBy);

    // Audit log
    await this.auditLogger.logCreate(
      credential.id,
      credential.name,
      credential.project,
      credential.environment,
      performedBy
    );

    this.logger.info(
      `Created credential: ${credential.name} (${credential.project}/${credential.environment})`
    );

    return this.toView(credential);
  }

  /**
   * Update credential metadata (not the value)
   */
  async update(
    id: string,
    input: UpdateCredentialInput,
    performedBy: string
  ): Promise<CredentialView> {
    const credential = this.getCredentialById(id);

    const changes: Record<string, unknown> = {};

    if (input.description !== undefined) {
      changes.description = { from: credential.description, to: input.description };
      credential.description = input.description;
    }

    if (input.category !== undefined) {
      changes.category = { from: credential.category, to: input.category };
      credential.category = input.category;
    }

    if (input.tags !== undefined) {
      changes.tags = { from: credential.tags, to: input.tags };
      credential.tags = input.tags;
    }

    if (input.expirationDays !== undefined) {
      const newExpiry = input.expirationDays > 0
        ? new Date(Date.now() + input.expirationDays * 24 * 60 * 60 * 1000)
        : undefined;
      changes.expiresAt = { from: credential.expiresAt, to: newExpiry };
      credential.expiresAt = newExpiry;
    }

    if (input.rotateAfterDays !== undefined) {
      changes.rotateAfterDays = { from: credential.rotateAfterDays, to: input.rotateAfterDays };
      credential.rotateAfterDays = input.rotateAfterDays;
    }

    if (input.isActive !== undefined) {
      changes.isActive = { from: credential.isActive, to: input.isActive };
      credential.isActive = input.isActive;
    }

    if (input.permissions) {
      const oldPerms = { ...credential.permissions };
      if (input.permissions.read) {
        credential.permissions.read = input.permissions.read;
      }
      if (input.permissions.manage) {
        credential.permissions.manage = input.permissions.manage;
      }
      await this.auditLogger.logPermissionChange(
        credential.id,
        credential.name,
        credential.project,
        credential.environment,
        performedBy,
        oldPerms,
        credential.permissions
      );
    }

    // Update audit info
    credential.audit.lastModifiedBy = performedBy;
    credential.audit.lastModifiedAt = new Date();

    // Audit log
    await this.auditLogger.logUpdate(
      credential.id,
      credential.name,
      credential.project,
      credential.environment,
      performedBy,
      changes
    );

    this.logger.info(`Updated credential: ${credential.name}`);

    return this.toView(credential);
  }

  /**
   * Rotate credential value (set new encrypted value)
   */
  async rotate(
    id: string,
    input: RotateCredentialInput,
    performedBy: string
  ): Promise<CredentialView> {
    this.ensureMasterKey();

    const credential = this.getCredentialById(id);

    // Encrypt new value
    const encrypted = encrypt(input.newValue, this.masterKey!);

    // Update credential
    credential.encryptedValue = encrypted.encryptedValue;
    credential.iv = encrypted.iv;
    credential.authTag = encrypted.authTag;
    credential.lastRotatedAt = new Date();
    credential.audit.lastModifiedBy = performedBy;
    credential.audit.lastModifiedAt = new Date();

    // Audit log
    await this.auditLogger.logRotate(
      credential.id,
      credential.name,
      credential.project,
      credential.environment,
      performedBy
    );

    this.logger.info(`Rotated credential: ${credential.name}`);

    return this.toView(credential);
  }

  /**
   * Delete a credential
   */
  async delete(id: string, performedBy: string): Promise<void> {
    const credential = this.getCredentialById(id);

    // Remove from store
    this.store.credentials.delete(id);

    // Audit log
    await this.auditLogger.logDelete(
      credential.id,
      credential.name,
      credential.project,
      credential.environment,
      performedBy
    );

    this.logger.info(`Deleted credential: ${credential.name}`);
  }

  /**
   * Get credential by ID (view only, no value)
   */
  async getById(id: string): Promise<CredentialView | null> {
    const credential = this.store.credentials.get(id);
    return credential ? this.toView(credential) : null;
  }

  /**
   * List credentials (views only, no values)
   */
  async list(query?: CredentialQuery): Promise<CredentialView[]> {
    let credentials = Array.from(this.store.credentials.values());

    // Apply filters
    if (query) {
      if (query.project) {
        credentials = credentials.filter((c) => c.project === query.project);
      }

      if (query.environment) {
        credentials = credentials.filter((c) => c.environment === query.environment);
      }

      if (query.category) {
        credentials = credentials.filter((c) => c.category === query.category);
      }

      if (query.tags && query.tags.length > 0) {
        credentials = credentials.filter((c) =>
          c.tags?.some((t) => query.tags!.includes(t))
        );
      }

      if (query.status) {
        credentials = credentials.filter((c) =>
          this.getStatus(c) === query.status
        );
      }

      if (query.namePattern) {
        const pattern = new RegExp(query.namePattern, 'i');
        credentials = credentials.filter((c) => pattern.test(c.name));
      }

      if (!query.includeInactive) {
        credentials = credentials.filter((c) => c.isActive);
      }
    } else {
      // By default, only show active
      credentials = credentials.filter((c) => c.isActive);
    }

    // Sort by name
    credentials.sort((a, b) => a.name.localeCompare(b.name));

    return credentials.map((c) => this.toView(c));
  }

  /**
   * Get decrypted value (INTERNAL USE ONLY - not exposed to MCP)
   * This is called by SecureAccessor
   */
  async getValue(
    id: string,
    requesterId: string
  ): Promise<string> {
    this.ensureMasterKey();

    const credential = this.getCredentialById(id);

    // Check if active
    if (!credential.isActive) {
      await this.auditLogger.logAccess(
        id,
        credential.name,
        credential.project,
        credential.environment,
        requesterId,
        'code',
        false,
        'Credential is inactive'
      );
      throw new VaultError('Credential is inactive', 'CREDENTIAL_INACTIVE');
    }

    // Check expiration
    if (credential.expiresAt && credential.expiresAt < new Date()) {
      await this.auditLogger.logAccess(
        id,
        credential.name,
        credential.project,
        credential.environment,
        requesterId,
        'code',
        false,
        'Credential has expired'
      );
      throw new VaultError('Credential has expired', 'CREDENTIAL_EXPIRED');
    }

    // Decrypt value
    const value = decrypt(
      credential.encryptedValue,
      credential.iv,
      credential.authTag,
      this.masterKey!
    );

    // Update access audit
    credential.audit.lastAccessedAt = new Date();
    credential.audit.accessCount++;

    // Audit log
    await this.auditLogger.logAccess(
      id,
      credential.name,
      credential.project,
      credential.environment,
      requesterId,
      'code',
      true
    );

    return value;
  }

  /**
   * Get value by name, project, environment (INTERNAL USE ONLY)
   */
  async getValueByName(
    name: string,
    project: string,
    environment: string,
    requesterId: string
  ): Promise<string> {
    const credential = this.findByNameProjectEnv(name, project, environment);
    if (!credential) {
      throw new VaultError(
        `Credential "${name}" not found in ${project}/${environment}`,
        'CREDENTIAL_NOT_FOUND'
      );
    }
    return this.getValue(credential.id, requesterId);
  }

  /**
   * Check credentials that are expiring soon or need rotation
   */
  async checkExpiring(daysAhead: number = 7): Promise<{
    expiring: CredentialView[];
    expired: CredentialView[];
    needsRotation: CredentialView[];
  }> {
    const now = new Date();
    const futureDate = new Date(now.getTime() + daysAhead * 24 * 60 * 60 * 1000);

    const expiring: Credential[] = [];
    const expired: Credential[] = [];
    const needsRotation: Credential[] = [];

    for (const credential of this.store.credentials.values()) {
      if (!credential.isActive) continue;

      // Check expiration
      if (credential.expiresAt) {
        if (credential.expiresAt < now) {
          expired.push(credential);
        } else if (credential.expiresAt < futureDate) {
          expiring.push(credential);
        }
      }

      // Check rotation needed
      if (credential.rotateAfterDays && credential.lastRotatedAt) {
        const rotationDue = new Date(
          credential.lastRotatedAt.getTime() +
          credential.rotateAfterDays * 24 * 60 * 60 * 1000
        );
        if (rotationDue < now) {
          needsRotation.push(credential);
        }
      }
    }

    return {
      expiring: expiring.map((c) => this.toView(c)),
      expired: expired.map((c) => this.toView(c)),
      needsRotation: needsRotation.map((c) => this.toView(c)),
    };
  }

  /**
   * Get all projects
   */
  async getProjects(): Promise<Project[]> {
    return Array.from(this.store.projects.values());
  }

  /**
   * Get environments for a project
   */
  async getEnvironments(project: string): Promise<string[]> {
    const credentials = Array.from(this.store.credentials.values()).filter(
      (c) => c.project === project
    );
    const environments = new Set(credentials.map((c) => c.environment));
    return Array.from(environments);
  }

  /**
   * Get vault statistics
   */
  getStats(): {
    totalCredentials: number;
    activeCredentials: number;
    projects: number;
    expiredCount: number;
    expiringCount: number;
  } {
    const credentials = Array.from(this.store.credentials.values());
    const now = new Date();
    const weekFromNow = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);

    return {
      totalCredentials: credentials.length,
      activeCredentials: credentials.filter((c) => c.isActive).length,
      projects: this.store.projects.size,
      expiredCount: credentials.filter(
        (c) => c.expiresAt && c.expiresAt < now
      ).length,
      expiringCount: credentials.filter(
        (c) => c.expiresAt && c.expiresAt >= now && c.expiresAt < weekFromNow
      ).length,
    };
  }

  // =========================================================================
  // Private Helper Methods
  // =========================================================================

  private ensureMasterKey(): void {
    if (!this.masterKey) {
      throw new VaultError(
        'Master key not configured. Set VAULT_MASTER_KEY or configure in plugin options.',
        'MASTER_KEY_NOT_SET'
      );
    }
  }

  private getCredentialById(id: string): Credential {
    const credential = this.store.credentials.get(id);
    if (!credential) {
      throw new VaultError(`Credential not found: ${id}`, 'CREDENTIAL_NOT_FOUND');
    }
    return credential;
  }

  private findByNameProjectEnv(
    name: string,
    project: string,
    environment: string
  ): Credential | undefined {
    for (const credential of this.store.credentials.values()) {
      if (
        credential.name === name &&
        credential.project === project &&
        credential.environment === environment
      ) {
        return credential;
      }
    }
    return undefined;
  }

  private ensureProject(projectId: string, createdBy: string): void {
    if (!this.store.projects.has(projectId)) {
      this.store.projects.set(projectId, {
        id: projectId,
        name: projectId,
        environments: ['dev', 'staging', 'prod'],
        defaultEnvironment: 'dev',
        createdAt: new Date(),
        createdBy,
      });
    }
  }

  private getStatus(credential: Credential): CredentialStatus {
    if (!credential.isActive) return 'inactive';

    const now = new Date();

    if (credential.expiresAt && credential.expiresAt < now) {
      return 'expired';
    }

    if (credential.expiresAt) {
      const weekFromNow = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
      if (credential.expiresAt < weekFromNow) {
        return 'expiring_soon';
      }
    }

    if (credential.rotateAfterDays && credential.lastRotatedAt) {
      const rotationDue = new Date(
        credential.lastRotatedAt.getTime() +
        credential.rotateAfterDays * 24 * 60 * 60 * 1000
      );
      if (rotationDue < now) {
        return 'rotation_needed';
      }
    }

    return 'active';
  }

  private toView(credential: Credential): CredentialView {
    return {
      id: credential.id,
      name: credential.name,
      project: credential.project,
      environment: credential.environment,
      description: credential.description,
      category: credential.category,
      tags: credential.tags,
      expiresAt: credential.expiresAt,
      rotateAfterDays: credential.rotateAfterDays,
      lastRotatedAt: credential.lastRotatedAt,
      permissions: credential.permissions,
      isActive: credential.isActive,
      value: MASKED_VALUE,
      status: this.getStatus(credential),
      audit: {
        createdBy: credential.audit.createdBy,
        createdAt: credential.audit.createdAt,
        lastAccessedAt: credential.audit.lastAccessedAt,
        accessCount: credential.audit.accessCount,
      },
    };
  }
}

/**
 * Create a new credential vault instance
 */
export function createVault(
  config: VaultPluginConfig,
  logger: PluginLogger,
  auditLogger: AuditLogger
): CredentialVault {
  return new CredentialVault(config, logger, auditLogger);
}
