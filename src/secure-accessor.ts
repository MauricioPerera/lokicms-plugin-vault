/**
 * Secure Accessor for Credential Values
 *
 * This module provides the ONLY way to access actual credential values.
 * It is designed for use by application code, NOT by MCP tools or agents.
 *
 * SECURITY: This module should never be exposed through MCP tools.
 */

import type {
  SecureAccessorOptions,
  InjectOptions,
  PluginLogger,
} from './types.js';
import { VaultError } from './types.js';
import type { CredentialVault } from './vault.js';
import type { AuditLogger } from './audit.js';

/**
 * SecureAccessor provides safe, audited access to credential values
 * for application code only.
 */
export class SecureAccessor {
  private vault: CredentialVault;
  private logger: PluginLogger;
  private auditLogger: AuditLogger;
  private defaultOptions: Partial<SecureAccessorOptions>;

  constructor(
    vault: CredentialVault,
    logger: PluginLogger,
    auditLogger: AuditLogger,
    defaultOptions?: Partial<SecureAccessorOptions>
  ) {
    this.vault = vault;
    this.logger = logger;
    this.auditLogger = auditLogger;
    this.defaultOptions = defaultOptions || {};
  }

  /**
   * Get a single credential value by name
   *
   * @param name - Credential name (e.g., 'API_KEY')
   * @param options - Access options including project and environment
   * @returns The decrypted credential value
   *
   * @example
   * const apiKey = await accessor.get('OPENAI_API_KEY', {
   *   project: 'my-app',
   *   environment: 'prod'
   * });
   */
  async get(name: string, options: SecureAccessorOptions): Promise<string> {
    const opts = this.mergeOptions(options);
    this.validateOptions(opts);

    try {
      const value = await this.vault.getValueByName(
        name,
        opts.project!,
        opts.environment!,
        opts.requesterId || 'code'
      );

      this.logger.debug(
        `[SecureAccessor] Retrieved credential: ${name} (${opts.project}/${opts.environment})`
      );

      return value;
    } catch (error) {
      this.logger.error(
        `[SecureAccessor] Failed to get credential: ${name}`,
        error
      );
      throw error;
    }
  }

  /**
   * Get multiple credential values at once
   *
   * @param names - Array of credential names
   * @param options - Access options
   * @returns Object mapping credential names to their values
   *
   * @example
   * const creds = await accessor.getMany(['DB_HOST', 'DB_USER', 'DB_PASS'], {
   *   project: 'my-app',
   *   environment: 'prod'
   * });
   * console.log(creds.DB_HOST); // 'localhost'
   */
  async getMany(
    names: string[],
    options: SecureAccessorOptions
  ): Promise<Record<string, string>> {
    const opts = this.mergeOptions(options);
    this.validateOptions(opts);

    const result: Record<string, string> = {};
    const errors: string[] = [];

    for (const name of names) {
      try {
        result[name] = await this.vault.getValueByName(
          name,
          opts.project!,
          opts.environment!,
          opts.requesterId || 'code'
        );
      } catch (error) {
        if (error instanceof VaultError) {
          errors.push(`${name}: ${error.message}`);
        } else {
          errors.push(`${name}: Unknown error`);
        }
      }
    }

    if (errors.length > 0) {
      this.logger.warn(
        `[SecureAccessor] Some credentials could not be retrieved: ${errors.join(', ')}`
      );
    }

    return result;
  }

  /**
   * Inject credentials into process.env
   *
   * @param names - Credential names to inject
   * @param options - Injection options
   * @returns Object with injected credential names
   *
   * @example
   * await accessor.inject(['API_KEY', 'SECRET'], {
   *   project: 'my-app',
   *   environment: 'prod',
   *   prefix: 'MY_APP_'  // Results in MY_APP_API_KEY, MY_APP_SECRET
   * });
   */
  async inject(
    names: string[],
    options: InjectOptions
  ): Promise<{ injected: string[]; skipped: string[]; errors: string[] }> {
    const opts = this.mergeOptions(options);
    this.validateOptions(opts);

    const prefix = options.prefix || '';
    const override = options.override ?? false;

    const injected: string[] = [];
    const skipped: string[] = [];
    const errors: string[] = [];

    for (const name of names) {
      const envVarName = `${prefix}${name}`;

      // Check if already exists and override is false
      if (!override && process.env[envVarName] !== undefined) {
        skipped.push(name);
        continue;
      }

      try {
        const value = await this.vault.getValueByName(
          name,
          opts.project!,
          opts.environment!,
          opts.requesterId || 'code'
        );

        // Inject into process.env
        process.env[envVarName] = value;
        injected.push(name);

        // Log injection
        const credentials = await this.vault.list({
          project: opts.project,
          environment: opts.environment,
          namePattern: `^${name}$`,
        });
        if (credentials.length > 0) {
          await this.auditLogger.logInject(
            credentials[0].id,
            name,
            opts.project!,
            opts.environment!,
            opts.requesterId || 'code'
          );
        }
      } catch (error) {
        if (error instanceof VaultError) {
          errors.push(`${name}: ${error.message}`);
        } else {
          errors.push(`${name}: Unknown error`);
        }
      }
    }

    this.logger.info(
      `[SecureAccessor] Injected ${injected.length} credentials, skipped ${skipped.length}, errors ${errors.length}`
    );

    return { injected, skipped, errors };
  }

  /**
   * Remove injected credentials from process.env
   *
   * @param names - Credential names to remove
   * @param prefix - Optional prefix that was used during injection
   */
  async uninject(names: string[], prefix: string = ''): Promise<void> {
    for (const name of names) {
      const envVarName = `${prefix}${name}`;
      delete process.env[envVarName];
    }

    this.logger.debug(`[SecureAccessor] Removed ${names.length} credentials from env`);
  }

  /**
   * Check if a credential exists and is accessible
   */
  async exists(name: string, options: SecureAccessorOptions): Promise<boolean> {
    const opts = this.mergeOptions(options);
    this.validateOptions(opts);

    const credentials = await this.vault.list({
      project: opts.project,
      environment: opts.environment,
      namePattern: `^${name}$`,
    });

    return credentials.length > 0 && credentials[0].status === 'active';
  }

  /**
   * Get credential status without accessing the value
   */
  async getStatus(
    name: string,
    options: SecureAccessorOptions
  ): Promise<{
    exists: boolean;
    active: boolean;
    expired: boolean;
    expiresAt?: Date;
    rotationNeeded: boolean;
  }> {
    const opts = this.mergeOptions(options);
    this.validateOptions(opts);

    const credentials = await this.vault.list({
      project: opts.project,
      environment: opts.environment,
      namePattern: `^${name}$`,
      includeInactive: true,
    });

    if (credentials.length === 0) {
      return {
        exists: false,
        active: false,
        expired: false,
        rotationNeeded: false,
      };
    }

    const cred = credentials[0];

    return {
      exists: true,
      active: cred.status === 'active',
      expired: cred.status === 'expired',
      expiresAt: cred.expiresAt,
      rotationNeeded: cred.status === 'rotation_needed',
    };
  }

  /**
   * Create a scoped accessor with pre-filled options
   */
  scope(options: Partial<SecureAccessorOptions>): ScopedAccessor {
    return new ScopedAccessor(this, options);
  }

  // =========================================================================
  // Private Methods
  // =========================================================================

  private mergeOptions(options: Partial<SecureAccessorOptions>): SecureAccessorOptions {
    return {
      ...this.defaultOptions,
      ...options,
    } as SecureAccessorOptions;
  }

  private validateOptions(options: SecureAccessorOptions): void {
    if (!options.project) {
      throw new VaultError('Project is required', 'INVALID_INPUT');
    }
    if (!options.environment) {
      throw new VaultError('Environment is required', 'INVALID_INPUT');
    }
  }
}

/**
 * Scoped accessor with pre-filled project/environment
 */
export class ScopedAccessor {
  private accessor: SecureAccessor;
  private scopeOptions: Partial<SecureAccessorOptions>;

  constructor(accessor: SecureAccessor, scopeOptions: Partial<SecureAccessorOptions>) {
    this.accessor = accessor;
    this.scopeOptions = scopeOptions;
  }

  async get(name: string, options?: Partial<SecureAccessorOptions>): Promise<string> {
    return this.accessor.get(name, { ...this.scopeOptions, ...options } as SecureAccessorOptions);
  }

  async getMany(
    names: string[],
    options?: Partial<SecureAccessorOptions>
  ): Promise<Record<string, string>> {
    return this.accessor.getMany(names, { ...this.scopeOptions, ...options } as SecureAccessorOptions);
  }

  async inject(
    names: string[],
    options?: Partial<InjectOptions>
  ): Promise<{ injected: string[]; skipped: string[]; errors: string[] }> {
    return this.accessor.inject(names, { ...this.scopeOptions, ...options } as InjectOptions);
  }

  async uninject(names: string[], prefix?: string): Promise<void> {
    return this.accessor.uninject(names, prefix);
  }

  async exists(name: string): Promise<boolean> {
    return this.accessor.exists(name, this.scopeOptions as SecureAccessorOptions);
  }
}

/**
 * Create a secure accessor instance
 */
export function createSecureAccessor(
  vault: CredentialVault,
  logger: PluginLogger,
  auditLogger: AuditLogger,
  defaultOptions?: Partial<SecureAccessorOptions>
): SecureAccessor {
  return new SecureAccessor(vault, logger, auditLogger, defaultOptions);
}
