/**
 * LokiCMS Vault Plugin
 *
 * Secure credential storage with encryption, expiration, and audit logging.
 */

// Export plugin
export { default } from './plugin.js';

// Export secure accessor (the ONLY way to get actual values)
export { getSecureAccessor } from './plugin.js';
export { SecureAccessor, ScopedAccessor, createSecureAccessor } from './secure-accessor.js';

// Export vault (for advanced use cases)
export { CredentialVault, createVault } from './vault.js';

// Export audit logger
export { AuditLogger, createAuditLogger } from './audit.js';

// Export crypto utilities (for custom implementations)
export {
  encrypt,
  decrypt,
  generateId,
  hashValue,
  validateMasterKey,
  generateSecureKey,
} from './crypto.js';

// Export types
export type {
  // Config
  VaultPluginConfig,

  // Credentials
  Credential,
  CredentialView,
  CredentialStatus,
  CredentialCategory,
  CredentialPermissions,
  CredentialAudit,

  // Input types
  CreateCredentialInput,
  UpdateCredentialInput,
  RotateCredentialInput,
  CredentialQuery,

  // Audit
  AuditEntry,
  AuditAction,
  AuditQuery,

  // Projects
  Project,
  Environment,

  // Accessor options
  SecureAccessorOptions,
  InjectOptions,

  // Plugin API types
  PluginDefinition,
  PluginAPI,
  PluginLogger,

  // Errors
  VaultError,
  VaultErrorCode,
} from './types.js';

// Export constants
export {
  DEFAULT_ENVIRONMENTS,
  CREDENTIAL_CATEGORIES,
  MASKED_VALUE,
} from './types.js';
