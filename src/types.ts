/**
 * Type definitions for LokiCMS Vault Plugin
 */

// ============================================================================
// Plugin Configuration
// ============================================================================

export interface VaultPluginConfig {
  /** Master key for encryption (from env var or provided directly) */
  masterKey?: string;
  /** Environment variable name containing the master key */
  masterKeyEnvVar?: string;
  /** Default expiration in days (0 = no expiration) */
  defaultExpirationDays?: number;
  /** Enable audit logging */
  enableAudit?: boolean;
  /** Audit log retention in days */
  auditRetentionDays?: number;
  /** Enable automatic rotation reminders */
  enableRotationReminders?: boolean;
  /** Default rotation reminder in days */
  defaultRotationDays?: number;
}

// ============================================================================
// Credential Types
// ============================================================================

export interface Credential {
  /** Unique identifier */
  id: string;
  /** Credential name (e.g., API_KEY, DB_PASSWORD) */
  name: string;
  /** Encrypted value (AES-256-GCM) */
  encryptedValue: string;
  /** Initialization vector for encryption */
  iv: string;
  /** GCM authentication tag */
  authTag: string;

  /** Project identifier */
  project: string;
  /** Environment (dev, staging, prod) */
  environment: string;

  /** Human-readable description */
  description?: string;
  /** Category for organization */
  category?: CredentialCategory;
  /** Custom tags */
  tags?: string[];

  /** Expiration date */
  expiresAt?: Date;
  /** Days until rotation reminder */
  rotateAfterDays?: number;
  /** Last rotation date */
  lastRotatedAt?: Date;

  /** Access permissions */
  permissions: CredentialPermissions;

  /** Audit metadata */
  audit: CredentialAudit;

  /** Is credential active */
  isActive: boolean;
}

export type CredentialCategory =
  | 'database'
  | 'api'
  | 'service'
  | 'oauth'
  | 'certificate'
  | 'ssh'
  | 'encryption'
  | 'other';

export interface CredentialPermissions {
  /** Roles that can read/use the credential */
  read: string[];
  /** Roles that can manage the credential */
  manage: string[];
}

export interface CredentialAudit {
  /** User who created the credential */
  createdBy: string;
  /** Creation timestamp */
  createdAt: Date;
  /** User who last modified the credential */
  lastModifiedBy?: string;
  /** Last modification timestamp */
  lastModifiedAt?: Date;
  /** Last access timestamp */
  lastAccessedAt?: Date;
  /** Total access count */
  accessCount: number;
}

// ============================================================================
// Credential Input Types (for creating/updating)
// ============================================================================

export interface CreateCredentialInput {
  /** Credential name */
  name: string;
  /** Plain text value (will be encrypted) */
  value: string;
  /** Project identifier */
  project: string;
  /** Environment */
  environment: string;
  /** Description */
  description?: string;
  /** Category */
  category?: CredentialCategory;
  /** Tags */
  tags?: string[];
  /** Expiration in days (0 = no expiration) */
  expirationDays?: number;
  /** Rotation reminder in days */
  rotateAfterDays?: number;
  /** Permissions */
  permissions?: Partial<CredentialPermissions>;
}

export interface UpdateCredentialInput {
  /** New description */
  description?: string;
  /** New category */
  category?: CredentialCategory;
  /** New tags */
  tags?: string[];
  /** New expiration in days */
  expirationDays?: number;
  /** New rotation reminder in days */
  rotateAfterDays?: number;
  /** New permissions */
  permissions?: Partial<CredentialPermissions>;
  /** Active status */
  isActive?: boolean;
}

export interface RotateCredentialInput {
  /** New plain text value */
  newValue: string;
}

// ============================================================================
// Credential View Types (safe for MCP - no values)
// ============================================================================

export interface CredentialView {
  id: string;
  name: string;
  project: string;
  environment: string;
  description?: string;
  category?: CredentialCategory;
  tags?: string[];
  expiresAt?: Date;
  rotateAfterDays?: number;
  lastRotatedAt?: Date;
  permissions: CredentialPermissions;
  isActive: boolean;
  /** Masked value indicator */
  value: '••••••••••••';
  /** Expiration status */
  status: CredentialStatus;
  audit: {
    createdBy: string;
    createdAt: Date;
    lastAccessedAt?: Date;
    accessCount: number;
  };
}

export type CredentialStatus =
  | 'active'
  | 'expired'
  | 'expiring_soon'
  | 'rotation_needed'
  | 'inactive';

// ============================================================================
// Query Types
// ============================================================================

export interface CredentialQuery {
  /** Filter by project */
  project?: string;
  /** Filter by environment */
  environment?: string;
  /** Filter by category */
  category?: CredentialCategory;
  /** Filter by tags (any match) */
  tags?: string[];
  /** Filter by status */
  status?: CredentialStatus;
  /** Filter by name pattern */
  namePattern?: string;
  /** Include inactive credentials */
  includeInactive?: boolean;
}

// ============================================================================
// Audit Types
// ============================================================================

export interface AuditEntry {
  id: string;
  timestamp: Date;
  action: AuditAction;
  credentialId: string;
  credentialName: string;
  project: string;
  environment: string;
  performedBy: string;
  performedByType: 'user' | 'system' | 'code';
  ipAddress?: string;
  userAgent?: string;
  details?: Record<string, unknown>;
  success: boolean;
  errorMessage?: string;
}

export type AuditAction =
  | 'create'
  | 'read'
  | 'update'
  | 'delete'
  | 'rotate'
  | 'access'    // Code accessed the value
  | 'inject'    // Value injected into env
  | 'export'    // Bulk export
  | 'permission_change';

export interface AuditQuery {
  /** Filter by credential ID */
  credentialId?: string;
  /** Filter by project */
  project?: string;
  /** Filter by environment */
  environment?: string;
  /** Filter by action */
  action?: AuditAction;
  /** Filter by performer */
  performedBy?: string;
  /** Start date */
  startDate?: Date;
  /** End date */
  endDate?: Date;
  /** Limit results */
  limit?: number;
  /** Offset for pagination */
  offset?: number;
}

// ============================================================================
// Project & Environment Types
// ============================================================================

export interface Project {
  id: string;
  name: string;
  description?: string;
  environments: string[];
  defaultEnvironment: string;
  createdAt: Date;
  createdBy: string;
}

export interface Environment {
  name: string;
  description?: string;
  isProduction: boolean;
}

// ============================================================================
// Secure Accessor Types (Code-only)
// ============================================================================

export interface SecureAccessorOptions {
  /** Project to access */
  project: string;
  /** Environment to access */
  environment: string;
  /** Requester identifier for audit */
  requesterId?: string;
}

export interface InjectOptions extends SecureAccessorOptions {
  /** Prefix for environment variables */
  prefix?: string;
  /** Override existing env vars */
  override?: boolean;
}

// ============================================================================
// Plugin API Types (simplified for this plugin)
// ============================================================================

export interface PluginDefinition {
  name: string;
  version: string;
  description?: string;
  register: (api: PluginAPI) => void | Promise<void>;
}

export interface PluginAPI {
  config: Record<string, unknown>;
  logger: PluginLogger;
  hooks: PluginHooks;
  mcp: McpTools;
  services: {
    entries: unknown;
    contentTypes: unknown;
    taxonomies: unknown;
    terms: unknown;
    users: unknown;
  };
  /** Get current user context */
  getCurrentUser?: () => { id: string; role: string } | null;
}

export interface PluginLogger {
  info: (message: string, ...args: unknown[]) => void;
  warn: (message: string, ...args: unknown[]) => void;
  error: (message: string, ...args: unknown[]) => void;
  debug: (message: string, ...args: unknown[]) => void;
}

export interface PluginHooks {
  on: (event: string, handler: HookHandler) => void;
  off: (event: string, handler?: HookHandler) => void;
}

export type HookHandler = (data: unknown) => void | Promise<void>;

export interface McpToolDefinition {
  description: string;
  inputSchema: unknown;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  handler: (input: any) => Promise<unknown>;
}

export interface McpTools {
  registerTool: (name: string, tool: McpToolDefinition) => void;
}

// ============================================================================
// Error Types
// ============================================================================

export class VaultError extends Error {
  constructor(
    message: string,
    public code: VaultErrorCode,
    public details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'VaultError';
  }
}

export type VaultErrorCode =
  | 'MASTER_KEY_NOT_SET'
  | 'ENCRYPTION_FAILED'
  | 'DECRYPTION_FAILED'
  | 'CREDENTIAL_NOT_FOUND'
  | 'CREDENTIAL_EXPIRED'
  | 'CREDENTIAL_INACTIVE'
  | 'PERMISSION_DENIED'
  | 'DUPLICATE_CREDENTIAL'
  | 'INVALID_INPUT'
  | 'PROJECT_NOT_FOUND'
  | 'AUDIT_FAILED';

// ============================================================================
// Constants
// ============================================================================

export const DEFAULT_ENVIRONMENTS = ['dev', 'staging', 'prod'] as const;

export const CREDENTIAL_CATEGORIES: CredentialCategory[] = [
  'database',
  'api',
  'service',
  'oauth',
  'certificate',
  'ssh',
  'encryption',
  'other',
];

export const MASKED_VALUE = '••••••••••••' as const;
