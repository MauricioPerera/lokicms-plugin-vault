/**
 * LokiCMS Vault Plugin
 *
 * Provides secure credential storage with encryption, expiration, and audit logging.
 * MCP tools provide management but NEVER expose actual values.
 */

import { z } from 'zod';
import type {
  PluginDefinition,
  PluginAPI,
  VaultPluginConfig,
  CredentialCategory,
} from './types.js';
import { CREDENTIAL_CATEGORIES } from './types.js';
import { createVault, CredentialVault } from './vault.js';
import { createAuditLogger, AuditLogger } from './audit.js';
import { createSecureAccessor, SecureAccessor } from './secure-accessor.js';

// Plugin state
let vault: CredentialVault | null = null;
let auditLogger: AuditLogger | null = null;
let secureAccessor: SecureAccessor | null = null;
let pluginConfig: VaultPluginConfig | null = null;

/**
 * Get the secure accessor for code usage
 * This is the ONLY way to access actual credential values
 */
export function getSecureAccessor(): SecureAccessor {
  if (!secureAccessor) {
    throw new Error('Vault plugin not initialized. Ensure plugin is registered.');
  }
  return secureAccessor;
}

/**
 * LokiCMS Vault Plugin Definition
 */
const plugin: PluginDefinition = {
  name: 'lokicms-vault',
  version: '1.0.0',
  description: 'Secure credential vault with encryption, expiration, and audit logging',

  async register(api: PluginAPI) {
    pluginConfig = (api.config.vault as VaultPluginConfig) || {};

    api.logger.info('Initializing Vault plugin');

    // Create audit logger
    auditLogger = createAuditLogger(api.logger, {
      enabled: pluginConfig.enableAudit ?? true,
      retentionDays: pluginConfig.auditRetentionDays ?? 90,
    });

    // Create vault
    vault = createVault(pluginConfig, api.logger, auditLogger);

    // Create secure accessor (for code use only)
    secureAccessor = createSecureAccessor(vault, api.logger, auditLogger);

    // Register MCP tools (these NEVER expose values)
    registerMcpTools(api);

    api.logger.info('Vault plugin registered');
  },
};

/**
 * Register MCP tools
 * IMPORTANT: These tools NEVER return actual credential values
 */
function registerMcpTools(api: PluginAPI): void {
  // ========================================================================
  // MCP Tool: vault_status
  // ========================================================================
  api.mcp.registerTool('vault_status', {
    description: 'Get vault status and statistics',
    inputSchema: z.object({}),
    handler: async () => {
      if (!vault || !auditLogger) {
        return { error: 'Vault plugin not initialized' };
      }

      return {
        hasMasterKey: vault.hasMasterKey(),
        stats: vault.getStats(),
        audit: auditLogger.getStats(),
      };
    },
  });

  // ========================================================================
  // MCP Tool: vault_list
  // ========================================================================
  api.mcp.registerTool('vault_list', {
    description: 'List credentials (metadata only, values are never exposed)',
    inputSchema: z.object({
      project: z.string().optional().describe('Filter by project'),
      environment: z.string().optional().describe('Filter by environment'),
      category: z.enum(CREDENTIAL_CATEGORIES as unknown as [string, ...string[]]).optional(),
      status: z
        .enum(['active', 'expired', 'expiring_soon', 'rotation_needed', 'inactive'])
        .optional(),
      includeInactive: z.boolean().optional().describe('Include inactive credentials'),
    }),
    handler: async (input: {
      project?: string;
      environment?: string;
      category?: CredentialCategory;
      status?: string;
      includeInactive?: boolean;
    }) => {
      if (!vault) {
        return { error: 'Vault plugin not initialized' };
      }

      const credentials = await vault.list({
        project: input.project,
        environment: input.environment,
        category: input.category,
        status: input.status as 'active' | 'expired' | 'expiring_soon' | 'rotation_needed' | 'inactive',
        includeInactive: input.includeInactive,
      });

      return {
        count: credentials.length,
        credentials: credentials.map((c) => ({
          id: c.id,
          name: c.name,
          project: c.project,
          environment: c.environment,
          description: c.description,
          category: c.category,
          status: c.status,
          expiresAt: c.expiresAt,
          lastRotatedAt: c.lastRotatedAt,
          value: c.value, // Always masked
        })),
      };
    },
  });

  // ========================================================================
  // MCP Tool: vault_create
  // ========================================================================
  api.mcp.registerTool('vault_create', {
    description: 'Create a new credential (value will be encrypted and stored securely)',
    inputSchema: z.object({
      name: z.string().describe('Credential name (e.g., API_KEY, DB_PASSWORD)'),
      value: z.string().describe('Credential value (will be encrypted)'),
      project: z.string().describe('Project identifier'),
      environment: z.string().describe('Environment (dev, staging, prod)'),
      description: z.string().optional().describe('Human-readable description'),
      category: z.enum(CREDENTIAL_CATEGORIES as unknown as [string, ...string[]]).optional(),
      expirationDays: z.number().optional().describe('Days until expiration (0 = never)'),
      rotateAfterDays: z.number().optional().describe('Days until rotation reminder'),
    }),
    handler: async (input: {
      name: string;
      value: string;
      project: string;
      environment: string;
      description?: string;
      category?: CredentialCategory;
      expirationDays?: number;
      rotateAfterDays?: number;
    }) => {
      if (!vault) {
        return { error: 'Vault plugin not initialized' };
      }

      try {
        const performedBy = api.getCurrentUser?.()?.id || 'mcp-agent';

        const credential = await vault.create(
          {
            name: input.name,
            value: input.value,
            project: input.project,
            environment: input.environment,
            description: input.description,
            category: input.category,
            expirationDays: input.expirationDays,
            rotateAfterDays: input.rotateAfterDays,
          },
          performedBy
        );

        // IMPORTANT: Never return the actual value
        return {
          success: true,
          credential: {
            id: credential.id,
            name: credential.name,
            project: credential.project,
            environment: credential.environment,
            status: credential.status,
            value: credential.value, // Masked
          },
          message: `Credential "${input.name}" created and encrypted securely`,
        };
      } catch (error) {
        return {
          success: false,
          error: error instanceof Error ? error.message : 'Creation failed',
        };
      }
    },
  });

  // ========================================================================
  // MCP Tool: vault_update
  // ========================================================================
  api.mcp.registerTool('vault_update', {
    description: 'Update credential metadata (not the value)',
    inputSchema: z.object({
      id: z.string().describe('Credential ID'),
      description: z.string().optional(),
      category: z.enum(CREDENTIAL_CATEGORIES as unknown as [string, ...string[]]).optional(),
      expirationDays: z.number().optional(),
      rotateAfterDays: z.number().optional(),
      isActive: z.boolean().optional(),
    }),
    handler: async (input: {
      id: string;
      description?: string;
      category?: CredentialCategory;
      expirationDays?: number;
      rotateAfterDays?: number;
      isActive?: boolean;
    }) => {
      if (!vault) {
        return { error: 'Vault plugin not initialized' };
      }

      try {
        const performedBy = api.getCurrentUser?.()?.id || 'mcp-agent';

        const credential = await vault.update(
          input.id,
          {
            description: input.description,
            category: input.category,
            expirationDays: input.expirationDays,
            rotateAfterDays: input.rotateAfterDays,
            isActive: input.isActive,
          },
          performedBy
        );

        return {
          success: true,
          credential: {
            id: credential.id,
            name: credential.name,
            status: credential.status,
          },
        };
      } catch (error) {
        return {
          success: false,
          error: error instanceof Error ? error.message : 'Update failed',
        };
      }
    },
  });

  // ========================================================================
  // MCP Tool: vault_rotate
  // ========================================================================
  api.mcp.registerTool('vault_rotate', {
    description: 'Rotate credential value (replace with new encrypted value)',
    inputSchema: z.object({
      id: z.string().describe('Credential ID'),
      newValue: z.string().describe('New credential value'),
    }),
    handler: async (input: { id: string; newValue: string }) => {
      if (!vault) {
        return { error: 'Vault plugin not initialized' };
      }

      try {
        const performedBy = api.getCurrentUser?.()?.id || 'mcp-agent';

        const credential = await vault.rotate(
          input.id,
          { newValue: input.newValue },
          performedBy
        );

        return {
          success: true,
          message: `Credential "${credential.name}" rotated successfully`,
          credential: {
            id: credential.id,
            name: credential.name,
            lastRotatedAt: credential.lastRotatedAt,
          },
        };
      } catch (error) {
        return {
          success: false,
          error: error instanceof Error ? error.message : 'Rotation failed',
        };
      }
    },
  });

  // ========================================================================
  // MCP Tool: vault_delete
  // ========================================================================
  api.mcp.registerTool('vault_delete', {
    description: 'Delete a credential permanently',
    inputSchema: z.object({
      id: z.string().describe('Credential ID'),
      confirm: z.boolean().describe('Confirm deletion'),
    }),
    handler: async (input: { id: string; confirm: boolean }) => {
      if (!vault) {
        return { error: 'Vault plugin not initialized' };
      }

      if (!input.confirm) {
        return {
          success: false,
          error: 'Deletion not confirmed. Set confirm: true to proceed.',
        };
      }

      try {
        const performedBy = api.getCurrentUser?.()?.id || 'mcp-agent';
        const credential = await vault.getById(input.id);

        if (!credential) {
          return { success: false, error: 'Credential not found' };
        }

        await vault.delete(input.id, performedBy);

        return {
          success: true,
          message: `Credential "${credential.name}" deleted permanently`,
        };
      } catch (error) {
        return {
          success: false,
          error: error instanceof Error ? error.message : 'Deletion failed',
        };
      }
    },
  });

  // ========================================================================
  // MCP Tool: vault_check_expiry
  // ========================================================================
  api.mcp.registerTool('vault_check_expiry', {
    description: 'Check for expiring, expired, or rotation-needed credentials',
    inputSchema: z.object({
      daysAhead: z.number().optional().describe('Days to look ahead for expiring (default: 7)'),
    }),
    handler: async (input: { daysAhead?: number }) => {
      if (!vault) {
        return { error: 'Vault plugin not initialized' };
      }

      const result = await vault.checkExpiring(input.daysAhead ?? 7);

      return {
        expiring: result.expiring.map((c) => ({
          id: c.id,
          name: c.name,
          project: c.project,
          environment: c.environment,
          expiresAt: c.expiresAt,
        })),
        expired: result.expired.map((c) => ({
          id: c.id,
          name: c.name,
          project: c.project,
          environment: c.environment,
          expiresAt: c.expiresAt,
        })),
        needsRotation: result.needsRotation.map((c) => ({
          id: c.id,
          name: c.name,
          project: c.project,
          environment: c.environment,
          lastRotatedAt: c.lastRotatedAt,
          rotateAfterDays: c.rotateAfterDays,
        })),
        summary: {
          expiringCount: result.expiring.length,
          expiredCount: result.expired.length,
          needsRotationCount: result.needsRotation.length,
        },
      };
    },
  });

  // ========================================================================
  // MCP Tool: vault_audit
  // ========================================================================
  api.mcp.registerTool('vault_audit', {
    description: 'Query audit logs for credential access history',
    inputSchema: z.object({
      credentialId: z.string().optional().describe('Filter by credential ID'),
      project: z.string().optional(),
      environment: z.string().optional(),
      action: z
        .enum([
          'create',
          'read',
          'update',
          'delete',
          'rotate',
          'access',
          'inject',
          'export',
          'permission_change',
        ])
        .optional(),
      limit: z.number().optional().describe('Max entries to return (default: 50)'),
    }),
    handler: async (input: {
      credentialId?: string;
      project?: string;
      environment?: string;
      action?: string;
      limit?: number;
    }) => {
      if (!auditLogger) {
        return { error: 'Vault plugin not initialized' };
      }

      const entries = await auditLogger.query({
        credentialId: input.credentialId,
        project: input.project,
        environment: input.environment,
        action: input.action as 'create' | 'read' | 'update' | 'delete' | 'rotate' | 'access' | 'inject' | 'export' | 'permission_change',
        limit: input.limit ?? 50,
      });

      return {
        count: entries.length,
        entries: entries.map((e) => ({
          id: e.id,
          timestamp: e.timestamp,
          action: e.action,
          credentialName: e.credentialName,
          project: e.project,
          environment: e.environment,
          performedBy: e.performedBy,
          success: e.success,
          errorMessage: e.errorMessage,
        })),
      };
    },
  });

  // ========================================================================
  // MCP Tool: vault_projects
  // ========================================================================
  api.mcp.registerTool('vault_projects', {
    description: 'List all projects and their environments',
    inputSchema: z.object({}),
    handler: async () => {
      if (!vault) {
        return { error: 'Vault plugin not initialized' };
      }

      const projects = await vault.getProjects();

      return {
        projects: await Promise.all(
          projects.map(async (p) => ({
            id: p.id,
            name: p.name,
            environments: await vault!.getEnvironments(p.id),
            credentialCount: (
              await vault!.list({ project: p.id, includeInactive: true })
            ).length,
          }))
        ),
      };
    },
  });

  // ========================================================================
  // MCP Tool: vault_set_master_key
  // ========================================================================
  api.mcp.registerTool('vault_set_master_key', {
    description: 'Set the master encryption key (required for vault operations)',
    inputSchema: z.object({
      key: z.string().describe('Master encryption key (min 16 chars)'),
    }),
    handler: async (input: { key: string }) => {
      if (!vault) {
        return { error: 'Vault plugin not initialized' };
      }

      const result = vault.setMasterKey(input.key);

      if (result.success) {
        return {
          success: true,
          message: 'Master key configured successfully',
        };
      } else {
        return {
          success: false,
          errors: result.errors,
        };
      }
    },
  });

  api.logger.info(
    'Vault plugin registered 9 MCP tools: vault_status, vault_list, vault_create, vault_update, vault_rotate, vault_delete, vault_check_expiry, vault_audit, vault_projects'
  );
}

export default plugin;
