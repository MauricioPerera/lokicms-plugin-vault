# lokicms-plugin-vault

Secure credential vault plugin for LokiCMS. Store, encrypt, and manage sensitive credentials with audit logging, expiration, and access control.

## Key Security Features

- **AES-256-GCM Encryption**: All credentials are encrypted at rest
- **Value Isolation**: MCP tools NEVER expose actual credential values
- **Code-Only Access**: Only application code can retrieve decrypted values
- **Audit Logging**: Complete trail of all credential access and modifications
- **Expiration & Rotation**: Built-in TTL and rotation reminders

## Installation

```bash
npm install lokicms-plugin-vault
```

## Configuration

Add the vault plugin configuration to your LokiCMS config:

```typescript
{
  plugins: {
    vault: {
      // Master key for encryption (REQUIRED)
      // Option 1: Direct configuration (not recommended for production)
      masterKey: 'your-secure-master-key-min-16-chars',

      // Option 2: Environment variable (recommended)
      masterKeyEnvVar: 'VAULT_MASTER_KEY',

      // Optional settings
      defaultExpirationDays: 90,      // 0 = no expiration
      defaultRotationDays: 30,         // Rotation reminder
      enableAudit: true,               // Audit logging
      auditRetentionDays: 90           // Audit log retention
    }
  }
}
```

### Environment Variable (Recommended)

```bash
export VAULT_MASTER_KEY="your-secure-master-key-with-letters-and-numbers-123"
```

## MCP Tools (For Agents)

All MCP tools are designed for credential **management** - they NEVER expose actual values.

### vault_status

Get vault status and statistics.

```typescript
await callTool('vault_status', {});
// Returns: { hasMasterKey: true, stats: {...}, audit: {...} }
```

### vault_list

List credentials (metadata only).

```typescript
await callTool('vault_list', {
  project: 'my-app',
  environment: 'prod',
  category: 'api',
  status: 'active'
});
// Returns credentials with value: '••••••••••••' (always masked)
```

### vault_create

Create a new encrypted credential.

```typescript
await callTool('vault_create', {
  name: 'OPENAI_API_KEY',
  value: 'sk-abc123...',           // Will be encrypted
  project: 'my-app',
  environment: 'prod',
  description: 'OpenAI API Key',
  category: 'api',
  expirationDays: 90,
  rotateAfterDays: 30
});
// Returns: { success: true, credential: { id, name, value: '••••••••••••' } }
```

### vault_update

Update credential metadata (not the value).

```typescript
await callTool('vault_update', {
  id: 'cred_abc123',
  description: 'Updated description',
  expirationDays: 180,
  isActive: true
});
```

### vault_rotate

Rotate credential with a new value.

```typescript
await callTool('vault_rotate', {
  id: 'cred_abc123',
  newValue: 'new-secret-value'    // Will be encrypted
});
```

### vault_delete

Delete a credential permanently.

```typescript
await callTool('vault_delete', {
  id: 'cred_abc123',
  confirm: true
});
```

### vault_check_expiry

Check for expiring or rotation-needed credentials.

```typescript
await callTool('vault_check_expiry', {
  daysAhead: 7
});
// Returns: { expiring: [...], expired: [...], needsRotation: [...] }
```

### vault_audit

Query audit logs.

```typescript
await callTool('vault_audit', {
  credentialId: 'cred_abc123',
  action: 'access',
  limit: 50
});
```

### vault_projects

List all projects and environments.

```typescript
await callTool('vault_projects', {});
```

## Code Access (SecureAccessor)

The **only way** to access actual credential values is through the `SecureAccessor` in your application code.

### Basic Usage

```typescript
import { getSecureAccessor } from 'lokicms-plugin-vault';

const accessor = getSecureAccessor();

// Get a single credential
const apiKey = await accessor.get('OPENAI_API_KEY', {
  project: 'my-app',
  environment: 'prod',
  requesterId: 'my-service'
});
```

### Get Multiple Credentials

```typescript
const creds = await accessor.getMany(
  ['DB_HOST', 'DB_USER', 'DB_PASS'],
  { project: 'my-app', environment: 'prod' }
);

console.log(creds.DB_HOST);  // 'localhost'
console.log(creds.DB_USER);  // 'admin'
console.log(creds.DB_PASS);  // 'secret123'
```

### Inject into process.env

```typescript
// Inject credentials into environment
await accessor.inject(
  ['API_KEY', 'API_SECRET'],
  {
    project: 'my-app',
    environment: 'prod',
    prefix: 'MY_APP_',     // Results in MY_APP_API_KEY
    override: false         // Don't override existing
  }
);

// Use them
console.log(process.env.MY_APP_API_KEY);

// Clean up when done
await accessor.uninject(['API_KEY', 'API_SECRET'], 'MY_APP_');
```

### Scoped Accessor

```typescript
// Create a scoped accessor for repeated use
const prodAccessor = accessor.scope({
  project: 'my-app',
  environment: 'prod'
});

// Now you don't need to specify project/env each time
const key1 = await prodAccessor.get('API_KEY');
const key2 = await prodAccessor.get('SECRET');
```

### Check Credential Status

```typescript
const status = await accessor.getStatus('API_KEY', {
  project: 'my-app',
  environment: 'prod'
});

if (status.expired) {
  console.log('Credential has expired!');
}

if (status.rotationNeeded) {
  console.log('Credential needs rotation');
}
```

## Security Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    MCP Tools (Agent)                         │
│         ❌ CANNOT access actual credential values            │
│                                                              │
│   vault_list → returns { value: '••••••••••••' }            │
│   vault_create → encrypts and stores                        │
│   vault_audit → returns access history                      │
└──────────────────────────┬──────────────────────────────────┘
                           │ Management only
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    Credential Vault                          │
│  ┌───────────────────────────────────────────────────────┐  │
│  │           Encrypted Storage (AES-256-GCM)              │  │
│  │                                                        │  │
│  │   { name, encryptedValue, iv, authTag, project... }   │  │
│  └───────────────────────────────────────────────────────┘  │
└──────────────────────────┬──────────────────────────────────┘
                           │ Decryption only via SecureAccessor
                           ▼
┌─────────────────────────────────────────────────────────────┐
│               SecureAccessor (Code Only)                     │
│         ✅ CAN access actual credential values               │
│                                                              │
│   accessor.get('API_KEY') → 'sk-abc123...'                  │
│   accessor.inject(['KEY']) → process.env.KEY                │
└─────────────────────────────────────────────────────────────┘
```

## Credential Categories

| Category | Description |
|----------|-------------|
| `database` | Database credentials |
| `api` | API keys and tokens |
| `service` | Service account credentials |
| `oauth` | OAuth tokens and secrets |
| `certificate` | SSL/TLS certificates |
| `ssh` | SSH keys |
| `encryption` | Encryption keys |
| `other` | Other credentials |

## Credential Status

| Status | Description |
|--------|-------------|
| `active` | Credential is valid and usable |
| `expired` | Credential has passed expiration date |
| `expiring_soon` | Expires within 7 days |
| `rotation_needed` | Past rotation reminder date |
| `inactive` | Manually deactivated |

## Audit Actions

| Action | Description |
|--------|-------------|
| `create` | Credential created |
| `update` | Metadata updated |
| `rotate` | Value rotated |
| `delete` | Credential deleted |
| `access` | Value retrieved (code) |
| `inject` | Value injected to env |
| `permission_change` | Permissions modified |

## TypeScript

```typescript
import type {
  VaultPluginConfig,
  Credential,
  CredentialView,
  CredentialStatus,
  CreateCredentialInput,
  SecureAccessorOptions,
  AuditEntry,
} from 'lokicms-plugin-vault';

import {
  getSecureAccessor,
  generateSecureKey,
  CREDENTIAL_CATEGORIES,
} from 'lokicms-plugin-vault';
```

## Best Practices

### Master Key Management

1. **Never hardcode** the master key in source code
2. **Use environment variables** for the master key
3. **Rotate the master key** periodically (requires re-encrypting all credentials)
4. **Back up the master key** securely - without it, credentials are irrecoverable

### Credential Lifecycle

1. **Set expiration dates** for all credentials
2. **Enable rotation reminders** for long-lived credentials
3. **Use categories** to organize credentials
4. **Review audit logs** regularly

### Access Control

1. **Use scoped accessors** for specific projects/environments
2. **Clean up** injected environment variables when done
3. **Minimize** the scope of credential access

## License

MIT
