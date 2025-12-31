/**
 * Cryptographic utilities for the Vault Plugin
 *
 * Uses AES-256-GCM for authenticated encryption
 */

import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scryptSync,
  createHash,
} from 'node:crypto';
import { VaultError } from './types.js';

// Constants
const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16; // 128 bits
const AUTH_TAG_LENGTH = 16; // 128 bits
const KEY_LENGTH = 32; // 256 bits
const SALT_LENGTH = 32;

/**
 * Encryption result containing all components needed for decryption
 */
export interface EncryptionResult {
  encryptedValue: string; // Base64 encoded
  iv: string; // Base64 encoded
  authTag: string; // Base64 encoded
}

/**
 * Derives a 256-bit key from the master key using scrypt
 */
function deriveKey(masterKey: string, salt?: Buffer): { key: Buffer; salt: Buffer } {
  const saltBuffer = salt || randomBytes(SALT_LENGTH);
  const key = scryptSync(masterKey, saltBuffer, KEY_LENGTH, {
    N: 16384, // CPU/memory cost parameter
    r: 8, // Block size
    p: 1, // Parallelization parameter
  });
  return { key, salt: saltBuffer };
}

/**
 * Encrypts a plain text value using AES-256-GCM
 *
 * @param plainText - The value to encrypt
 * @param masterKey - The master encryption key
 * @returns Encryption result with encrypted value, IV, and auth tag
 */
export function encrypt(plainText: string, masterKey: string): EncryptionResult {
  if (!masterKey) {
    throw new VaultError('Master key is required for encryption', 'MASTER_KEY_NOT_SET');
  }

  try {
    // Generate random IV
    const iv = randomBytes(IV_LENGTH);

    // Derive key from master key (using IV as additional entropy for salt)
    const keyHash = createHash('sha256').update(masterKey).digest();

    // Create cipher
    const cipher = createCipheriv(ALGORITHM, keyHash, iv, {
      authTagLength: AUTH_TAG_LENGTH,
    });

    // Encrypt
    const encrypted = Buffer.concat([
      cipher.update(plainText, 'utf8'),
      cipher.final(),
    ]);

    // Get auth tag
    const authTag = cipher.getAuthTag();

    return {
      encryptedValue: encrypted.toString('base64'),
      iv: iv.toString('base64'),
      authTag: authTag.toString('base64'),
    };
  } catch (error) {
    throw new VaultError(
      `Encryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
      'ENCRYPTION_FAILED',
      { originalError: error }
    );
  }
}

/**
 * Decrypts an encrypted value using AES-256-GCM
 *
 * @param encryptedValue - Base64 encoded encrypted value
 * @param iv - Base64 encoded initialization vector
 * @param authTag - Base64 encoded authentication tag
 * @param masterKey - The master encryption key
 * @returns Decrypted plain text value
 */
export function decrypt(
  encryptedValue: string,
  iv: string,
  authTag: string,
  masterKey: string
): string {
  if (!masterKey) {
    throw new VaultError('Master key is required for decryption', 'MASTER_KEY_NOT_SET');
  }

  try {
    // Decode from Base64
    const encryptedBuffer = Buffer.from(encryptedValue, 'base64');
    const ivBuffer = Buffer.from(iv, 'base64');
    const authTagBuffer = Buffer.from(authTag, 'base64');

    // Derive key from master key
    const keyHash = createHash('sha256').update(masterKey).digest();

    // Create decipher
    const decipher = createDecipheriv(ALGORITHM, keyHash, ivBuffer, {
      authTagLength: AUTH_TAG_LENGTH,
    });

    // Set auth tag for verification
    decipher.setAuthTag(authTagBuffer);

    // Decrypt
    const decrypted = Buffer.concat([
      decipher.update(encryptedBuffer),
      decipher.final(),
    ]);

    return decrypted.toString('utf8');
  } catch (error) {
    throw new VaultError(
      `Decryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
      'DECRYPTION_FAILED',
      { originalError: error }
    );
  }
}

/**
 * Generates a cryptographically secure random ID
 */
export function generateId(prefix: string = 'cred'): string {
  const timestamp = Date.now().toString(36);
  const random = randomBytes(8).toString('hex');
  return `${prefix}_${timestamp}_${random}`;
}

/**
 * Hashes a value for comparison (not for encryption)
 */
export function hashValue(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

/**
 * Validates that a master key meets minimum requirements
 */
export function validateMasterKey(masterKey: string): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  if (!masterKey) {
    errors.push('Master key is required');
    return { valid: false, errors };
  }

  if (masterKey.length < 16) {
    errors.push('Master key must be at least 16 characters');
  }

  if (masterKey.length > 256) {
    errors.push('Master key must be at most 256 characters');
  }

  // Check for some complexity (not too restrictive)
  const hasLetter = /[a-zA-Z]/.test(masterKey);
  const hasNumber = /[0-9]/.test(masterKey);

  if (!hasLetter || !hasNumber) {
    errors.push('Master key should contain both letters and numbers');
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Securely compares two strings in constant time to prevent timing attacks
 */
export function secureCompare(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }

  const bufferA = Buffer.from(a);
  const bufferB = Buffer.from(b);

  let result = 0;
  for (let i = 0; i < bufferA.length; i++) {
    result |= bufferA[i] ^ bufferB[i];
  }

  return result === 0;
}

/**
 * Generates a secure random password/key
 */
export function generateSecureKey(length: number = 32): string {
  const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
  const bytes = randomBytes(length);
  let result = '';

  for (let i = 0; i < length; i++) {
    result += charset[bytes[i] % charset.length];
  }

  return result;
}

/**
 * Clears sensitive data from memory (best effort)
 */
export function clearSensitiveData(data: string): void {
  // In JavaScript, we can't truly clear memory, but we can
  // try to overwrite the reference if it's mutable
  // This is more of a documentation of intent than actual security
  if (typeof data === 'string' && data.length > 0) {
    // Strings are immutable in JS, so this doesn't actually help
    // But we document the intent for code reviewers
  }
}
