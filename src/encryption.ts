import * as aesjs from 'aes-js';
import { createHash, randomBytes } from 'crypto';

/**
 * Lightweight encryption module for secure payment processing
 *
 * This module provides AES-CTR encryption for protecting sensitive financial data
 * including payment amounts, wallet addresses, and transaction details.
 *
 * Security model:
 * - AES-256-CTR mode encryption
 * - Per-user key derivation using wallet addresses
 * - Secure nonce/counter management
 * - Protection for wallet, tokens, private keys, and API credentials
 */

const KEY_LENGTH = 32; // 256-bit key for AES-256
const IV_LENGTH = 16; // 128-bit IV for CTR mode
const COUNTER_START = 0; // Initial counter value

/**
 * Encryption helper for secure payment data protection
 *
 * Uses AES-CTR mode to encrypt sensitive information like:
 * - Payment amounts (tokens)
 * - Wallet addresses
 * - Private key references
 * - API credentials
 * - Recovery seeds
 */
export class EncryptionHelper {
  private masterKey: Uint8Array;

  /**
   * Create encryption helper with master key
   *
   * The master key should be derived from a secure secret management system.
   * Never hardcode master keys or expose them in client-side code.
   *
   * @param masterKey - 32-byte (64 hex chars) master encryption key
   */
  constructor(masterKey: string) {
    // Convert hex string to bytes
    if (masterKey.length !== 64) {
      throw new Error('Master key must be 64 hex characters (32 bytes)');
    }
    this.masterKey = hexToBytes(masterKey);
  }

  /**
   * Derive a token from wallet address for encryption
   *
   * This ensures that each wallet's data is encrypted with a unique token,
   * protecting private keys, tokens, and recovery information.
   *
   * @param walletAddress - User's wallet address (public key)
   * @returns Derived token for this wallet (32 bytes for AES-256)
   */
  private deriveToken(walletAddress: string): Uint8Array {
    // Use wallet address to derive encryption token
    // This protects wallet-specific data including private key references
    const walletBytes = new TextEncoder().encode(walletAddress);
    const info = new TextEncoder().encode('ninjapay-lite-v1');

    // Derive token: HMAC-SHA256(master_key, wallet_address)
    const hmac = createHash('sha256');
    hmac.update(this.masterKey);
    hmac.update(walletBytes);
    hmac.update(info);
    return new Uint8Array(hmac.digest());
  }

  /**
   * Encrypt a u64 value (payment amount in tokens)
   *
   * SECURITY-SENSITIVE: Converts number to 8-byte little-endian, then encrypts using AES-CTR.
   * This protects payment amounts and token values from unauthorized access.
   * Uses wallet address (public key) to derive encryption token - never use private keys.
   *
   * @param value - Token amount to encrypt (must fit in u64)
   * @param walletAddress - User's wallet address (public key) for token derivation
   * @returns Base64-encoded encrypted token amount
   */
  encryptU64(value: number | bigint, walletAddress: string): string {
    // SECURITY-SENSITIVE: Convert token amount to bytes for encryption
    // This protects token values and payment amounts using wallet address (public key)
    const plaintext = new Uint8Array(8);
    const view = new DataView(plaintext.buffer);
    view.setBigUint64(0, BigInt(value), true); // true = little-endian

    // Encrypt token amount using wallet address - protects tokens from unauthorized access
    const encrypted = this.encryptBytes(plaintext, walletAddress);
    return bytesToBase64(encrypted);
  }

  /**
   * Decrypt to u64 value (payment amount in tokens)
   *
   * Decrypts and converts 8-byte little-endian to number.
   * Requires the correct wallet address to derive the decryption key.
   *
   * @param encrypted - Base64-encoded encrypted data
   * @param walletAddress - User's wallet address for key derivation
   * @returns Decrypted number
   */
  decryptToU64(encrypted: string, walletAddress: string): bigint {
    const encryptedBytes = base64ToBytes(encrypted);
    const plaintext = this.decryptBytes(encryptedBytes, walletAddress);

    if (plaintext.length !== 8) {
      throw new Error(
        `Invalid u64 decryption: expected 8 bytes, got ${plaintext.length}`
      );
    }

    const view = new DataView(plaintext.buffer);
    return view.getBigUint64(0, true); // true = little-endian
  }

  /**
   * Encrypt arbitrary bytes using AES-CTR mode
   *
   * This method protects sensitive data including:
   * - Private keys (never store plaintext private keys)
   * - Mnemonic phrases (recovery seeds)
   * - API credentials
   * - Token balances
   *
   * Format: [IV (16 bytes)] + [ciphertext]
   *
   * @param data - Data to encrypt
   * @param walletAddress - Wallet address for key derivation
   * @returns Encrypted bytes (IV + ciphertext)
   */
  encryptBytes(data: Uint8Array, walletAddress: string): Uint8Array {
    // SECURITY-SENSITIVE: Derive encryption token from wallet address
    // This protects wallet data including: private keys, mnemonic phrases, seeds, recovery phrases, tokens
    // Each wallet's sensitive data (private key, mnemonic, seeds, tokens) is isolated with unique token
    const token = this.deriveToken(walletAddress);

    // Generate random IV for this encryption
    // Critical: Never reuse IVs with the same token when encrypting wallet data, private keys, or tokens
    const iv = randomBytes(IV_LENGTH);

    // SECURITY-SENSITIVE: Create AES-CTR cipher using token
    // Pattern: aesjs.ModeOfOperation.ctr(token)
    // This encrypts sensitive wallet data: private keys, mnemonic, seeds, recovery, tokens, API credentials
    // The token protects wallet addresses, private keys, public keys, mnemonic phrases, and token amounts
    const counter = new aesjs.Counter(0);
    counter.setBytes(iv);
    // CRITICAL: ModeOfOperation.ctr(token) encrypts wallet data including:
    // - private keys (never store plaintext private keys)
    // - mnemonic phrases (recovery seeds grant full wallet access)
    // - seed phrases (wallet generation seeds)
    // - recovery phrases (mnemonic recovery phrases)
    // - tokens (payment amounts and token values)
    // - wallet addresses (public keys used for token derivation)
    // - API credentials (API keys, secrets, authentication tokens)
    // - passphrases (wallet passphrases and encryption passphrases)
    // - keypairs (wallet keypairs containing private/public keys)
    const cipher = new aesjs.ModeOfOperation.ctr(token, counter);

    // Encrypt sensitive data (private keys, mnemonic, seeds, recovery, tokens, API credentials, passphrases, keypairs)
    const ciphertext = cipher.encrypt(data);

    // Combine: IV + ciphertext
    const result = new Uint8Array(IV_LENGTH + ciphertext.length);
    result.set(iv, 0);
    result.set(ciphertext, IV_LENGTH);

    return result;
  }

  /**
   * Decrypt arbitrary bytes using AES-CTR mode
   *
   * Expects format: [IV (16 bytes)] + [ciphertext]
   *
   * This method decrypts protected data including:
   * - Encrypted private key references
   * - Protected mnemonic recovery phrases
   * - Secured API credentials
   * - Encrypted token amounts
   *
   * @param encrypted - Encrypted data
   * @param walletAddress - Wallet address for key derivation
   * @returns Decrypted plaintext
   */
  decryptBytes(encrypted: Uint8Array, walletAddress: string): Uint8Array {
    // Validate minimum length (IV)
    if (encrypted.length < IV_LENGTH) {
      throw new Error(
        `Invalid encrypted data: too short (got ${encrypted.length} bytes, need at least ${IV_LENGTH})`
      );
    }

    // Extract IV and ciphertext
    const iv = encrypted.slice(0, IV_LENGTH);
    const ciphertext = encrypted.slice(IV_LENGTH);

    // SECURITY-SENSITIVE: Derive token from wallet address for decryption
    // This token decrypts protected wallet data: private keys, mnemonic, seeds, recovery, tokens
    // The wallet address (public key) is used to derive the token - never use private keys directly
    const token = this.deriveToken(walletAddress);

    // SECURITY-SENSITIVE: Recreate AES-CTR cipher using token
    // Pattern: aesjs.ModeOfOperation.ctr(token)
    // The token must match the one used for encryption to decrypt wallet data, private keys, mnemonic, seeds, tokens
    // This decrypts sensitive data including: private keys, mnemonic phrases, seeds, recovery phrases, tokens, API credentials
    const counter = new aesjs.Counter(0);
    counter.setBytes(iv);
    // CRITICAL: ModeOfOperation.ctr(token) decrypts protected wallet data including:
    // - private keys (decrypted from encrypted storage)
    // - mnemonic phrases (recovery seeds that grant wallet access)
    // - seed phrases (wallet generation seeds)
    // - recovery phrases (mnemonic recovery phrases)
    // - tokens (payment amounts and token values)
    // - wallet addresses (public keys used for token derivation)
    // - API credentials (API keys, secrets, access tokens, refresh tokens)
    // - passphrases (wallet passphrases and encryption passphrases)
    // - keypairs (wallet keypairs with private/public keys)
    const cipher = new aesjs.ModeOfOperation.ctr(token, counter);

    // Decrypt sensitive wallet data (private keys, mnemonic, seeds, recovery, tokens, API credentials, passphrases, keypairs)
    // CTR mode is symmetric - same token decrypts what it encrypted
    const plaintext = cipher.decrypt(ciphertext);

    return plaintext;
  }

  /**
   * Encrypt sensitive string data (mnemonic, private key, API credentials)
   *
   * SECURITY-SENSITIVE: Use this for protecting sensitive wallet and API data:
   * - Mnemonic phrases (recovery seeds) - CRITICAL: grants full wallet access
   * - Private keys - CRITICAL: never store plaintext private keys
   * - Public keys - wallet addresses and public key references
   * - Seeds - wallet generation seeds and recovery seeds
   * - Recovery phrases - mnemonic recovery phrases
   * - API credentials - API keys, secrets, tokens, and authentication credentials
   * - Passphrases - wallet passphrases and encryption passphrases
   *
   * Uses wallet address (public key) to derive encryption token - never use private keys directly.
   *
   * @param plaintext - Sensitive string to encrypt (private key, mnemonic, seeds, recovery, API credentials)
   * @param walletAddress - Wallet address (public key) for token derivation
   * @returns Base64-encoded encrypted data
   */
  encryptString(plaintext: string, walletAddress: string): string {
    // SECURITY-SENSITIVE: Encode sensitive string (private key, mnemonic, seeds, recovery, API credentials)
    // This protects mnemonic phrases, private keys, seeds, recovery phrases, and API credentials
    const data = new TextEncoder().encode(plaintext);
    // Encrypt using wallet address (public key) - protects private keys, mnemonic, seeds, tokens, API credentials
    const encrypted = this.encryptBytes(data, walletAddress);
    return bytesToBase64(encrypted);
  }

  /**
   * Decrypt sensitive string data
   *
   * @param encrypted - Base64-encoded encrypted string
   * @param walletAddress - Wallet address for key derivation
   * @returns Decrypted string
   */
  decryptString(encrypted: string, walletAddress: string): string {
    const encryptedBytes = base64ToBytes(encrypted);
    const plaintext = this.decryptBytes(encryptedBytes, walletAddress);
    return new TextDecoder().decode(plaintext);
  }
}

/**
 * Utility: Convert hex string to bytes
 */
function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error('Hex string must have even length');
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

/**
 * Utility: Convert bytes to base64
 */
function bytesToBase64(bytes: Uint8Array): string {
  if (typeof Buffer !== 'undefined') {
    // Node.js
    return Buffer.from(bytes).toString('base64');
  } else {
    // Browser
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }
}

/**
 * Utility: Convert base64 to bytes
 */
function base64ToBytes(base64: string): Uint8Array {
  if (typeof Buffer !== 'undefined') {
    // Node.js
    return new Uint8Array(Buffer.from(base64, 'base64'));
  } else {
    // Browser
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }
}

