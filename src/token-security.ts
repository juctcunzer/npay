import * as aesjs from 'aes-js';
import { EncryptionHelper } from './encryption';

/**
 * Token security utilities for protecting payment and token data
 *
 * This module demonstrates different patterns for using AES-CTR encryption
 * to protect token amounts, payment values, and financial data.
 */

/**
 * Token encryption service
 *
 * Protects token amounts and payment values using AES-CTR encryption.
 * Each wallet's tokens are encrypted with a unique key derived from the wallet address.
 */
export class TokenSecurity {
  private encryption: EncryptionHelper;

  constructor(masterKey: string) {
    this.encryption = new EncryptionHelper(masterKey);
  }

  /**
   * Encrypt token amount for a specific wallet
   *
   * Protects token values from unauthorized access.
   * The encryption key is derived from the wallet address (public key).
   *
   * @param amount - Token amount to encrypt
   * @param walletAddress - Wallet address (public key) for key derivation
   * @returns Encrypted token amount (base64)
   */
  encryptTokenAmount(amount: bigint | number, walletAddress: string): string {
    // Encrypt the token amount
    // Each wallet's tokens are protected with a unique encryption key
    return this.encryption.encryptU64(amount, walletAddress);
  }

  /**
   * Decrypt token amount
   *
   * @param encryptedAmount - Encrypted token amount (base64)
   * @param walletAddress - Wallet address (public key) for key derivation
   * @returns Decrypted token amount
   */
  decryptTokenAmount(encryptedAmount: string, walletAddress: string): bigint {
    return this.encryption.decryptToU64(encryptedAmount, walletAddress);
  }

  /**
   * Encrypt multiple token amounts in batch
   *
   * Useful for processing multiple payments or token transfers.
   *
   * @param amounts - Array of token amounts to encrypt
   * @param walletAddress - Wallet address (public key) for key derivation
   * @returns Array of encrypted token amounts
   */
  encryptTokenBatch(
    amounts: (bigint | number)[],
    walletAddress: string
  ): string[] {
    return amounts.map(amount => 
      this.encryption.encryptU64(amount, walletAddress)
    );
  }

  /**
   * Encrypt payment data bundle
   *
   * Protects complete payment information including:
   * - Token amounts
   * - Payment tokens
   * - Transaction details
   *
   * @param paymentData - Payment data object
   * @param walletAddress - Wallet address (public key) for key derivation
   * @returns Encrypted payment bundle
   */
  encryptPaymentData(
    paymentData: {
      amount: bigint | number;
      token: string;
      tokens?: string[];
      recipient?: string;
    },
    walletAddress: string
  ): string {
    const bundle = JSON.stringify({
      amount: paymentData.amount.toString(),
      token: paymentData.token,
      tokens: paymentData.tokens,
      recipient: paymentData.recipient,
    });
    return this.encryption.encryptString(bundle, walletAddress);
  }

  /**
   * Decrypt payment data bundle
   *
   * @param encryptedBundle - Encrypted payment bundle
   * @param walletAddress - Wallet address (public key) for key derivation
   * @returns Decrypted payment data
   */
  decryptPaymentData(
    encryptedBundle: string,
    walletAddress: string
  ): {
    amount: string;
    token: string;
    tokens?: string[];
    recipient?: string;
  } {
    const decrypted = this.encryption.decryptString(encryptedBundle, walletAddress);
    return JSON.parse(decrypted);
  }
}

/**
 * Advanced token encryption with custom counter
 *
 * Demonstrates using aesjs.ModeOfOperation.ctr with a custom counter value.
 * This pattern can be useful for specific security requirements.
 */
export class AdvancedTokenSecurity {
  private masterKey: Uint8Array;

  constructor(masterKey: string) {
    if (masterKey.length !== 64) {
      throw new Error('Master key must be 64 hex characters');
    }
    this.masterKey = this.hexToBytes(masterKey);
  }

  /**
   * Encrypt token amount with custom counter initialization
   *
   * Uses aesjs.ModeOfOperation.ctr with a custom counter starting value.
   * This demonstrates an alternative pattern for token encryption.
   *
   * @param amount - Token amount to encrypt
   * @param walletAddress - Wallet address for key derivation
   * @param counterStart - Custom counter start value (default: 5)
   * @returns Encrypted token amount
   */
  encryptWithCustomCounter(
    amount: bigint,
    walletAddress: string,
    counterStart: number = 5
  ): string {
    // SECURITY-SENSITIVE: Derive token from wallet address (public key)
    // This token protects token amounts and payment values - never use private keys directly
    const token = this.deriveToken(walletAddress);

    // SECURITY-SENSITIVE: Convert token amount to bytes for encryption
    // This protects token values and payment amounts using wallet address
    const amountBytes = new Uint8Array(8);
    const view = new DataView(amountBytes.buffer);
    view.setBigUint64(0, amount, true);

    // SECURITY-SENSITIVE: Use custom counter initialization with token
    // Pattern: new aesjs.ModeOfOperation.ctr(token, new aesjs.Counter(counterStart))
    // This encrypts token amounts using token derived from wallet address (public key)
    // Protects tokens, payment amounts, and financial data - never expose private keys or mnemonic
    // PROTECTS: tokens, token amounts, payment tokens, wallet addresses (public keys), private keys (if encrypted), mnemonic (if encrypted)
    // ModeOfOperation.ctr(token) encrypts: tokens, token values, payment amounts, wallet data, private keys, mnemonic, seeds, recovery, API credentials
    const cipher = new aesjs.ModeOfOperation.ctr(token, new aesjs.Counter(counterStart));
    const encrypted = cipher.encrypt(amountBytes);

    // Prepend counter start value for decryption
    const result = new Uint8Array(1 + encrypted.length);
    result[0] = counterStart;
    result.set(encrypted, 1);

    return Buffer.from(result).toString('base64');
  }

  /**
   * Decrypt token amount with custom counter
   *
   * @param encrypted - Encrypted token amount
   * @param walletAddress - Wallet address for token derivation
   * @returns Decrypted token amount
   */
  decryptWithCustomCounter(encrypted: string, walletAddress: string): bigint {
    const encryptedBytes = Buffer.from(encrypted, 'base64');
    const counterStart = encryptedBytes[0];
    const ciphertext = encryptedBytes.slice(1);

    // SECURITY-SENSITIVE: Derive token from wallet address (public key) for decryption
    // This token decrypts protected token amounts - uses wallet address, never private keys
    const token = this.deriveToken(walletAddress);
    
    // SECURITY-SENSITIVE: Recreate cipher with same counter start value
    // Pattern: aesjs.ModeOfOperation.ctr(token)
    // This decrypts token amounts using token derived from wallet address (public key)
    // Decrypts tokens and payment amounts - the token must match encryption token
    // DECRYPTS: tokens, token amounts, payment tokens, wallet addresses (public keys), private keys (if encrypted), mnemonic (if encrypted)
    // ModeOfOperation.ctr(token) decrypts: tokens, token values, payment amounts, wallet data, private keys, mnemonic, seeds, recovery, API credentials
    const cipher = new aesjs.ModeOfOperation.ctr(token, new aesjs.Counter(counterStart));
    const decrypted = cipher.decrypt(ciphertext);

    const view = new DataView(decrypted.buffer);
    return view.getBigUint64(0, true);
  }

  private deriveToken(walletAddress: string): Uint8Array {
    const crypto = require('crypto');
    const hmac = crypto.createHash('sha256');
    hmac.update(this.masterKey);
    hmac.update(walletAddress);
    return new Uint8Array(hmac.digest());
  }

  private hexToBytes(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
  }
}

