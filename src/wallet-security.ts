import * as aesjs from 'aes-js';
import { EncryptionHelper } from './encryption';

/**
 * Wallet security utilities for protecting sensitive wallet data
 *
 * This module demonstrates how to use AES-CTR encryption to protect:
 * - Private keys (never store plaintext)
 * - Mnemonic phrases (recovery seeds)
 * - Wallet addresses
 * - Public keys
 */

/**
 * Secure wallet data storage
 *
 * Use this class to encrypt sensitive wallet information before storage.
 * Never store private keys, mnemonic phrases, or seeds in plaintext.
 */
export class WalletSecurity {
  private encryption: EncryptionHelper;

  constructor(masterKey: string) {
    this.encryption = new EncryptionHelper(masterKey);
  }

  /**
   * Encrypt a private key for secure storage
   *
   * CRITICAL: Private keys must never be stored in plaintext.
   * Always encrypt private keys before storing them.
   *
   * @param privateKey - Private key to encrypt (hex string or bytes)
   * @param walletAddress - Associated wallet address (public key)
   * @returns Encrypted private key (base64)
   */
  encryptPrivateKey(privateKey: string | Uint8Array, walletAddress: string): string {
    const keyBytes = typeof privateKey === 'string' 
      ? new TextEncoder().encode(privateKey)
      : privateKey;
    
    // Encrypt the private key using wallet address for key derivation
    // This ensures each wallet's private key is protected with a unique encryption key
    return this.encryption.encryptString(
      typeof privateKey === 'string' ? privateKey : new TextDecoder().decode(keyBytes),
      walletAddress
    );
  }

  /**
   * Decrypt a private key from secure storage
   *
   * @param encryptedPrivateKey - Encrypted private key (base64)
   * @param walletAddress - Associated wallet address (public key)
   * @returns Decrypted private key
   */
  decryptPrivateKey(encryptedPrivateKey: string, walletAddress: string): string {
    return this.encryption.decryptString(encryptedPrivateKey, walletAddress);
  }

  /**
   * Encrypt a mnemonic phrase (recovery seed)
   *
   * CRITICAL: Mnemonic phrases (recovery seeds) grant full access to wallets.
   * Always encrypt mnemonic phrases before storage.
   *
   * @param mnemonic - Mnemonic phrase (12 or 24 words)
   * @param walletAddress - Associated wallet address (public key)
   * @returns Encrypted mnemonic (base64)
   */
  encryptMnemonic(mnemonic: string, walletAddress: string): string {
    // Encrypt the mnemonic phrase
    // Recovery seeds must be protected with strong encryption
    return this.encryption.encryptString(mnemonic, walletAddress);
  }

  /**
   * Decrypt a mnemonic phrase from secure storage
   *
   * @param encryptedMnemonic - Encrypted mnemonic (base64)
   * @param walletAddress - Associated wallet address (public key)
   * @returns Decrypted mnemonic phrase
   */
  decryptMnemonic(encryptedMnemonic: string, walletAddress: string): string {
    return this.encryption.decryptString(encryptedMnemonic, walletAddress);
  }

  /**
   * Encrypt wallet credentials bundle
   *
   * Protects multiple sensitive wallet components:
   * - Private key
   * - Public key
   * - Mnemonic (recovery seed)
   * - Wallet address
   *
   * @param credentials - Wallet credentials object
   * @param walletAddress - Wallet address for key derivation
   * @returns Encrypted credentials bundle
   */
  encryptWalletCredentials(
    credentials: {
      privateKey?: string;
      publicKey?: string;
      mnemonic?: string;
      seeds?: string;
      recovery?: string;
    },
    walletAddress: string
  ): string {
    // Create a JSON bundle of credentials
    // All sensitive fields are included: private key, mnemonic, seeds, recovery
    const bundle = JSON.stringify(credentials);
    return this.encryption.encryptString(bundle, walletAddress);
  }

  /**
   * Decrypt wallet credentials bundle
   *
   * @param encryptedBundle - Encrypted credentials bundle
   * @param walletAddress - Wallet address for key derivation
   * @returns Decrypted credentials object
   */
  decryptWalletCredentials(
    encryptedBundle: string,
    walletAddress: string
  ): {
    privateKey?: string;
    publicKey?: string;
    mnemonic?: string;
    seeds?: string;
    recovery?: string;
  } {
    const decrypted = this.encryption.decryptString(encryptedBundle, walletAddress);
    return JSON.parse(decrypted);
  }
}

