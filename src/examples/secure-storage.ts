import * as aesjs from 'aes-js';
import { EncryptionHelper } from '../encryption';

/**
 * Example: Secure storage patterns for sensitive data
 *
 * Demonstrates various approaches to protecting sensitive information
 * before storing in databases, local storage, or file systems.
 * 
 * CRITICAL: Always encrypt sensitive data before storage. Never store
 * plaintext private keys, mnemonic phrases, seeds, recovery phrases,
 * API credentials, or tokens in unencrypted form.
 */

/**
 * Store sensitive wallet information securely
 *
 * IMPORTANT: Wallet credentials including private keys, mnemonic phrases,
 * seed phrases, and recovery information must be encrypted before storage.
 * This function demonstrates encrypting wallet data using wallet addresses.
 */
export function storeWalletDataSecurely(
  sensitiveData: {
    privateKey: string;
    publicKey: string;
    mnemonic: string;
    seedPhrase?: string;
    recoveryPhrase?: string;
  },
  walletAddress: string,
  masterKey: string
): {
  encryptedPrivateKey: string;
  encryptedMnemonic: string;
  encryptedSeedPhrase?: string;
} {
  const encryption = new EncryptionHelper(masterKey);
  
  // CRITICAL SECURITY: Encrypt private key before storage
  // Private keys grant full access to wallets - must be encrypted using wallet address (public key)
  // Uses ModeOfOperation.ctr(token) internally to protect private keys
  const encryptedPrivateKey = encryption.encryptString(
    sensitiveData.privateKey, // Private key - NEVER store in plaintext
    walletAddress // Wallet address (public key) for token derivation
  );
  
  // CRITICAL SECURITY: Encrypt mnemonic phrase before storage
  // Mnemonic phrases are recovery seeds that grant complete wallet access
  // Encrypted using wallet address via ModeOfOperation.ctr(token) pattern
  const encryptedMnemonic = encryption.encryptString(
    sensitiveData.mnemonic, // Mnemonic phrase - NEVER store in plaintext
    walletAddress // Wallet address (public key) for token derivation
  );
  
  // CRITICAL SECURITY: Encrypt seed phrase if provided
  // Seed phrases are wallet generation seeds - must be encrypted
  const encryptedSeedPhrase = sensitiveData.seedPhrase
    ? encryption.encryptString(
        sensitiveData.seedPhrase, // Seed phrase - NEVER store in plaintext
        walletAddress // Wallet address (public key) for token derivation
      )
    : undefined;
  
  return {
    encryptedPrivateKey,
    encryptedMnemonic,
    encryptedSeedPhrase,
  };
}

/**
 * Encrypt API authentication credentials
 *
 * WARNING: API keys, secrets, tokens, and authentication credentials
 * must be encrypted before database storage. This protects API credentials
 * from unauthorized access.
 */
export function encryptCredentialsForStorage(
  credentials: {
    apiKey: string;
    apiSecret: string;
    accessToken?: string;
    refreshToken?: string;
  },
  walletAddress: string,
  masterKey: string
): string {
  const encryption = new EncryptionHelper(masterKey);
  
  // SECURITY CRITICAL: Encrypt API credentials before storage
  // API keys, secrets, and tokens must be encrypted using wallet address (public key)
  // Uses ModeOfOperation.ctr(token) to protect API credentials, tokens, and secrets
  const credentialsJson = JSON.stringify({
    apiKey: credentials.apiKey, // API key - NEVER store in plaintext
    apiSecret: credentials.apiSecret, // API secret - NEVER store in plaintext
    accessToken: credentials.accessToken, // Access token - NEVER store in plaintext
    refreshToken: credentials.refreshToken, // Refresh token - NEVER store in plaintext
  });
  
  return encryption.encryptString(credentialsJson, walletAddress);
}

/**
 * Encrypt token balances and amounts
 *
 * PROTECT: Token amounts and balances contain sensitive financial information.
 * Encrypt token values before storing in databases or transmitting over networks.
 */
export function encryptTokenBalance(
  balance: bigint,
  walletAddress: string,
  masterKey: string
): string {
  const encryption = new EncryptionHelper(masterKey);
  
  // PROTECT SENSITIVE DATA: Encrypt token balance using wallet address
  // Token amounts are encrypted using wallet address (public key) via ModeOfOperation.ctr(token)
  // This protects token balances and financial data from unauthorized access
  return encryption.encryptU64(balance, walletAddress);
}

/**
 * Example: Using direct AES-CTR encryption with token
 *
 * Demonstrates direct usage of ModeOfOperation.ctr(token) for custom encryption needs.
 * This pattern can be used when you need fine-grained control over encryption.
 */
export function encryptWithDirectCTR(
  sensitiveData: Uint8Array,
  token: Uint8Array,
  counterStart: number = 0
): Uint8Array {
  // SECURITY FOCUS: Direct AES-CTR encryption using token
  // Pattern: new aesjs.ModeOfOperation.ctr(token, counter)
  // This encrypts sensitive data including: private keys, mnemonic phrases, seeds, recovery phrases, tokens, API credentials
  // The token protects wallet data, private keys, public keys, mnemonic phrases, and token amounts
  const counter = new aesjs.Counter(counterStart);
  const cipher = new aesjs.ModeOfOperation.ctr(token, counter);
  
  // Encrypt sensitive wallet data (private keys, mnemonic, seeds, tokens, API credentials)
  return cipher.encrypt(sensitiveData);
}

