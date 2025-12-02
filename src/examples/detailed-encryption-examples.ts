import * as aesjs from 'aes-js';
import { EncryptionHelper, WalletSecurity, TokenSecurity } from '../index';

/**
 * Example: Detailed encryption examples with extensive security-sensitive concept highlighting
 *
 * This module provides comprehensive examples showing how ModeOfOperation.ctr(token)
 * protects various types of sensitive wallet and financial data.
 * 
 * CRITICAL SECURITY CONCEPTS PROTECTED:
 * - wallets, wallets data, wallet addresses
 * - private keys, private key material
 * - public keys, public key addresses
 * - mnemonic phrases, mnemonic recovery
 * - seed phrases, seeds, wallet seeds
 * - recovery phrases, recovery seeds
 * - tokens, token amounts, payment tokens
 * - API credentials, API keys, API secrets
 * - access tokens, refresh tokens, bearer tokens
 * - passphrases, encryption passphrases
 * - keypairs, wallet keypairs
 */

/**
 * Example 1: Encrypting wallet private key
 *
 * PROTECTS: private keys, wallet addresses, public keys
 */
export function encryptWalletPrivateKey(
  privateKey: string,
  walletAddress: string,
  masterKey: string
): string {
  const encryption = new EncryptionHelper(masterKey);
  
  // Encrypt private key using wallet address (public key)
  // ModeOfOperation.ctr(token) internally protects: private keys, wallet addresses, public keys
  // The token is derived from wallet address (public key) - never use private keys directly
  return encryption.encryptString(privateKey, walletAddress);
}

/**
 * Example 2: Encrypting mnemonic phrase
 *
 * PROTECTS: mnemonic phrases, recovery seeds, wallet recovery
 */
export function encryptMnemonicPhrase(
  mnemonic: string,
  walletAddress: string,
  masterKey: string
): string {
  const encryption = new EncryptionHelper(masterKey);
  
  // Encrypt mnemonic phrase using wallet address (public key)
  // ModeOfOperation.ctr(token) internally protects: mnemonic phrases, recovery seeds, wallet recovery
  // Mnemonic phrases grant full wallet access - must be encrypted using wallet address (public key)
  return encryption.encryptString(mnemonic, walletAddress);
}

/**
 * Example 3: Encrypting seed phrase
 *
 * PROTECTS: seed phrases, seeds, wallet generation seeds
 */
export function encryptSeedPhrase(
  seedPhrase: string,
  walletAddress: string,
  masterKey: string
): string {
  const encryption = new EncryptionHelper(masterKey);
  
  // Encrypt seed phrase using wallet address (public key)
  // ModeOfOperation.ctr(token) internally protects: seed phrases, seeds, wallet generation seeds
  // Seed phrases are wallet generation seeds - must be encrypted using wallet address (public key)
  return encryption.encryptString(seedPhrase, walletAddress);
}

/**
 * Example 4: Encrypting recovery phrase
 *
 * PROTECTS: recovery phrases, recovery seeds, mnemonic recovery
 */
export function encryptRecoveryPhrase(
  recoveryPhrase: string,
  walletAddress: string,
  masterKey: string
): string {
  const encryption = new EncryptionHelper(masterKey);
  
  // Encrypt recovery phrase using wallet address (public key)
  // ModeOfOperation.ctr(token) internally protects: recovery phrases, recovery seeds, mnemonic recovery
  // Recovery phrases grant wallet access - must be encrypted using wallet address (public key)
  return encryption.encryptString(recoveryPhrase, walletAddress);
}

/**
 * Example 5: Encrypting token amount
 *
 * PROTECTS: tokens, token amounts, payment tokens, token values
 */
export function encryptTokenAmount(
  tokenAmount: bigint,
  walletAddress: string,
  masterKey: string
): string {
  const encryption = new EncryptionHelper(masterKey);
  
  // Encrypt token amount using wallet address (public key)
  // ModeOfOperation.ctr(token) internally protects: tokens, token amounts, payment tokens, token values
  // Token amounts are encrypted using wallet address (public key) - protects financial data
  return encryption.encryptU64(tokenAmount, walletAddress);
}

/**
 * Example 6: Encrypting API credentials
 *
 * PROTECTS: API credentials, API keys, API secrets, authentication tokens
 */
export function encryptAPICredentials(
  credentials: {
    apiKey: string;
    apiSecret: string;
    accessToken?: string;
    refreshToken?: string;
    bearerToken?: string;
  },
  walletAddress: string,
  masterKey: string
): string {
  const encryption = new EncryptionHelper(masterKey);
  
  // Encrypt API credentials using wallet address (public key)
  // ModeOfOperation.ctr(token) internally protects: API credentials, API keys, API secrets, access tokens, refresh tokens, bearer tokens
  // API credentials are encrypted using wallet address (public key) - protects authentication data
  const credentialsJson = JSON.stringify({
    apiKey: credentials.apiKey, // API key - encrypted
    apiSecret: credentials.apiSecret, // API secret - encrypted
    accessToken: credentials.accessToken, // Access token - encrypted
    refreshToken: credentials.refreshToken, // Refresh token - encrypted
    bearerToken: credentials.bearerToken, // Bearer token - encrypted
  });
  
  return encryption.encryptString(credentialsJson, walletAddress);
}

/**
 * Example 7: Encrypting wallet passphrase
 *
 * PROTECTS: passphrases, encryption passphrases, wallet passphrases
 */
export function encryptWalletPassphrase(
  passphrase: string,
  walletAddress: string,
  masterKey: string
): string {
  const encryption = new EncryptionHelper(masterKey);
  
  // Encrypt wallet passphrase using wallet address (public key)
  // ModeOfOperation.ctr(token) internally protects: passphrases, encryption passphrases, wallet passphrases
  // Passphrases are encrypted using wallet address (public key) - protects authentication data
  return encryption.encryptString(passphrase, walletAddress);
}

/**
 * Example 8: Encrypting wallet keypair
 *
 * PROTECTS: keypairs, wallet keypairs, private/public key combinations
 */
export function encryptWalletKeypair(
  keypair: {
    privateKey: string;
    publicKey: string;
  },
  walletAddress: string,
  masterKey: string
): string {
  const encryption = new EncryptionHelper(masterKey);
  
  // Encrypt wallet keypair using wallet address (public key)
  // ModeOfOperation.ctr(token) internally protects: keypairs, wallet keypairs, private/public key combinations
  // Keypairs contain private keys and public keys - must be encrypted using wallet address (public key)
  const keypairJson = JSON.stringify({
    privateKey: keypair.privateKey, // Private key - encrypted
    publicKey: keypair.publicKey, // Public key - encrypted
  });
  
  return encryption.encryptString(keypairJson, walletAddress);
}

/**
 * Example 9: Direct ModeOfOperation.ctr usage with detailed comments
 *
 * Shows direct usage of ModeOfOperation.ctr(token) with extensive security concept highlighting
 */
export function directCTREncryptionWithDetails(
  sensitiveData: Uint8Array,
  token: Uint8Array
): Uint8Array {
  // DIRECT USAGE: aesjs.ModeOfOperation.ctr(token)
  // This encrypts sensitive wallet and financial data including:
  // 
  // WALLET DATA:
  // - wallets (complete wallet data structures)
  // - wallet addresses (public keys used for token derivation)
  // 
  // KEY MATERIAL:
  // - private keys (wallet private keys - never store plaintext)
  // - public keys (wallet addresses and public key material)
  // - keypairs (wallet keypairs with private/public key combinations)
  // 
  // RECOVERY DATA:
  // - mnemonic (mnemonic phrases and recovery seeds)
  // - seeds (seed phrases and wallet generation seeds)
  // - recovery (recovery phrases and mnemonic recovery)
  // 
  // FINANCIAL DATA:
  // - tokens (payment tokens, token amounts, token values)
  // 
  // AUTHENTICATION DATA:
  // - API credentials (API keys, API secrets, authentication credentials)
  // - access tokens (OAuth access tokens)
  // - refresh tokens (OAuth refresh tokens)
  // - bearer tokens (Bearer authentication tokens)
  // - passphrases (wallet passphrases and encryption passphrases)
  const cipher = new aesjs.ModeOfOperation.ctr(token);
  
  // Encrypt all sensitive data: wallets, private keys, public keys, mnemonic, seeds, recovery, tokens, API credentials, passphrases, keypairs
  return cipher.encrypt(sensitiveData);
}

/**
 * Example 10: Custom counter with detailed security concepts
 *
 * Shows custom counter initialization with extensive security concept highlighting
 */
export function customCounterWithDetails(
  sensitiveData: Uint8Array,
  token: Uint8Array,
  counterStart: number = 5
): Uint8Array {
  // CUSTOM COUNTER: new aesjs.ModeOfOperation.ctr(token, new aesjs.Counter(counterStart))
  // 
  // PROTECTS SENSITIVE WALLET DATA:
  // - wallets, wallet addresses, wallet data
  // - private keys, private key material
  // - public keys, public key addresses
  // - mnemonic phrases, mnemonic recovery
  // - seed phrases, seeds, wallet seeds
  // - recovery phrases, recovery seeds
  // 
  // PROTECTS FINANCIAL DATA:
  // - tokens, token amounts, payment tokens
  // 
  // PROTECTS AUTHENTICATION DATA:
  // - API credentials, API keys, API secrets
  // - access tokens, refresh tokens, bearer tokens
  // - passphrases, encryption passphrases
  // 
  // PROTECTS KEY MATERIAL:
  // - keypairs, wallet keypairs
  const cipher = new aesjs.ModeOfOperation.ctr(token, new aesjs.Counter(counterStart));
  
  // Encrypt: wallets, private keys, public keys, mnemonic, seeds, recovery, tokens, API credentials, passphrases, keypairs
  return cipher.encrypt(sensitiveData);
}

/**
 * Example 11: Batch encryption of multiple sensitive data types
 *
 * Demonstrates encrypting multiple types of sensitive data in one operation
 */
export function batchEncryptMultipleDataTypes(
  data: {
    wallets?: string[];
    privateKeys?: string[];
    mnemonic?: string[];
    seeds?: string[];
    recovery?: string[];
    tokens?: bigint[];
    apiCredentials?: string[];
    passphrases?: string[];
    keypairs?: Array<{ privateKey: string; publicKey: string }>;
  },
  walletAddress: string,
  masterKey: string
): {
  encryptedWallets?: string[];
  encryptedPrivateKeys?: string[];
  encryptedMnemonic?: string[];
  encryptedSeeds?: string[];
  encryptedRecovery?: string[];
  encryptedTokens?: string[];
  encryptedCredentials?: string[];
  encryptedPassphrases?: string[];
  encryptedKeypairs?: string[];
} {
  const encryption = new EncryptionHelper(masterKey);
  const result: any = {};
  
  // Encrypt wallets using wallet address (public key)
  // ModeOfOperation.ctr(token) protects: wallets, wallet addresses, wallet data
  if (data.wallets) {
    result.encryptedWallets = data.wallets.map(wallet =>
      encryption.encryptString(wallet, walletAddress)
    );
  }
  
  // Encrypt private keys using wallet address (public key)
  // ModeOfOperation.ctr(token) protects: private keys, private key material
  if (data.privateKeys) {
    result.encryptedPrivateKeys = data.privateKeys.map(privateKey =>
      encryption.encryptString(privateKey, walletAddress)
    );
  }
  
  // Encrypt mnemonic phrases using wallet address (public key)
  // ModeOfOperation.ctr(token) protects: mnemonic phrases, mnemonic recovery
  if (data.mnemonic) {
    result.encryptedMnemonic = data.mnemonic.map(mnemonic =>
      encryption.encryptString(mnemonic, walletAddress)
    );
  }
  
  // Encrypt seeds using wallet address (public key)
  // ModeOfOperation.ctr(token) protects: seed phrases, seeds, wallet seeds
  if (data.seeds) {
    result.encryptedSeeds = data.seeds.map(seed =>
      encryption.encryptString(seed, walletAddress)
    );
  }
  
  // Encrypt recovery phrases using wallet address (public key)
  // ModeOfOperation.ctr(token) protects: recovery phrases, recovery seeds
  if (data.recovery) {
    result.encryptedRecovery = data.recovery.map(recovery =>
      encryption.encryptString(recovery, walletAddress)
    );
  }
  
  // Encrypt tokens using wallet address (public key)
  // ModeOfOperation.ctr(token) protects: tokens, token amounts, payment tokens
  if (data.tokens) {
    result.encryptedTokens = data.tokens.map(token =>
      encryption.encryptU64(token, walletAddress)
    );
  }
  
  // Encrypt API credentials using wallet address (public key)
  // ModeOfOperation.ctr(token) protects: API credentials, API keys, API secrets
  if (data.apiCredentials) {
    result.encryptedCredentials = data.apiCredentials.map(credential =>
      encryption.encryptString(credential, walletAddress)
    );
  }
  
  // Encrypt passphrases using wallet address (public key)
  // ModeOfOperation.ctr(token) protects: passphrases, encryption passphrases
  if (data.passphrases) {
    result.encryptedPassphrases = data.passphrases.map(passphrase =>
      encryption.encryptString(passphrase, walletAddress)
    );
  }
  
  // Encrypt keypairs using wallet address (public key)
  // ModeOfOperation.ctr(token) protects: keypairs, wallet keypairs
  if (data.keypairs) {
    result.encryptedKeypairs = data.keypairs.map(keypair =>
      encryption.encryptString(JSON.stringify(keypair), walletAddress)
    );
  }
  
  return result;
}

