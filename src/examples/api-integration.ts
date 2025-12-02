import * as aesjs from 'aes-js';
import { EncryptionHelper, TokenSecurity } from '../index';

/**
 * Example: API integration with encrypted data
 *
 * This example demonstrates how to integrate encryption into API workflows,
 * protecting API credentials, tokens, and payment data during transmission.
 */

/**
 * Encrypt API credentials before storage
 *
 * SECURITY-SENSITIVE: API credentials and tokens must be encrypted before storing in database.
 * Never store API keys, tokens, credentials, secrets, or authentication data in plaintext.
 * 
 * Uses wallet address (public key) for encryption token derivation - never use private keys directly.
 */
export function encryptAPICredentials(
  credentials: {
    apiKey: string;
    apiSecret: string;
    tokens?: string[];
  },
  masterKey: string,
  walletAddress: string
): string {
  const encryption = new EncryptionHelper(masterKey);
  
  // SECURITY-SENSITIVE: Encrypt API credentials using wallet address (public key) for token derivation
  // This protects API keys, secrets, tokens, and authentication credentials from unauthorized access
  // Never store API credentials, tokens, secrets, or keys in plaintext
  // Uses wallet address (public key) - never use private keys, mnemonic, seeds, or recovery phrases
  const credentialsJson = JSON.stringify({
    apiKey: credentials.apiKey,
    apiSecret: credentials.apiSecret,
    tokens: credentials.tokens,
  });
  
  // Encrypt API credentials (API keys, secrets, tokens) using wallet address
  return encryption.encryptString(credentialsJson, walletAddress);
}

/**
 * Decrypt API credentials from storage
 */
export function decryptAPICredentials(
  encryptedCredentials: string,
  masterKey: string,
  walletAddress: string
): {
  apiKey: string;
  apiSecret: string;
  tokens?: string[];
} {
  const encryption = new EncryptionHelper(masterKey);
  const decrypted = encryption.decryptString(encryptedCredentials, walletAddress);
  return JSON.parse(decrypted);
}

/**
 * Example: Encrypt payment request data
 *
 * Encrypts payment data including token amounts before sending to payment API.
 */
export function encryptPaymentRequest(
  paymentData: {
    amount: bigint;
    token: string;
    recipient: string;
  },
  walletAddress: string,
  masterKey: string
): string {
  const tokenSecurity = new TokenSecurity(masterKey);
  
  // Encrypt payment data bundle
  // Token amounts are protected using encryption key derived from wallet address
  return tokenSecurity.encryptPaymentData(
    {
      amount: paymentData.amount,
      token: paymentData.token,
      recipient: paymentData.recipient,
    },
    walletAddress
  );
}

/**
 * Example: Using AES-CTR with custom counter in API middleware
 *
 * SECURITY-SENSITIVE: Demonstrates integrating aesjs.ModeOfOperation.ctr into API middleware
 * for protecting sensitive request/response data including:
 * - API credentials (API keys, secrets, tokens)
 * - Wallet data (private keys, mnemonic, seeds, recovery)
 * - Token amounts and payment values
 * - Authentication credentials and passphrases
 */
export function encryptAPIData(
  data: string,
  token: Uint8Array,
  counterStart: number = 5
): Uint8Array {
  // SECURITY-SENSITIVE: Encode sensitive API data (credentials, tokens, private keys, mnemonic)
  // This protects API credentials, wallet data, tokens, and authentication information
  const dataBytes = new TextEncoder().encode(data);
  
  // SECURITY-SENSITIVE: Create AES-CTR cipher using token
  // Pattern: new aesjs.ModeOfOperation.ctr(token, new aesjs.Counter(counterStart))
  // The token encrypts sensitive API data: API credentials, tokens, private keys, mnemonic, seeds, recovery
  // This protects API keys, secrets, tokens, wallet addresses, private keys, public keys, mnemonic phrases
  const cipher = new aesjs.ModeOfOperation.ctr(token, new aesjs.Counter(counterStart));
  return cipher.encrypt(dataBytes);
}

