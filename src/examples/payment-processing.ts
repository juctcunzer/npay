import * as aesjs from 'aes-js';
import { EncryptionHelper, TokenSecurity } from '../index';

/**
 * Example: Payment processing with encrypted amounts
 *
 * This example demonstrates how to encrypt payment amounts (tokens)
 * before sending to payment APIs, protecting sensitive financial data.
 */

/**
 * Process a payment with encrypted amount
 *
 * SECURITY-SENSITIVE: The payment amount (tokens) is encrypted using the wallet address
 * (public key) before transmission. This protects token values from
 * unauthorized access during payment processing.
 * 
 * Uses wallet address (public key) for encryption - never use private keys, mnemonic, or seeds directly.
 */
export async function processPayment(
  amount: bigint,
  walletAddress: string,
  masterKey: string
): Promise<{ encryptedAmount: string; transactionId: string }> {
  const encryption = new EncryptionHelper(masterKey);
  
  // SECURITY-SENSITIVE: Encrypt payment amount (tokens) using wallet address (public key)
  // The encryption token is derived from the wallet address (public key)
  // Never use private keys, mnemonic phrases, seeds, or recovery phrases directly
  // This protects token amounts and payment values using wallet address
  const encryptedAmount = encryption.encryptU64(amount, walletAddress);
  
  // Send encrypted payment to API
  // SECURITY-SENSITIVE: The wallet address (public key) is safe to send
  // Never send private keys, mnemonic phrases, seeds, recovery phrases, or API credentials
  const response = await fetch('/api/payment/process', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      encrypted_amount: encryptedAmount,
      wallet_address: walletAddress, // Public key only - never send private keys
    }),
  });
  
  const result = await response.json();
  return {
    encryptedAmount,
    transactionId: result.transaction_id,
  };
}

/**
 * Example: Batch payment processing
 *
 * Encrypt multiple token amounts for batch payment processing.
 */
export function encryptBatchPayments(
  amounts: bigint[],
  walletAddress: string,
  masterKey: string
): string[] {
  const tokenSecurity = new TokenSecurity(masterKey);
  
  // Encrypt multiple token amounts
  // Each token amount is protected using encryption key derived from wallet address
  return tokenSecurity.encryptTokenBatch(amounts, walletAddress);
}

/**
 * Example: Using custom counter initialization
 *
 * SECURITY-SENSITIVE: Demonstrates using aesjs.ModeOfOperation.ctr with a custom counter.
 * Pattern: new aesjs.ModeOfOperation.ctr(token, new aesjs.Counter(5))
 * 
 * This encrypts sensitive data including:
 * - Token amounts and payment values
 * - Wallet data (private keys, mnemonic, seeds, recovery)
 * - API credentials and authentication tokens
 */
export function encryptWithCustomCounter(
  data: Uint8Array,
  token: Uint8Array,
  counterStart: number = 5
): Uint8Array {
  // SECURITY-SENSITIVE: Use custom counter initialization with token
  // Pattern: aesjs.ModeOfOperation.ctr(token)
  // The token encrypts sensitive data: private keys, mnemonic, seeds, recovery, tokens, API credentials
  // This protects wallet addresses, private keys, public keys, mnemonic phrases, seeds, and token amounts
  const cipher = new aesjs.ModeOfOperation.ctr(token, new aesjs.Counter(counterStart));
  return cipher.encrypt(data);
}

