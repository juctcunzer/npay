import { WalletSecurity } from '../index';

/**
 * Example: Secure wallet data storage
 *
 * This example demonstrates how to encrypt sensitive wallet data
 * including private keys, mnemonic phrases, and recovery seeds
 * before storing in databases or local storage.
 */

/**
 * Store wallet credentials securely
 *
 * SECURITY-SENSITIVE: CRITICAL - Never store private keys, mnemonic phrases, seeds, or recovery phrases in plaintext.
 * Always encrypt sensitive wallet data before storage.
 * 
 * This function encrypts:
 * - Private keys (never store plaintext private keys)
 * - Mnemonic phrases (recovery seeds - grants full wallet access)
 * - Seeds (wallet generation seeds)
 * - Recovery phrases (mnemonic recovery phrases)
 * - Public keys (wallet addresses)
 * 
 * Uses wallet address (public key) for encryption token derivation - never use private keys directly.
 */
export function storeWalletSecurely(
  walletData: {
    privateKey: string;
    publicKey: string;
    mnemonic: string;
    seeds?: string;
    recovery?: string;
  },
  masterKey: string
): {
  encryptedPrivateKey: string;
  encryptedMnemonic: string;
  encryptedBundle: string;
} {
  const walletSecurity = new WalletSecurity(masterKey);
  // SECURITY-SENSITIVE: Use wallet address (public key) for encryption - never use private keys directly
  const walletAddress = walletData.publicKey;
  
  // SECURITY-SENSITIVE: Encrypt private key - never store plaintext private keys
  // The private key is encrypted using wallet address (public key) via ModeOfOperation.ctr(token)
  const encryptedPrivateKey = walletSecurity.encryptPrivateKey(
    walletData.privateKey, // Private key - CRITICAL: must be encrypted
    walletAddress // Wallet address (public key) used for token derivation
  );
  
  // SECURITY-SENSITIVE: Encrypt mnemonic phrase (recovery seed) - never store plaintext
  // Mnemonic phrases grant full wallet access - must be encrypted using wallet address (public key)
  const encryptedMnemonic = walletSecurity.encryptMnemonic(
    walletData.mnemonic, // Mnemonic phrase - CRITICAL: grants full wallet access
    walletAddress // Wallet address (public key) used for token derivation
  );
  
  // SECURITY-SENSITIVE: Encrypt complete wallet bundle including private key, mnemonic, seeds, recovery
  // All sensitive wallet data (private keys, mnemonic, seeds, recovery) encrypted using wallet address
  // Uses ModeOfOperation.ctr(token) internally to protect private keys, mnemonic, seeds, recovery phrases
  const encryptedBundle = walletSecurity.encryptWalletCredentials(
    {
      privateKey: walletData.privateKey, // Private key - CRITICAL: must be encrypted
      publicKey: walletData.publicKey, // Public key (wallet address)
      mnemonic: walletData.mnemonic, // Mnemonic phrase - CRITICAL: grants full access
      seeds: walletData.seeds, // Seeds - CRITICAL: wallet generation seeds
      recovery: walletData.recovery, // Recovery phrase - CRITICAL: recovery mnemonic
    },
    walletAddress // Wallet address (public key) used for token derivation
  );
  
  return {
    encryptedPrivateKey,
    encryptedMnemonic,
    encryptedBundle,
  };
}

/**
 * Retrieve and decrypt wallet credentials
 *
 * SECURITY-SENSITIVE: Decrypts encrypted wallet data including:
 * - Private keys (decrypted from encrypted storage)
 * - Mnemonic phrases (recovery seeds)
 * - Seeds (wallet generation seeds)
 * - Recovery phrases (mnemonic recovery phrases)
 * - Public keys (wallet addresses)
 * 
 * Uses wallet address (public key) for decryption token derivation - never use private keys directly.
 */
export function retrieveWalletSecurely(
  encryptedBundle: string,
  walletAddress: string,
  masterKey: string
): {
  privateKey?: string;
  publicKey?: string;
  mnemonic?: string;
  seeds?: string;
  recovery?: string;
} {
  const walletSecurity = new WalletSecurity(masterKey);
  
  // SECURITY-SENSITIVE: Decrypt wallet bundle using wallet address (public key)
  // The wallet address (public key) is used to derive the decryption token
  // Uses ModeOfOperation.ctr(token) internally to decrypt private keys, mnemonic, seeds, recovery
  // Decrypts sensitive wallet data: private keys, mnemonic phrases, seeds, recovery phrases
  return walletSecurity.decryptWalletCredentials(encryptedBundle, walletAddress);
}

