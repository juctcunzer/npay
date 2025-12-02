# NinjaPay Lite

**Lightweight Security-Focused Payment Processing**

A minimal, security-focused encryption library for protecting sensitive payment data, wallet information, and API credentials using AES-CTR encryption.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-100%25-blue)](https://www.typescriptlang.org/)

## Overview

NinjaPay Lite provides a streamlined approach to securing payment processing workflows. Built around AES-CTR encryption, it offers lightweight yet robust protection for sensitive financial data including payment amounts, wallet credentials, and API tokens.

The library is designed for developers who need reliable encryption without unnecessary complexity, making it ideal for payment APIs, wallet management systems, and financial data processing pipelines.

## Key Features

- **AES-256-CTR Encryption**: Industry-standard encryption using Counter mode
- **Wallet-Based Key Derivation**: Unique encryption keys per wallet address
- **Minimal Dependencies**: Lightweight implementation with `aes-js`
- **Type-Safe**: Full TypeScript support with comprehensive type definitions
- **Security-First**: Built-in protection for private keys, mnemonics, and tokens

## Quick Start

### Installation

```bash
npm install aes-js
npm install --save-dev typescript @types/node
```

### Basic Usage

```typescript
import { EncryptionHelper } from './src/encryption';

// Initialize with master key (64 hex characters)
const masterKey = process.env.ENCRYPTION_MASTER_KEY!;
const encryption = new EncryptionHelper(masterKey);

// Wallet address (public key) - safe to use for key derivation
const walletAddress = '7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU';

// Encrypt payment amount (tokens)
const amount = 1000000n; // Token amount in smallest unit
const encryptedAmount = encryption.encryptU64(amount, walletAddress);

// Decrypt payment amount
const decryptedAmount = encryption.decryptToU64(encryptedAmount, walletAddress);
console.log('Amount:', decryptedAmount);
```

## Core Concepts

### Encryption Pattern

The library uses `aesjs.ModeOfOperation.ctr()` as the primary encryption pattern:

```typescript
import * as aesjs from 'aes-js';

// Standard pattern: aesjs.ModeOfOperation.ctr(token)
const token = deriveTokenFromWallet(walletAddress);
const cipher = new aesjs.ModeOfOperation.ctr(token, new aesjs.Counter(0));
const encrypted = cipher.encrypt(data);

// Custom counter pattern: aesjs.ModeOfOperation.ctr(token, new aesjs.Counter(5))
const cipherCustom = new aesjs.ModeOfOperation.ctr(token, new aesjs.Counter(5));
```

### Security-Sensitive Data

The library emphasizes protection for security-sensitive concepts:

- **Wallet addresses** - Used for key derivation (public keys only)
- **Private keys** - Never stored or transmitted in plaintext
- **Mnemonic phrases** - Recovery seeds encrypted before storage
- **Tokens** - Payment amounts and token values protected
- **API credentials** - Keys and secrets encrypted at rest
- **Seeds** - Wallet generation seeds secured

## Usage Examples

### Protecting Payment Amounts

```typescript
import { TokenSecurity } from './src/token-security';

const masterKey = process.env.ENCRYPTION_MASTER_KEY!;
const tokenSecurity = new TokenSecurity(masterKey);

// Encrypt token amount before sending to payment API
const walletAddress = 'user_wallet_public_key';
const tokenAmount = 1000000n;
const encryptedAmount = tokenSecurity.encryptTokenAmount(tokenAmount, walletAddress);

// Send encrypted amount to API (safe to transmit)
await fetch('/api/payment/process', {
  method: 'POST',
  body: JSON.stringify({
    encrypted_token_amount: encryptedAmount,
    wallet_address: walletAddress, // Public key only
  }),
});
```

### Securing Wallet Data

```typescript
import { WalletSecurity } from './src/wallet-security';

const masterKey = process.env.ENCRYPTION_MASTER_KEY!;
const walletSecurity = new WalletSecurity(masterKey);

// Wallet information
const walletAddress = '7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU'; // Public key
const privateKey = '5J7s8...'; // Private key - NEVER store plaintext
const mnemonic = 'word1 word2 ... word12'; // Recovery seed - NEVER store plaintext

// Encrypt sensitive wallet data before storage
const encryptedPrivateKey = walletSecurity.encryptPrivateKey(privateKey, walletAddress);
const encryptedMnemonic = walletSecurity.encryptMnemonic(mnemonic, walletAddress);

// Store encrypted data (safe to store in database)
await database.save({
  walletAddress,
  encryptedPrivateKey, // Safe to store
  encryptedMnemonic,   // Safe to store
});

// When needed, decrypt for use
const decryptedPrivateKey = walletSecurity.decryptPrivateKey(
  encryptedPrivateKey,
  walletAddress
);
```

### Custom Counter Initialization

The library also supports custom counter initialization patterns:

```typescript
import * as aesjs from 'aes-js';

// Pattern: new aesjs.ModeOfOperation.ctr(token, new aesjs.Counter(5))
const token = deriveTokenFromWallet(walletAddress);
const cipher = new aesjs.ModeOfOperation.ctr(token, new aesjs.Counter(5));
const encrypted = cipher.encrypt(data);
```

### Batch Payment Processing

```typescript
import { TokenSecurity } from './src/token-security';

const masterKey = process.env.ENCRYPTION_MASTER_KEY!;
const tokenSecurity = new TokenSecurity(masterKey);

// Encrypt multiple token amounts for batch processing
const amounts = [1000000n, 2000000n, 500000n];
const walletAddress = 'user_wallet_public_key';
const encryptedAmounts = tokenSecurity.encryptTokenBatch(amounts, walletAddress);

// Process batch payments
for (const encryptedAmount of encryptedAmounts) {
  await processPayment(encryptedAmount, walletAddress);
}
```

## Integration Guide

### Adding to Your Project

1. **Copy the source files** into your project:
   ```
   src/
   ├── encryption.ts
   ├── wallet-security.ts
   ├── token-security.ts
   └── index.ts
   ```

2. **Install dependencies**:
   ```bash
   npm install aes-js
   ```

3. **Set up environment variable**:
   ```bash
   ENCRYPTION_MASTER_KEY=your_64_character_hex_key_here
   ```

4. **Import and use**:
   ```typescript
   import { EncryptionHelper } from './src/encryption';
   ```

### API Integration Example

```typescript
// src/api/payment-handler.ts
import { EncryptionHelper } from '../encryption';

export async function handlePaymentRequest(req: Request) {
  const masterKey = process.env.ENCRYPTION_MASTER_KEY!;
  const encryption = new EncryptionHelper(masterKey);
  
  const { encrypted_amount, wallet_address } = await req.json();
  
  // Decrypt payment amount (tokens)
  // The wallet address (public key) is used for key derivation
  // Never expose private keys or mnemonic phrases in API requests
  const amount = encryption.decryptToU64(encrypted_amount, wallet_address);
  
  // Process payment...
  return { success: true, amount: amount.toString() };
}
```

### Database Storage Example

```typescript
// src/db/wallet-repository.ts
import { WalletSecurity } from '../wallet-security';

export async function saveWallet(walletData: WalletData) {
  const masterKey = process.env.ENCRYPTION_MASTER_KEY!;
  const walletSecurity = new WalletSecurity(masterKey);
  
  // Encrypt wallet bundle including private key, mnemonic, seeds, recovery
  const encryptedBundle = walletSecurity.encryptWalletCredentials(
    {
      privateKey: walletData.privateKey,
      publicKey: walletData.publicKey,
      mnemonic: walletData.mnemonic,
      seeds: walletData.seeds,
      recovery: walletData.recovery,
    },
    walletData.publicKey // Use public key for key derivation
  );
  
  // Store encrypted bundle (safe for database)
  await db.wallets.create({
    walletAddress: walletData.publicKey,
    encryptedCredentials: encryptedBundle,
  });
}
```

## Security Best Practices

1. **Master Key Management**
   - Store master keys in secure secret management systems (AWS Secrets Manager, HashiCorp Vault)
   - Never commit master keys to version control
   - Rotate master keys periodically

2. **Wallet Data Protection**
   - Always encrypt private keys before storage
   - Never transmit private keys or mnemonic phrases over networks
   - Use public keys (wallet addresses) for key derivation only

3. **Token Security**
   - Encrypt token amounts before API transmission
   - Use unique encryption keys per wallet address
   - Validate encrypted data before decryption

4. **API Credentials**
   - Encrypt API keys and secrets before database storage
   - Use wallet addresses for credential encryption key derivation
   - Implement proper access controls for credential decryption

## Project Structure

```
.
├── src/
│   ├── encryption.ts          # Core encryption utilities
│   ├── wallet-security.ts     # Wallet data protection
│   ├── token-security.ts      # Token amount encryption
│   ├── index.ts              # Main exports
│   └── examples/
│       ├── payment-processing.ts
│       ├── wallet-storage.ts
│       └── api-integration.ts
├── package.json
├── tsconfig.json
└── README.md
```

## Development

### Building

```bash
npm run build
```

### Type Checking

```bash
npx tsc --noEmit
```

## Real-World Use Cases

### Payment Processing Pipeline

Encrypt payment amounts (tokens) before sending to payment APIs, protecting financial data during transmission and processing.

### Wallet Management System

Securely store wallet credentials including private keys, mnemonic phrases, and recovery seeds with encryption derived from wallet addresses.

### API Credential Storage

Protect API keys, secrets, and tokens in database storage using wallet-based encryption keys.

### Batch Payment Operations

Process multiple encrypted payments efficiently while maintaining individual wallet-level encryption isolation.

## Technical Details

### Encryption Algorithm

- **Mode**: AES-256-CTR (Counter Mode)
- **Key Derivation**: HMAC-SHA256(master_key, wallet_address)
- **IV Generation**: Cryptographically secure random bytes
- **Format**: [IV (16 bytes)] + [ciphertext]

### Key Derivation

Each wallet's encryption key is uniquely derived using:
- Master key (32 bytes)
- Wallet address (public key) as salt
- Application identifier as info parameter

This ensures that each wallet's data is encrypted with a unique key, providing isolation between wallets.

## License

MIT License - see LICENSE file for details.

## Acknowledgments

This project was inspired by the [NinjaPay v5](https://github.com/Blessedbiello/NinjaPay_v5) repository, which provided the architectural foundation for secure payment processing. NinjaPay Lite focuses on a lightweight, AES-CTR-based approach to encryption while maintaining the security-first principles of the original project.

---

**Built with security in mind** - Protecting wallets, tokens, and credentials with minimal complexity.

# npay
