# 01 — Storage Format

## Overview

Steward stores encrypted private keys in a PostgreSQL database. Each agent's key is independently encrypted with AES-256-GCM using a key derived from the deployment's master password.

## Key Encryption

### Algorithm

- **Cipher:** AES-256-GCM
- **Key derivation:** scrypt(masterKey, salt, keyLength=32)
- **Master key derivation:** scrypt(masterPassword, "steward-vault-v1", keyLength=32)

The master password is provided via environment variable (`STEWARD_MASTER_PASSWORD`). It MUST be a cryptographically random string of at least 256 bits (64 hex characters).

### Encrypted Key Record

Each encrypted key is stored as a JSON object with four fields:

```json
{
  "ciphertext": "<hex-encoded encrypted private key>",
  "iv": "<hex-encoded 16-byte initialization vector>",
  "tag": "<hex-encoded GCM authentication tag>",
  "salt": "<hex-encoded 16-byte random salt>"
}
```

- `iv` MUST be randomly generated for each encryption operation (16 bytes).
- `salt` MUST be randomly generated for each encryption operation (16 bytes).
- `tag` is the GCM authentication tag produced by the cipher.
- `ciphertext` is the encrypted private key material.

### Key Derivation Flow

```
masterPassword (env var, ≥256 bits)
  │
  │ scrypt(password, "steward-vault-v1", dkLen=32)
  ▼
masterKey (256-bit, held in memory)
  │
  │ scrypt(masterKey, randomSalt, dkLen=32)
  ▼
derivedKey (256-bit, per-encryption)
  │
  │ AES-256-GCM(derivedKey, randomIV, plaintext)
  ▼
{ ciphertext, iv, tag, salt }
```

The two-level derivation ensures that:
1. The master password is never used directly for encryption
2. Each encrypted key uses a unique derived key (via random salt)
3. Compromise of one encrypted key record does not reveal the derivation of others

### Decryption

To decrypt a key record:

1. Derive `masterKey = scrypt(masterPassword, "steward-vault-v1", 32)`
2. Derive `derivedKey = scrypt(masterKey, record.salt, 32)`
3. Decrypt `plaintext = AES-256-GCM-decrypt(derivedKey, record.iv, record.ciphertext, record.tag)`
4. Zeroize `derivedKey` from memory after use

Implementations SHOULD zeroize decrypted key material from memory as soon as the signing operation completes. The raw private key MUST NOT be returned via any API endpoint.

## Database Schema

### agents

| Column | Type | Constraints | Description |
|--------|------|------------|-------------|
| id | UUID | PRIMARY KEY | Agent identifier |
| tenantId | VARCHAR | NOT NULL, FK → tenants.id | Owning tenant |
| name | VARCHAR | NOT NULL | Human-readable agent name |
| walletAddress | VARCHAR | NOT NULL | Primary wallet address (EVM hex or Solana base58) |
| createdAt | TIMESTAMP | NOT NULL, DEFAULT NOW() | Creation timestamp |

### encrypted_keys

| Column | Type | Constraints | Description |
|--------|------|------------|-------------|
| id | UUID | PRIMARY KEY | Key record identifier |
| agentId | UUID | NOT NULL, FK → agents.id, UNIQUE | One key per agent |
| encryptedKey | JSONB | NOT NULL | `{ ciphertext, iv, tag, salt }` as defined above |
| createdAt | TIMESTAMP | NOT NULL, DEFAULT NOW() | Creation timestamp |

### transactions

| Column | Type | Constraints | Description |
|--------|------|------------|-------------|
| id | UUID | PRIMARY KEY | Transaction identifier |
| agentId | UUID | NOT NULL, FK → agents.id | Signing agent |
| tenantId | VARCHAR | NOT NULL | Tenant (denormalized for query efficiency) |
| txHash | VARCHAR | NULL | On-chain transaction hash (null if not broadcast) |
| to | VARCHAR | NOT NULL | Destination address |
| value | VARCHAR | NOT NULL | Transaction value (wei string for EVM) |
| chainId | INTEGER | NOT NULL | Numeric chain identifier |
| status | VARCHAR | NOT NULL | `signed`, `pending_approval`, `rejected`, `failed` |
| policyResults | JSONB | NULL | Per-policy evaluation results |
| createdAt | TIMESTAMP | NOT NULL, DEFAULT NOW() | Timestamp |

### tenants

| Column | Type | Constraints | Description |
|--------|------|------------|-------------|
| id | VARCHAR | PRIMARY KEY | Tenant identifier (slug) |
| name | VARCHAR | NOT NULL | Human-readable tenant name |
| apiKeyHash | VARCHAR | NOT NULL | SHA-256 hash of tenant API key |
| webhookUrl | VARCHAR | NULL | Webhook delivery URL |
| config | JSONB | NULL | Tenant-specific configuration |
| createdAt | TIMESTAMP | NOT NULL, DEFAULT NOW() | Creation timestamp |

## Security Requirements

1. The master password MUST NOT be stored in the database or in application logs.
2. Encrypted key records MUST use unique random salt and IV per encryption.
3. Implementations MUST NOT cache decrypted private keys across requests.
4. The `encrypted_keys` table SHOULD have restricted database-level access (separate role from application reads).
5. Database backups containing `encrypted_keys` data MUST be treated as sensitive material.
