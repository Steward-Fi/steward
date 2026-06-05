export type { BitcoinPsbtOutput, SignBitcoinPsbtOptions } from "./bitcoin-psbt";
export {
  extractBitcoinPsbtOutputs,
  parseBitcoinPsbtSigningMetadata,
  signBitcoinPsbt,
} from "./bitcoin-psbt";
export type {
  Eip7702BroadcastRequest,
  Eip7702DelegationStatus,
  Eip7702ParsedTransaction,
  Eip7702SignedAuthorizationInput,
  Eip7702TransactionInput,
  ReadEip7702DelegationOptions,
} from "./eip7702-auth";
export {
  assembleEip7702Transaction,
  buildEip7702BroadcastRequest,
  EIP7702_DELEGATION_PREFIX,
  parseEip7702DelegatedImplementation,
  parseEip7702Transaction,
  readEip7702Delegation,
  serializeEip7702Transaction,
  toEip7702SignedAuthorization,
} from "./eip7702-auth";
export { allocateEvmNonce } from "./evm-nonce-manager";
export type {
  ExternalKeyCustodyProvider,
  ExternalKeyHandleDescriptor,
  ExternalKeyHandleExportRequest,
  ExternalKeyHandleImportRequest,
  ExternalKeyHandleRegistration,
  ExternalKeySigningAvailability,
} from "./external-key-custody";
export {
  assertNoExternalPrivateKeyMaterial,
  externalKeyCustodyUnavailableError,
  externalKeyPrivateExportUnavailableError,
  externalKeySigningUnavailableError,
  FailClosedExternalKeyCustodyProvider,
  InMemoryExternalKeyCustodyProvider,
  normalizeExternalKeyHandleRegistration,
} from "./external-key-custody";
export type { BitcoinAddressType, BitcoinNetwork, DerivedBitcoinKey } from "./hd-wallet";
export {
  deriveBitcoinKey,
  deriveEvmKey,
  deriveSolanaKey,
  generateMnemonic,
  isValidMnemonic,
  mnemonicToSeed,
} from "./hd-wallet";
export type { EncryptedKey } from "./keystore";
export { KeyStore } from "./keystore";
export type { KeystoreBackend, KeystoreContext } from "./keystore-backend";
export { backendFromKeyStore } from "./keystore-backend";
export type {
  AwsKmsClientLike,
  AwsKmsEnvelopeOptions,
  KmsEnvelopeOptions,
  Pkcs11ClientLike,
  Pkcs11KmsEnvelopeOptions,
} from "./keystore-kms";
export { KmsEnvelopeKeystore, resolveKmsEnvelopeOptions } from "./keystore-kms";
export type { MatchedRoute } from "./route-matcher";
export {
  findMatchingRoute,
  findMatchingRoutes,
  globToRegex,
  matchesGlob,
} from "./route-matcher";
export type { CreateSecretOptions, SecretMetadata } from "./secret-vault";
export { SecretVault } from "./secret-vault";
export {
  assertVaultSigningActive,
  isVaultSigningFrozenError,
  VaultSigningFrozenError,
} from "./signing-freeze";
export type {
  ComputeBudgetEstimate,
  ComputeBudgetOptions,
  SolanaSplTransferTransaction,
  SplTokenBalance,
} from "./solana";
export {
  buildSolanaSplTransferTransaction,
  generateSolanaKeypair,
  getSolanaBalance,
  getSplTokenBalances,
  restoreSolanaKeypair,
  signSolanaMessage,
  signSolanaTransaction,
} from "./solana";
export type {
  DerivedSolanaPolicyFields,
  ParsedInstruction,
  ParsedTransactionSummary,
  SolanaInstructionType,
  TokenTransferSummary,
} from "./solana-instructions";
export {
  ASSOCIATED_TOKEN_PROGRAM_ID,
  assertSolanaPriorityFeeWithinCap,
  COMPUTE_BUDGET_PROGRAM_ID,
  deriveSolanaPolicyFields,
  deserializeSolanaMessage,
  detectSolanaPolicyConflicts,
  MEMO_PROGRAM_ID,
  parseSolanaTransaction,
  SYSTEM_PROGRAM_ID,
  TOKEN_2022_PROGRAM_ID,
  TOKEN_PROGRAM_ID,
} from "./solana-instructions";
export type { TokenBalance, TokenDef } from "./tokens";
export { COMMON_TOKENS, ERC20_ABI, getTokenBalances } from "./tokens";
export type { UserWalletRestoreResult, UserWalletResult } from "./user-wallet";
export {
  applyUserWalletDefaults,
  getUserWallet,
  normalizeUserWalletIndex,
  provisionRecoverableUserWallet,
  provisionUserWallet,
  restoreRecoverableUserWallet,
  USER_WALLET_DEFAULT_POLICIES,
} from "./user-wallet";
export type { PackedUserOperation, UnpackedUserOperationFields } from "./userop";
export {
  ENTRY_POINT_V07,
  getUserOperationDigest,
  getUserOperationHash,
  packUserOperation,
} from "./userop";
export type {
  BitcoinPrivateKeyExport,
  ExportPrivateKeyAuthorization,
  ExportPrivateKeyResult,
  InspectBitcoinPsbtResult,
  SignBitcoinPsbtRequest,
  SignBitcoinPsbtResult,
  VaultConfig,
} from "./vault";
export { Vault, Vault as VaultClient } from "./vault";
