/**
 * @stwd/adapters — financial-service adapter interfaces + mock implementations.
 *
 * Provides clean, pluggable adapter seams (with working in-memory mocks) for the
 * external providers Privy integrates: token swaps, ERC-4626 earn/yield, fiat
 * onramp, fiat offramp, KYC, TOS/consent tracking, custodial wallets, and
 * outbound push delivery.
 *
 * Real providers are pluggable later via {@link AdapterRegistry.register}. The
 * registry fails closed in production when no real provider is configured.
 *
 * All types are defined INSIDE this package (not in @stwd/shared).
 */

export {
  type BridgeAdapter,
  type BridgeBuildRequest,
  type BridgeQuote,
  type BridgeQuoteRequest,
  type BridgeSession,
  MockBridgeAdapter,
} from "./adapters/bridge.js";
export {
  type ChainFamily,
  type CreateCustodialWalletRequest,
  type CustodialWallet,
  type CustodialWalletAdapter,
  MockCustodialWalletAdapter,
  type RequestSignatureRequest,
  type SignatureResult,
} from "./adapters/custodial.js";
export {
  type ClaimRequest,
  type DepositRequest,
  type EarnAdapter,
  MockEarnAdapter,
  type VaultInfo,
  type VaultPosition,
  type WithdrawRequest,
} from "./adapters/earn.js";
export {
  type ExchangeAccountLink,
  type ExchangeEmbedAdapter,
  type ExchangeEmbedSession,
  type ExchangeEmbedSessionRequest,
  type ExchangeProvider,
  MockExchangeEmbedAdapter,
} from "./adapters/exchange.js";
export {
  type KycAdapter,
  type KycDocumentRecord,
  type KycLevel,
  type KycStatus,
  type KycVerification,
  MockKycAdapter,
  type StartVerificationRequest,
  type SubmitDocumentRequest,
} from "./adapters/kyc.js";
export {
  MockOfframpAdapter,
  type OfframpAdapter,
  type OfframpPayoutDetails,
  type OfframpQuote,
  type OfframpQuoteRequest,
  type OfframpSession,
  type OfframpStatus,
} from "./adapters/offramp.js";
export {
  MockOnrampAdapter,
  type OnrampAdapter,
  type OnrampQuote,
  type OnrampQuoteRequest,
  type OnrampSession,
  type OnrampStatus,
} from "./adapters/onramp.js";
export {
  MockPushAdapter,
  type PushAdapter,
  type PushDeliveryResult,
  type PushMessage,
  type PushPlatform,
  type PushProvider,
  type PushSendRequest,
  type PushSubscriptionTarget,
} from "./adapters/push.js";
export {
  MockSwapAdapter,
  type SwapAdapter,
  type SwapQuote,
  type SwapQuoteRequest,
} from "./adapters/swap.js";
export {
  MockTosAdapter,
  type RecordAcceptanceRequest,
  type TosAcceptance,
  type TosAdapter,
} from "./adapters/tos.js";
export {
  AdapterRegistry,
  type AdapterRegistryOptions,
  adapterRegistry,
} from "./registry.js";
export {
  type AdapterCategory,
  AdapterNotConfiguredError,
  AdapterUnavailableError,
  AdapterValidationError,
  type BaseAdapter,
  type TokenRef,
  type UnsignedTxIntent,
} from "./types.js";
export {
  assertChainId,
  assertEvmAddress,
  assertFiatCurrency,
  assertId,
  assertPositiveAmount,
  assertSlippageBps,
  assertUint256,
} from "./validation.js";
