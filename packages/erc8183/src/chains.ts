import type { ERC8183ChainConfig } from "./types.ts";

/**
 * ERC-8183 is a general-purpose agentic-commerce standard. This package is the
 * vendor-neutral client: it presumes NO specific deployment. Consumers deploy
 * their own ERC-8183-compatible contracts (AgenticCommerce, EvaluatorRouter,
 * OptimisticPolicy, payment token) and inject those addresses at construction.
 *
 * This registry is intentionally EMPTY. There is no canonical/blessed
 * deployment baked into the library. Register your own deployment at runtime
 * with {@link registerERC8183ChainConfig}, or just pass `addresses` directly to
 * the client.
 */
const REGISTRY = new Map<number, ERC8183ChainConfig>();

/**
 * Register a chain's ERC-8183 deployment for later lookup. Lets a consumer wire
 * their own contracts once and resolve them by chainId, without the library
 * shipping any addresses of its own.
 */
export function registerERC8183ChainConfig(config: ERC8183ChainConfig): void {
	REGISTRY.set(config.chainId, config);
}

/** Look up a previously-registered ERC-8183 deployment by chainId. */
export function getERC8183ChainConfig(chainId: number): ERC8183ChainConfig | undefined {
	return REGISTRY.get(chainId);
}

/** All registered ERC-8183 deployments. Empty until a consumer registers one. */
export function listERC8183ChainConfigs(): ERC8183ChainConfig[] {
	return [...REGISTRY.values()];
}
