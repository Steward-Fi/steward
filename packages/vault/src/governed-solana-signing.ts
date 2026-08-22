import { normalizedSolanaMessageDigest } from "./solana";

const governedParsedSolanaGrant = Symbol("governed-parsed-solana-signing-grant");

export type GovernedParsedSolanaSigningGrant = {
  readonly [governedParsedSolanaGrant]: true;
  readonly agentId: string;
  readonly broadcast: boolean;
  readonly chainId: number;
  readonly executionPayloadDigest: string;
  readonly messageDigest: string;
  readonly tenantId: string;
};

export function createGovernedParsedSolanaSigningGrant(input: {
  agentId: string;
  broadcast: boolean;
  chainId: number;
  executionPayloadDigest: string;
  messageDigest: string;
  tenantId: string;
}): GovernedParsedSolanaSigningGrant {
  return Object.freeze({
    [governedParsedSolanaGrant]: true as const,
    ...input,
  });
}

export function assertGovernedParsedSolanaSigningGrant(
  grant: GovernedParsedSolanaSigningGrant | undefined,
  request: {
    agentId: string;
    broadcast?: boolean;
    chainId?: number;
    tenantId: string;
    transaction: string;
  },
): void {
  if (
    !grant ||
    grant[governedParsedSolanaGrant] !== true ||
    grant.tenantId !== request.tenantId ||
    grant.agentId !== request.agentId ||
    grant.chainId !== (request.chainId ?? 101) ||
    grant.broadcast !== (request.broadcast !== false) ||
    !grant.executionPayloadDigest ||
    grant.messageDigest !== normalizedSolanaMessageDigest(request.transaction)
  ) {
    throw new Error("Parsed Solana signing requires a matching governed execution grant");
  }
}
