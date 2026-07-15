export const PROVIDER_ENVIRONMENTS = ["development", "staging", "production"] as const;
export type ProviderEnvironment = (typeof PROVIDER_ENVIRONMENTS)[number];

export const PROVIDER_AUTHORITY_STATUSES = ["active", "disabled", "revoked"] as const;
export type ProviderAuthorityStatus = (typeof PROVIDER_AUTHORITY_STATUSES)[number];

export const PROVIDER_ROLES = [
  "tenant_authority_admin",
  "workspace_admin",
  "workspace_operator",
  "workspace_viewer",
  "workspace_approver",
] as const;
export type ProviderRole = (typeof PROVIDER_ROLES)[number];

export const PROVIDER_PRINCIPAL_TYPES = ["human", "agent"] as const;
export type ProviderPrincipalType = (typeof PROVIDER_PRINCIPAL_TYPES)[number];

export const PROVIDER_RISK_CLASSES = ["read", "write", "consequential"] as const;
export type ProviderRiskClass = (typeof PROVIDER_RISK_CLASSES)[number];

/** Every repository lookup carries this scope. organizationId is tenantId in v1. */
export interface TenantWorkspaceScope {
  tenantId: string;
  workspaceId: string;
}

export interface ProviderAccessRequestV1 {
  tenantId: string;
  workspaceId: string;
  actor: { type: ProviderPrincipalType; id: string };
  providerAccountId: string;
  operationKey: string;
  environment: ProviderEnvironment;
  evaluatedAt: string;
}

export interface ProviderAccessDecisionV1 {
  decisionId: string;
  effect: "allow" | "deny";
  reasonCode: string;
  matchedBindingIds: string[];
  matchedGrantIds: string[];
  dependencyRevisions: {
    actor: number;
    workspace: number;
    providerAccount: number;
    operation: number;
    bindings: Array<{ id: string; revision: number }>;
    grants: Array<{ id: string; revision: number }>;
  };
  decidedAt: string;
}

export const PROVIDER_ACCESS_REASON = {
  ALLOWED: "provider_access_allowed",
  ACTOR_INACTIVE: "actor_inactive",
  RESOURCE_NOT_FOUND: "resource_not_found",
  RESOURCE_INACTIVE: "resource_inactive",
  NO_MATCHING_AUTHORITY: "no_matching_authority",
} as const;

export interface ProviderAuthorityMutationContext {
  tenantId: string;
  actorUserId: string;
  tenantRole: string;
  mfaVerifiedAt: number;
  idempotencyKey: string;
  expectedRevision: number;
  reason: string;
  requestId?: string;
}
