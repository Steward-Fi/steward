import type { Tenant } from "@steward/db";

export interface AuthContext {
  tenantId: string;
  tenant: Tenant;
}

export interface ApiKeyPair {
  key: string;
  hash: string;
}

export type AuthVariables = AuthContext;
