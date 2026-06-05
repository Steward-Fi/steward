import { describe, expect, it } from "bun:test";
import { classifyEndpoint, compareOpenApiSpecs, listEndpoints } from "../privy-openapi-parity";

describe("privy-openapi-parity", () => {
  it("classifies endpoint surfaces from paths, operation ids, and tags", () => {
    expect(
      classifyEndpoint({
        method: "post",
        path: "/v1/wallets/{wallet_id}/rpc",
        operationId: "sendWalletRpc",
        tags: ["Wallets"],
      }),
    ).toBe("wallets");
    expect(
      classifyEndpoint({
        method: "post",
        path: "/v1/policies/{policy_id}/rules",
        operationId: "createPolicyRule",
        tags: [],
      }),
    ).toBe("policies");
    expect(
      classifyEndpoint({
        method: "get",
        path: "/v1/opaque-provider-resource",
        operationId: "listMysteryResources",
        tags: [],
      }),
    ).toBe("unknown");
  });

  it("lists supported OpenAPI methods with their classified surfaces", () => {
    const endpoints = listEndpoints({
      paths: {
        "/v1/users": {
          get: { operationId: "listUsers" },
          post: { operationId: "createUser" },
        },
        "/v1/users/{id}": {
          delete: { operationId: "deleteUser" },
        },
      },
    });

    expect(endpoints).toEqual([
      {
        method: "get",
        path: "/v1/users",
        operationId: "listUsers",
        tags: [],
        surface: "users",
      },
      {
        method: "post",
        path: "/v1/users",
        operationId: "createUser",
        tags: [],
        surface: "users",
      },
      {
        method: "delete",
        path: "/v1/users/{id}",
        operationId: "deleteUser",
        tags: [],
        surface: "users",
      },
    ]);
  });

  it("reports covered and missing Privy surfaces against Steward OpenAPI", () => {
    const privy = {
      paths: {
        "/v1/users": { get: { operationId: "listUsers" } },
        "/v1/wallets": { post: { operationId: "createWallet" } },
        "/v1/policies": { get: { operationId: "listPolicies" } },
        "/v1/unknown-provider": { get: { operationId: "listProviderSpecificThings" } },
      },
    };
    const steward = {
      paths: {
        "/platform/tenants/{tenantId}/users": { get: { operationId: "listTenantUsers" } },
        "/agents": { post: { operationId: "createWallet" } },
        "/agents/{agentId}/policies": { get: { operationId: "listPolicies" } },
      },
    };

    const report = compareOpenApiSpecs(privy, steward);
    expect(report.privyEndpointCount).toBe(4);
    expect(report.stewardEndpointCount).toBe(3);
    expect(report.surfaces.find((surface) => surface.surface === "users")?.status).toBe("covered");
    expect(report.surfaces.find((surface) => surface.surface === "wallets")?.status).toBe(
      "covered",
    );
    expect(report.surfaces.find((surface) => surface.surface === "unknown")?.status).toBe("gap");
  });
});
