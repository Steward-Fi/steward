import { describe, expect, test } from "bun:test";
import { StewardClient } from "@stwd/sdk";
import * as React from "react";
import { renderToString } from "react-dom/server";

const { StewardGlobalWalletConsent } = await import("../components/StewardGlobalWalletConsent.js");
const { StewardProvider, StewardAuthContext } = await import("../provider.js");

function authContext() {
  return {
    isAuthenticated: true,
    isLoading: false,
    user: { id: "user-1", email: "user@example.test" },
    session: { token: "token", address: "0x123", tenantId: "personal-user-1" },
    providers: null,
    isProvidersLoading: false,
    signOut: () => {},
    getToken: () => "token",
  } as React.ContextType<typeof StewardAuthContext>;
}

function wrap(node: React.ReactNode) {
  return React.createElement(
    StewardProvider,
    {
      client: new StewardClient({ baseUrl: "https://api.steward.example" }),
      agentId: "agent-1",
    },
    React.createElement(StewardAuthContext.Provider, { value: authContext() }, node),
  );
}

describe("<StewardGlobalWalletConsent />", () => {
  test("renders app, wallet, and requested permissions from a preloaded consent request", () => {
    const html = renderToString(
      wrap(
        React.createElement(StewardGlobalWalletConsent, {
          appId: "tenant/client",
          initialRequest: {
            app: {
              id: "client",
              appId: "tenant/client",
              tenantId: "tenant",
              name: "Example App",
              environment: "production",
              origin: "https://app.example.test",
              redirectUri: "https://app.example.test/callback",
            },
            requestedScopes: ["eth_accounts"],
            wallet: {
              agentId: "user-wallet-user-1",
              address: "0x1111111111111111111111111111111111111111",
            },
            consent: null,
          },
        }),
      ),
    );
    expect(html).toContain("connect global wallet");
    expect(html).toContain("Example App");
    expect(html).toContain("0x1111111111111111111111111111111111111111");
    expect(html).toContain("eth_accounts");
    expect(html).toContain("approve");
  });
});
