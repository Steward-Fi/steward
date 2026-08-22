import { afterAll, beforeEach, describe, expect, mock, test } from "bun:test";
import { resolve } from "node:path";
import { chromium } from "@playwright/test";
import { Window } from "happy-dom";
import * as React from "react";
import { createRoot, type Root } from "react-dom/client";

const window = new Window({ url: "https://steward.test/accept-invitation" });
Object.assign(globalThis, {
  window,
  document: window.document,
  navigator: window.navigator,
  HTMLElement: window.HTMLElement,
  IS_REACT_ACT_ENVIRONMENT: true,
});

type AuthState = {
  activeTenantId: string | null;
  getToken: () => string | null;
  isAuthenticated: boolean;
  session: { token: string } | null;
  user: { id: string } | null;
};

let authState: AuthState;
const installedTokens: string[] = [];
let clearedTokens = 0;
let currentToken: string | null = null;
let observedProviderAuth: Record<string, unknown> | undefined;

mock.module("@stwd/react", () => ({
  StewardProvider: ({
    auth,
    children,
  }: {
    auth: Record<string, unknown>;
    children: React.ReactNode;
  }) => {
    observedProviderAuth = auth;
    return React.createElement(React.Fragment, null, children);
  },
  useAuth: () => authState,
}));
mock.module("next/navigation", () => ({ usePathname: () => "/accept-invitation" }));
mock.module("@/lib/api", () => ({
  clearAuthToken: () => {
    clearedTokens += 1;
    currentToken = null;
  },
  setAuthToken: (token: string) => {
    installedTokens.push(token);
    currentToken = token;
  },
  steward: {},
}));

const { AuthTokenSync, Providers } = await import("./providers");

let container: HTMLDivElement;
let root: Root | null = null;

function setAuth(overrides: Partial<AuthState> = {}): void {
  authState = {
    activeTenantId: null,
    getToken: () => null,
    isAuthenticated: false,
    session: null,
    user: null,
    ...overrides,
  };
}

async function render(node: React.ReactNode): Promise<void> {
  await React.act(async () => root?.render(node));
}

beforeEach(async () => {
  if (root) await React.act(async () => root?.unmount());
  container = window.document.createElement("div") as unknown as HTMLDivElement;
  window.document.body.replaceChildren(container as never);
  window.sessionStorage.clear();
  root = createRoot(container);
  installedTokens.length = 0;
  clearedTokens = 0;
  currentToken = null;
  observedProviderAuth = undefined;
  setAuth();
});

afterAll(async () => {
  if (root) await React.act(async () => root?.unmount());
  window.close();
});

describe("mounted AuthTokenSync epochs", () => {
  test("installs the concrete session token before descendant passive loads", async () => {
    const observedByChild: string[][] = [];
    function Child() {
      React.useEffect(() => {
        observedByChild.push([...installedTokens]);
      }, []);
      return null;
    }
    setAuth({
      activeTenantId: "tenant-a",
      getToken: () => "fallback-must-not-win",
      isAuthenticated: true,
      session: { token: "session-a" },
    });

    await render(
      <AuthTokenSync>
        <Child />
      </AuthTokenSync>,
    );

    expect(installedTokens).toEqual(["session-a"]);
    expect(observedByChild).toEqual([["session-a"]]);
  });

  test("rotates tenant, user, and session epochs once in one retained document", async () => {
    const descendantActions: Array<string | null> = [];
    function Child({ epoch }: { epoch: number }) {
      React.useEffect(() => {
        descendantActions.push(currentToken);
      }, [epoch]);
      return null;
    }
    setAuth({
      activeTenantId: "tenant-a",
      getToken: () => "old-fallback",
      isAuthenticated: true,
      session: { token: "session-a" },
      user: { id: "user-a" },
    });
    await render(
      <AuthTokenSync>
        <Child epoch={1} />
      </AuthTokenSync>,
    );

    setAuth({
      activeTenantId: "tenant-b",
      getToken: () => {
        throw new Error("a delayed fallback must not be consulted when a concrete session exists");
      },
      isAuthenticated: true,
      session: { token: "session-b" },
      user: { id: "user-a" },
    });
    await render(
      <AuthTokenSync>
        <Child epoch={2} />
      </AuthTokenSync>,
    );

    setAuth({
      activeTenantId: "tenant-b",
      getToken: () => "stale-user-fallback",
      isAuthenticated: true,
      session: { token: "session-c" },
      user: { id: "user-b" },
    });
    await render(
      <AuthTokenSync>
        <Child epoch={3} />
      </AuthTokenSync>,
    );

    setAuth({
      activeTenantId: "tenant-b",
      getToken: () => "stale-session-fallback",
      isAuthenticated: true,
      session: { token: "session-d" },
      user: { id: "user-b" },
    });
    await render(
      <AuthTokenSync>
        <Child epoch={4} />
      </AuthTokenSync>,
    );
    await render(
      <AuthTokenSync>
        <Child epoch={4} />
      </AuthTokenSync>,
    );

    expect(installedTokens).toEqual(["session-a", "session-b", "session-c", "session-d"]);
    expect(descendantActions).toEqual(["session-a", "session-b", "session-c", "session-d"]);
  });

  test("clears the legacy client before signed-out descendant actions", async () => {
    const observedByChild: number[] = [];
    function Child({ epoch }: { epoch: number }) {
      React.useEffect(() => {
        observedByChild.push(clearedTokens);
      }, [epoch]);
      return null;
    }
    setAuth({ isAuthenticated: true, session: { token: "session-a" } });
    await render(
      <AuthTokenSync>
        <Child epoch={1} />
      </AuthTokenSync>,
    );

    setAuth();
    await render(
      <AuthTokenSync>
        <Child epoch={2} />
      </AuthTokenSync>,
    );

    expect(clearedTokens).toBe(1);
    expect(observedByChild.at(-1)).toBe(1);
  });
});

async function buildBrowserAuthSyncHarness(): Promise<string> {
  const providersPath = resolve(import.meta.dir, "providers.tsx");
  const entry = `
    import React, { useEffect } from "react";
    import { flushSync } from "react-dom";
    import { createRoot } from "react-dom/client";
    import { AuthTokenSync } from ${JSON.stringify(providersPath)};

    const root = createRoot(document.getElementById("root"));
    window.__authState = {
      activeTenantId: null,
      getToken: () => null,
      isAuthenticated: false,
      session: null,
      user: null,
    };
    window.__authObservations = { actions: [], clears: 0, current: null, installed: [] };

    function Descendant({ epoch }) {
      useEffect(() => {
        window.__authObservations.actions.push({
          clears: window.__authObservations.clears,
          epoch,
          token: window.__authObservations.current,
        });
      }, [epoch]);
      return React.createElement("button", {
        id: "descendant-action",
        onClick: () => window.__authObservations.actions.push({
          clears: window.__authObservations.clears,
          epoch: "click",
          token: window.__authObservations.current,
        }),
      }, "use auth");
    }

    window.__renderAuthEpoch = async (auth, epoch) => {
      window.__authState = { ...auth, getToken: () => auth.fallbackToken ?? null };
      flushSync(() => root.render(
        React.createElement(AuthTokenSync, null, React.createElement(Descendant, { epoch })),
      ));
      await new Promise((resolve) => setTimeout(resolve, 0));
    };
    window.__supersedeAuthEpoch = async (staleAuth, currentAuth, epoch) => {
      window.__authState = { ...staleAuth, getToken: () => staleAuth.fallbackToken ?? null };
      root.render(React.createElement(
        AuthTokenSync,
        null,
        React.createElement(Descendant, { epoch: epoch - 1 }),
      ));
      window.__authState = { ...currentAuth, getToken: () => currentAuth.fallbackToken ?? null };
      flushSync(() => root.render(
        React.createElement(AuthTokenSync, null, React.createElement(Descendant, { epoch })),
      ));
      await new Promise((resolve) => setTimeout(resolve, 0));
    };
  `;
  const modules = new Map([
    [
      "@stwd/react",
      `
        import React from "react";
        export function StewardProvider({ children }) { return React.createElement(React.Fragment, null, children); }
        export function useAuth() { return window.__authState; }
      `,
    ],
    ["next/navigation", 'export function usePathname() { return "/accept-invitation"; }'],
    [
      "@/lib/api",
      `
        export const steward = {};
        export function clearAuthToken() {
          window.__authObservations.clears += 1;
          window.__authObservations.current = null;
        }
        export function setAuthToken(token) {
          window.__authObservations.installed.push(token);
          window.__authObservations.current = token;
        }
      `,
    ],
    ["@/lib/steward-api-url", 'export const STEWARD_API_URL = "https://api.example.test";'],
    ["@simplewebauthn/browser", "export {};"],
    [
      "@stwd/react/wallet",
      `
        import React from "react";
        export function EVMWalletProvider({ children }) { return React.createElement(React.Fragment, null, children); }
        export function SolanaWalletProvider({ children }) { return React.createElement(React.Fragment, null, children); }
      `,
    ],
    [
      "@/lib/wagmi",
      'export function getWagmiConfig() { return {}; } export const SOLANA_RPC_URL = "";',
    ],
  ]);
  const result = await Bun.build({
    entrypoints: ["auth-sync-browser-entry"],
    format: "esm",
    minify: false,
    plugins: [
      {
        name: "auth-sync-browser-harness",
        setup(build) {
          build.onResolve({ filter: /^auth-sync-browser-entry$/ }, () => ({
            namespace: "auth-sync-browser",
            path: "entry",
          }));
          build.onLoad({ filter: /.*/, namespace: "auth-sync-browser" }, () => ({
            contents: entry,
            loader: "tsx",
          }));
          build.onResolve({ filter: /.*/ }, ({ path }) =>
            modules.has(path) ? { namespace: "auth-sync-mock", path } : undefined,
          );
          build.onLoad({ filter: /.*/, namespace: "auth-sync-mock" }, ({ path }) => ({
            contents: modules.get(path) as string,
            loader: "tsx",
          }));
        },
      },
    ],
    splitting: false,
    target: "browser",
  });
  if (!result.success || !result.outputs[0]) {
    throw new Error(
      result.logs.map((log) => log.message).join("\n") || "browser harness build failed",
    );
  }
  return result.outputs[0].text();
}

describe("browser AuthTokenSync effect ordering", () => {
  test("a retained Chromium document never exposes a stale epoch to descendant actions", async () => {
    const browser = await chromium.launch({ headless: true });
    try {
      const page = await browser.newPage();
      await page.setContent('<div id="root"></div>');
      await page.addScriptTag({ content: await buildBrowserAuthSyncHarness(), type: "module" });
      await page.waitForFunction(
        () =>
          typeof (window as never as { __renderAuthEpoch?: unknown }).__renderAuthEpoch ===
          "function",
      );

      const renderEpoch = (auth: Record<string, unknown>, epoch: number) =>
        page.evaluate(
          async ({ nextAuth, nextEpoch }) => {
            await (
              window as never as {
                __renderAuthEpoch: (
                  value: Record<string, unknown>,
                  valueEpoch: number,
                ) => Promise<void>;
              }
            ).__renderAuthEpoch(nextAuth, nextEpoch);
          },
          { nextAuth: auth, nextEpoch: epoch },
        );

      await renderEpoch(
        {
          activeTenantId: "tenant-a",
          fallbackToken: "stale-a",
          isAuthenticated: true,
          session: { token: "session-a" },
          user: { id: "user-a" },
        },
        1,
      );
      await renderEpoch(
        {
          activeTenantId: "tenant-b",
          fallbackToken: "stale-b",
          isAuthenticated: true,
          session: { token: "session-b" },
          user: { id: "user-b" },
        },
        2,
      );
      await page.locator("#descendant-action").click();
      await renderEpoch(
        {
          activeTenantId: "tenant-b",
          fallbackToken: "stale-c",
          isAuthenticated: true,
          session: { token: "session-c" },
          user: { id: "user-b" },
        },
        3,
      );
      await page.evaluate(async () => {
        await (
          window as never as {
            __supersedeAuthEpoch: (
              stale: Record<string, unknown>,
              current: Record<string, unknown>,
              epoch: number,
            ) => Promise<void>;
          }
        ).__supersedeAuthEpoch(
          {
            activeTenantId: "tenant-stale",
            fallbackToken: "stale-fallback",
            isAuthenticated: true,
            session: { token: "session-must-not-win" },
            user: { id: "user-stale" },
          },
          {
            activeTenantId: "tenant-b",
            fallbackToken: "current-fallback",
            isAuthenticated: true,
            session: { token: "session-current" },
            user: { id: "user-b" },
          },
          4,
        );
      });
      await renderEpoch(
        {
          activeTenantId: null,
          fallbackToken: "stale-signed-out",
          isAuthenticated: false,
          session: null,
          user: null,
        },
        5,
      );
      await page.locator("#descendant-action").click();

      const observations = await page.evaluate(
        () =>
          (
            window as never as {
              __authObservations: {
                actions: Array<{ clears: number; epoch: number | string; token: string | null }>;
                clears: number;
                current: string | null;
                installed: string[];
              };
            }
          ).__authObservations,
      );
      expect(observations.installed).toEqual([
        "session-a",
        "session-b",
        "session-c",
        "session-current",
      ]);
      expect(observations.current).toBeNull();
      expect(observations.clears).toBe(1);
      expect(observations.actions).toEqual([
        { clears: 0, epoch: 1, token: "session-a" },
        { clears: 0, epoch: 2, token: "session-b" },
        { clears: 0, epoch: "click", token: "session-b" },
        { clears: 0, epoch: 3, token: "session-c" },
        { clears: 0, epoch: 4, token: "session-current" },
        { clears: 1, epoch: 5, token: null },
        { clears: 1, epoch: "click", token: null },
      ]);
    } finally {
      await browser.close();
    }
  });
});

describe("mounted refresh-token custody", () => {
  test.each([
    ["authenticated", { isAuthenticated: true, session: { token: "session-a" } }],
    ["authentication failure", { isAuthenticated: false, session: null }],
  ] as const)("uses the same-origin proxy and removes legacy material after %s", async (_name, state) => {
    window.sessionStorage.setItem("steward_refresh_token", "must-not-survive");
    setAuth(state);

    await render(<Providers>child</Providers>);

    expect(observedProviderAuth?.authProxyUrl).toBe("/api/auth");
    expect(window.sessionStorage.getItem("steward_refresh_token")).toBeNull();
  });
});
