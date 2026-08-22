import { afterEach, beforeAll, beforeEach, describe, expect, mock, test } from "bun:test";
import { Window } from "happy-dom";
import * as React from "react";
import { createRoot, type Root } from "react-dom/client";

const browser = new Window({ url: "https://app.example.test/auth/callback" });
Object.assign(globalThis, {
  window: browser,
  document: browser.document,
  navigator: browser.navigator,
  HTMLElement: browser.HTMLElement,
  Event: browser.Event,
  IS_REACT_ACT_ENVIRONMENT: true,
});

const { StewardOAuthCallback } = await import("../components/StewardOAuthCallback.js");
const { StewardAuthContext } = await import("../provider.js");

let root: Root | null = null;
let container: HTMLDivElement;

function context(isAuthenticated = false) {
  return {
    isAuthenticated,
    isLoading: false,
    user: isAuthenticated ? { id: "user-1", email: "user@example.test" } : null,
    session: null,
  };
}

async function mount(
  href: string,
  props: Record<string, unknown> = {},
  isAuthenticated = false,
): Promise<void> {
  browser.location.href = href;
  container = browser.document.createElement("div") as unknown as HTMLDivElement;
  browser.document.body.replaceChildren(container as unknown as Node);
  root = createRoot(container);
  await React.act(async () => {
    root?.render(
      React.createElement(
        StewardAuthContext.Provider,
        {
          value: context(isAuthenticated) as unknown as React.ContextType<
            typeof StewardAuthContext
          >,
        },
        React.createElement(StewardOAuthCallback, props),
      ),
    );
  });
}

beforeAll(() => {
  Object.defineProperty(browser, "opener", { value: null, writable: true, configurable: true });
});

beforeEach(() => {
  browser.localStorage.clear();
  browser.sessionStorage.clear();
});

afterEach(async () => {
  if (root) await React.act(async () => root?.unmount());
  root = null;
  browser.opener = null;
  mock.restore();
});

describe("<StewardOAuthCallback /> mounted behavior", () => {
  for (const suffix of [
    "?token=access-secret&refreshToken=refresh-secret",
    "#token=access-secret&refreshToken=refresh-secret",
  ]) {
    test(`rejects token credentials in ${suffix.startsWith("#") ? "fragment" : "query"}`, async () => {
      const onError = mock((_error: Error) => {});
      const postMessage = mock(() => {});
      browser.opener = { postMessage } as unknown as Window;
      await mount(`https://app.example.test/auth/callback${suffix}`, { onError });
      expect(container.textContent).toContain("Token-in-URL OAuth callbacks are disabled");
      expect(onError).toHaveBeenCalledTimes(1);
      expect(postMessage).toHaveBeenCalledTimes(0);
      expect(browser.localStorage.length).toBe(0);
      expect(browser.sessionStorage.length).toBe(0);
    });
  }

  test("posts and reports one exact code/state result", async () => {
    const onSuccess = mock((_result: { code: string; state: string }) => {});
    const postMessage = mock(() => {});
    browser.opener = { postMessage } as unknown as Window;
    await mount("https://app.example.test/auth/callback?code=one-time-code&state=bound-state", {
      onSuccess,
    });
    expect(container.textContent).toContain("Signed in successfully");
    expect(postMessage).toHaveBeenCalledTimes(1);
    expect(postMessage).toHaveBeenCalledWith(
      { type: "steward-oauth-callback", code: "one-time-code", state: "bound-state" },
      "https://app.example.test",
    );
    expect(onSuccess).toHaveBeenCalledTimes(1);
    expect(onSuccess).toHaveBeenCalledWith({ code: "one-time-code", state: "bound-state" });
  });

  test("sanitizes provider errors and invokes the error callback once", async () => {
    const onError = mock((_error: Error) => {});
    const postMessage = mock(() => {});
    browser.opener = { postMessage } as unknown as Window;
    await mount(
      "https://app.example.test/auth/callback?error=access_denied&error_description=User%20cancelled",
      { onError },
    );
    expect(container.textContent).toContain("User cancelled");
    expect(postMessage).toHaveBeenCalledWith(
      { type: "steward-oauth-callback", error: "access_denied" },
      "https://app.example.test",
    );
    expect(onError).toHaveBeenCalledTimes(1);
    expect((onError.mock.calls[0]?.[0] as Error).message).toBe("User cancelled");
  });

  for (const suffix of ["", "?code=missing-state", "?state=missing-code", "?code=&state=x"]) {
    test(`rejects missing callback parameters (${suffix || "empty"})`, async () => {
      const onError = mock((_error: Error) => {});
      const onSuccess = mock(() => {});
      await mount(`https://app.example.test/auth/callback${suffix}`, { onError, onSuccess });
      expect(container.textContent).toContain("Missing authentication parameters");
      expect(onError).toHaveBeenCalledTimes(1);
      expect(onSuccess).toHaveBeenCalledTimes(0);
    });
  }

  test("succeeds without an opener and does not rerun after a prop refresh", async () => {
    const firstSuccess = mock(() => {});
    const laterSuccess = mock(() => {});
    await mount("https://app.example.test/auth/callback?code=code&state=state", {
      onSuccess: firstSuccess,
    });
    await React.act(async () => {
      root?.render(
        React.createElement(
          StewardAuthContext.Provider,
          {
            value: context(false) as unknown as React.ContextType<typeof StewardAuthContext>,
          },
          React.createElement(StewardOAuthCallback, { onSuccess: laterSuccess }),
        ),
      );
    });
    expect(firstSuccess).toHaveBeenCalledTimes(1);
    expect(laterSuccess).toHaveBeenCalledTimes(0);
  });

  test("already-authenticated mounts ignore callback parameters", async () => {
    const onSuccess = mock(() => {});
    const onError = mock(() => {});
    const postMessage = mock(() => {});
    browser.opener = { postMessage } as unknown as Window;
    await mount(
      "https://app.example.test/auth/callback?token=hostile&error=hostile&code=hostile&state=hostile",
      { onSuccess, onError },
      true,
    );
    expect(container.textContent).toContain("Signed in successfully");
    expect(onSuccess).toHaveBeenCalledTimes(0);
    expect(onError).toHaveBeenCalledTimes(0);
    expect(postMessage).toHaveBeenCalledTimes(0);
  });

  test("unmounting after completion does not duplicate callbacks", async () => {
    const onSuccess = mock(() => {});
    await mount("https://app.example.test/auth/callback?code=code&state=state", { onSuccess });
    await React.act(async () => root?.unmount());
    root = null;
    await Promise.resolve();
    expect(onSuccess).toHaveBeenCalledTimes(1);
  });
});
