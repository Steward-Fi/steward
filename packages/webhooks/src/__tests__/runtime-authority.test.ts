import { describe, expect, it } from "bun:test";
import { withRuntimeEnvironment } from "@stwd/shared/runtime-env";
import { currentWebhookRuntimeAuthority } from "../runtime-authority";

const insecureName = "STEWARD_ALLOW_INSECURE_WEBHOOK_URLS";
const privateName = "STEWARD_ALLOW_PRIVATE_WEBHOOK_NETWORKS";

describe("webhook runtime authority", () => {
  it("uses current Bun process values when no request snapshot exists", () => {
    const priorInsecure = process.env[insecureName];
    const priorPrivate = process.env[privateName];
    try {
      process.env[insecureName] = "true";
      process.env[privateName] = "true";
      expect(currentWebhookRuntimeAuthority()).toEqual({
        allowInsecureHttp: true,
        allowPrivateNetwork: true,
      });

      delete process.env[insecureName];
      delete process.env[privateName];
      expect(currentWebhookRuntimeAuthority()).toEqual({
        allowInsecureHttp: false,
        allowPrivateNetwork: false,
      });
    } finally {
      if (priorInsecure === undefined) delete process.env[insecureName];
      else process.env[insecureName] = priorInsecure;
      if (priorPrivate === undefined) delete process.env[privateName];
      else process.env[privateName] = priorPrivate;
    }
  });

  it("does not fall back to stale process values inside a Worker request", () => {
    const priorInsecure = process.env[insecureName];
    const priorPrivate = process.env[privateName];
    try {
      process.env[insecureName] = "true";
      process.env[privateName] = "true";
      expect(withRuntimeEnvironment({}, () => currentWebhookRuntimeAuthority())).toEqual({
        allowInsecureHttp: false,
        allowPrivateNetwork: false,
      });
    } finally {
      if (priorInsecure === undefined) delete process.env[insecureName];
      else process.env[insecureName] = priorInsecure;
      if (priorPrivate === undefined) delete process.env[privateName];
      else process.env[privateName] = priorPrivate;
    }
  });
});
