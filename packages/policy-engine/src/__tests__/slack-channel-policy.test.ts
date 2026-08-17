import { describe, expect, test } from "bun:test";
import {
  composeProviderActionPolicyDecision,
  type ProviderPolicyContext,
  type ProviderPolicyRule,
} from "../capability-intent";

const rule: ProviderPolicyRule = {
  id: "slack-channel-scope",
  type: "capability-intent",
  enabled: true,
  config: {
    capabilities: ["slack.chat.postMessage"],
    effect: "allow",
    constraints: { argEquals: { channel: "C12345678" } },
  },
};

function context(channel: string): ProviderPolicyContext {
  return {
    operationKey: "slack.chat.postMessage",
    args: { channel, hasBlocks: false, textLength: 5 },
    method: "POST",
    host: "slack.com",
    path: "/api/chat.postMessage",
    invokeCount1h: 0,
  };
}

describe("Slack channel policy scope", () => {
  test("channel belongs to capability-intent args, not the credential grant", () => {
    expect(composeProviderActionPolicyDecision([rule], context("C12345678")).effect).toBe("allow");
    expect(composeProviderActionPolicyDecision([rule], context("C99999999")).effect).toBe(
      "hard_deny",
    );
  });
});
