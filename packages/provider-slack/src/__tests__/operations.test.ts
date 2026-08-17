import { describe, expect, test } from "bun:test";
import { CanonError } from "@stwd/shared";
import { buildSlackAction } from "../operations";

describe("Slack provider actions", () => {
  test("builds postMessage with channel as a policy argument and no content leakage", () => {
    const built = buildSlackAction("slack.chat.postMessage", {
      channel: "C12345678",
      text: "quarterly secret",
      blocks: [{ type: "section", text: { type: "mrkdwn", text: "hello" } }],
      thread_ts: "1712345678.123456",
    });
    expect(built.action).toMatchObject({
      profile: "slack.provider-action.v1",
      origin: "https://slack.com",
      normalizedPath: "/api/chat.postMessage",
    });
    expect(built.policyArgs).toEqual({ channel: "C12345678", hasBlocks: true, textLength: 16 });
    expect(JSON.stringify(built.safeSummary)).not.toContain("quarterly secret");
  });

  test("builds bounded read operations", () => {
    expect(
      buildSlackAction("slack.conversations.list", {
        types: ["private_channel", "public_channel"],
        limit: 100,
      }).action.orderedQueryPairs,
    ).toEqual([
      ["limit", "100"],
      ["types", "private_channel,public_channel"],
    ]);
    expect(buildSlackAction("slack.users.info", { user: "U12345678" }).policyArgs).toEqual({
      user: "U12345678",
    });
  });

  test("fails closed on unknown, malformed, and credential-shaped inputs", () => {
    for (const args of [
      { channel: "#general", text: "hello" },
      { channel: "C12345678", text: "hello", token: "xoxb-canary" },
      { channel: "C12345678", blocks: [{ type: "section", accessToken: "canary" }] },
    ]) {
      expect(() => buildSlackAction("slack.chat.postMessage", args)).toThrow(CanonError);
    }
  });
});
