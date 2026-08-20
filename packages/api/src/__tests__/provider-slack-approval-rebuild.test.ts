import { describe, expect, test } from "bun:test";
import { buildSlackAction, type SlackOperationKey } from "@stwd/provider-slack";
import { jcsStringify } from "@stwd/shared";
import { __rebuildApprovedActionForTests } from "../services/provider-action-service";

describe("Slack approval-time canonical reconstruction", () => {
  const cases: Array<[SlackOperationKey, Record<string, unknown>]> = [
    [
      "slack.chat.postMessage",
      {
        channel: "C12345678",
        text: "approved payload",
        blocks: [{ type: "section", text: { type: "plain_text", text: "hello" } }],
        thread_ts: "1234567890.123456",
      },
    ],
    [
      "slack.conversations.list",
      { types: ["private_channel", "public_channel"], limit: 25, cursor: "next_page=" },
    ],
    ["slack.users.info", { user: "U12345678" }],
  ];

  for (const [operationKey, args] of cases) {
    test(`${operationKey} rebuilds the exact approved canonical action`, () => {
      const original = buildSlackAction(operationKey, args);
      const rebuilt = __rebuildApprovedActionForTests(
        operationKey,
        original.action as unknown as Record<string, unknown>,
        original.safeSummary,
      );
      expect(jcsStringify(rebuilt.action)).toBe(jcsStringify(original.action));
      expect(rebuilt.policyArgs).toEqual(original.policyArgs);
      expect(rebuilt.safeSummary).toEqual(original.safeSummary);
    });
  }
});
