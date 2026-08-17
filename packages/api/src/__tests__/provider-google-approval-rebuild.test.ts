import { describe, expect, test } from "bun:test";
import { buildGoogleAction, type GoogleOperationKey } from "@stwd/provider-google";
import { jcsStringify } from "@stwd/shared";
import { __rebuildApprovedActionForTests } from "../services/provider-action-service";

describe("Google approval-time canonical reconstruction", () => {
  const cases: Array<[GoogleOperationKey, Record<string, unknown>]> = [
    [
      "google.gmail.messages.send",
      {
        to: ["alice@example.com", "bob@example.net"],
        subject: "Approved subject",
        body: "Approved body\nwith a second line",
      },
    ],
    [
      "google.calendar.events.list",
      {
        timeMin: "2026-08-17T00:00:00.000Z",
        timeMax: "2026-08-18T00:00:00.000Z",
        maxResults: 25,
        pageToken: "next_page=",
      },
    ],
    [
      "google.calendar.events.insert",
      {
        summary: "Approved meeting",
        start: "2026-08-17T10:00:00.000Z",
        end: "2026-08-17T11:00:00.000Z",
        attendees: ["alice@example.com", "bob@example.net"],
      },
    ],
  ];

  for (const [operationKey, args] of cases) {
    test(`${operationKey} rebuilds the exact approved canonical action`, () => {
      const original = buildGoogleAction(operationKey, args);
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
