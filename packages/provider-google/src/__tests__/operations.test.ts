import { describe, expect, it } from "bun:test";
import { buildGoogleAction } from "../operations";

describe("Google governed operations", () => {
  it("derives recipient-domain policy args without exposing message content", () => {
    const b = buildGoogleAction("google.gmail.messages.send", {
      to: ["A@Example.com", "b@other.test"],
      subject: "Board",
      body: "canary-secret-body",
    });
    expect(b.policyArgs).toEqual({
      toDomainSet: ["example.com", "other.test"],
      hasAttachment: false,
      subjectLength: 5,
    });
    expect(JSON.stringify(b.safeSummary)).not.toContain("canary-secret-body");
    expect(JSON.stringify(b.safeSummary)).not.toContain("A@Example.com");
  });
  it("fails closed on recipient injection, unknown args, and invalid time ranges", () => {
    expect(() =>
      buildGoogleAction("google.gmail.messages.send", {
        to: ["a@example.com\r\nBcc: evil@x.test"],
        subject: "x",
        body: "x",
      }),
    ).toThrow();
    expect(() =>
      buildGoogleAction("google.gmail.messages.send", {
        to: ["a@example.com"],
        subject: "x",
        body: "x",
        raw: "escape",
      }),
    ).toThrow();
    expect(() =>
      buildGoogleAction("google.calendar.events.insert", {
        summary: "x",
        start: "2026-01-02T00:00:00Z",
        end: "2026-01-01T00:00:00Z",
      }),
    ).toThrow();
  });
  it("canonicalizes list queries independent of caller key order", () => {
    const a = buildGoogleAction("google.calendar.events.list", {
      maxResults: 10,
      timeMin: "2026-01-01T00:00:00Z",
    });
    expect(a.action.orderedQueryPairs).toEqual([
      ["maxResults", "10"],
      ["timeMin", "2026-01-01T00:00:00Z"],
    ]);
  });
  it("rejects date-like values that are not strict RFC3339 instants", () => {
    for (const invalid of [
      "2026-01-02T00:00:00",
      "2026-02-30T00:00:00Z",
      "2026-01-02 00:00:00Z",
      "2026-01-02T00:00:00+15:00",
    ]) {
      expect(() => buildGoogleAction("google.calendar.events.list", { timeMin: invalid })).toThrow(
        "timeMin must be RFC3339",
      );
    }
  });
});
