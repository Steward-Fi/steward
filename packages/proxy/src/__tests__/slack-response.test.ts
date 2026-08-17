import { describe, expect, test } from "bun:test";
import { classifySlackWebApiPayload } from "../handlers/proxy";

describe("Slack Web API response semantics", () => {
  test("requires explicit ok:true even when HTTP transport succeeded", () => {
    expect(classifySlackWebApiPayload('{"ok":true,"ts":"1712345678.123456"}')).toBeNull();
    expect(classifySlackWebApiPayload('{"ok":false,"error":"channel_not_found"}')).toBe(
      "channel_not_found",
    );
    expect(classifySlackWebApiPayload('{"error":"missing_ok"}')).toBe("missing_ok");
    expect(classifySlackWebApiPayload("not json")).toBe("invalid_response");
    expect(classifySlackWebApiPayload('{"ok":false,"error":"token leaked: xoxb-secret"}')).toBe(
      "invalid_response",
    );
  });
});
