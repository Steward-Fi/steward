import { describe, expect, test } from "bun:test";
import { boolFlag, parseArgs, parseJsonFlag, required, stringFlag } from "../args";

describe("CLI argument parsing", () => {
  test("parses positional args, booleans, values, and equals syntax", () => {
    const parsed = parseArgs([
      "tenant",
      "create",
      "--id",
      "acme",
      "--json",
      "--api-url=http://localhost:3200",
    ]);

    expect(parsed.positional).toEqual(["tenant", "create"]);
    expect(stringFlag(parsed.flags, "id")).toBe("acme");
    expect(boolFlag(parsed.flags, "json")).toBe(true);
    expect(stringFlag(parsed.flags, "api-url")).toBe("http://localhost:3200");
  });

  test("validates required flags and JSON flags", () => {
    const parsed = parseArgs(["policy", "set", "--rules", '[{"type":"spend_limit"}]']);
    expect(required(stringFlag(parsed.flags, "rules"), "rules")).toStartWith("[");
    expect(parseJsonFlag<Array<{ type: string }>>(parsed.flags, "rules", [])).toEqual([
      { type: "spend_limit" },
    ]);
    expect(() => required(undefined, "name")).toThrow("Missing required --name");
  });
});
