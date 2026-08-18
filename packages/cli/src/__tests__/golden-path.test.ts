import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// packages/cli/src/__tests__ -> repo root is four levels up.
const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
const SCRIPT_PATH = join(REPO_ROOT, "scripts", "golden-path.sh");

function sourceLines(): { lineNo: number; text: string }[] {
  const raw = readFileSync(SCRIPT_PATH, "utf8");
  return raw.split(/\r?\n/).map((text, i) => ({ lineNo: i + 1, text }));
}

// Strip a trailing shell comment so prose that legitimately references the
// variable name (e.g. "Do NOT interpolate $TENANT_KEY here") is not flagged.
// Naive but sufficient: the script uses no `#` inside string literals that we
// care about for these output lines.
function stripComment(line: string): string {
  const hashIdx = line.indexOf("#");
  return hashIdx === -1 ? line : line.slice(0, hashIdx);
}

describe("golden-path.sh secrecy", () => {
  test("no output statement interpolates the supplied TENANT_KEY", () => {
    // Guard against regressions where an error/success message echoes the raw
    // operator-supplied tenant API key into stderr/stdout (terminal scrollback,
    // CI logs, screen-shares). The key may only be READ (conditionals) and
    // PASSED to the CLI as an argument, never printed.
    const interpolation = /\$\{?TENANT_KEY\b/;
    const printsToStream = /^\s*(echo|printf)\b/;

    const offenders = sourceLines()
      .map(({ lineNo, text }) => ({ lineNo, code: stripComment(text) }))
      .filter(({ code }) => printsToStream.test(code) && interpolation.test(code));

    expect(offenders).toEqual([]);
  });

  test("placeholder rejection uses the static guidance message", () => {
    const raw = readFileSync(SCRIPT_PATH, "utf8");
    // The exact static message must be present so the rejection path always
    // gives actionable guidance without leaking the supplied value.
    expect(raw).toContain(
      "STEWARD_GOLDEN_TENANT_KEY looks like a placeholder; generate a real tenant key.",
    );
    // Error output must not echo the supplied tenant key.
    expect(raw).not.toContain("looks like a placeholder ('$TENANT_KEY')");
  });
});
