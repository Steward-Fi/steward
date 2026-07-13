export type OutputFormat = "json" | "pretty";

export function printJson(value: unknown): void {
  console.log(JSON.stringify(value, null, 2));
}

export function printResult(value: unknown, format: OutputFormat): void {
  if (format === "json") {
    printJson(value);
    return;
  }
  if (typeof value === "string") {
    console.log(value);
    return;
  }
  printJson(value);
}

/**
 * Describe a secret's presence and shape WITHOUT ever emitting any substring of
 * its value. Reports only: present/missing and the byte length. This is safe to
 * print in doctor output (pretty or JSON) and in logs — no portion of the
 * master password, Ed25519 seed, or any other secret is ever revealed.
 *
 * Deliberately never returns the first/last characters of the value: even a
 * handful of leaked chars materially reduces brute-force cost and can identify
 * a rotated-but-reused secret across environments.
 */
export function describeSecret(value: string | undefined): string {
  if (value === undefined || value === "") return "missing";
  const bytes = Buffer.byteLength(value, "utf8");
  return `present (${bytes} bytes)`;
}
