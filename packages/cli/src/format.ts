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

export function redact(value: string | undefined): string {
  if (!value) return "missing";
  if (value.length <= 10) return "***";
  return `${value.slice(0, 6)}...${value.slice(-4)}`;
}
