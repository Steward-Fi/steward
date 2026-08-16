export type ParsedArgs = {
  positional: string[];
  flags: Record<string, string | boolean>;
};

export function parseArgs(argv: string[]): ParsedArgs {
  const positional: string[] = [];
  const flags: Record<string, string | boolean> = {};

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith("--")) {
      positional.push(arg);
      continue;
    }

    const raw = arg.slice(2);
    const eq = raw.indexOf("=");
    if (eq >= 0) {
      flags[raw.slice(0, eq)] = raw.slice(eq + 1);
      continue;
    }

    const next = argv[i + 1];
    if (next && !next.startsWith("--")) {
      flags[raw] = next;
      i++;
    } else {
      flags[raw] = true;
    }
  }

  return { positional, flags };
}

export function stringFlag(
  flags: Record<string, string | boolean>,
  name: string,
): string | undefined {
  const value = flags[name];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

export function boolFlag(flags: Record<string, string | boolean>, name: string): boolean {
  return flags[name] === true || flags[name] === "true";
}

export function intFlag(flags: Record<string, string | boolean>, name: string): number | undefined {
  const raw = stringFlag(flags, name);
  if (!raw) return undefined;
  const parsed = Number(raw);
  if (!Number.isSafeInteger(parsed)) throw new Error(`--${name} must be an integer`);
  return parsed;
}

export function required(value: string | undefined, flag: string): string {
  if (!value) throw new Error(`Missing required --${flag}`);
  return value;
}

export function parseJsonFlag<T = unknown>(
  flags: Record<string, string | boolean>,
  name: string,
  fallback: T,
): T {
  const raw = stringFlag(flags, name);
  if (!raw) return fallback;
  try {
    return JSON.parse(raw) as T;
  } catch (error) {
    throw new Error(`--${name} must be valid JSON: ${(error as Error).message}`);
  }
}
