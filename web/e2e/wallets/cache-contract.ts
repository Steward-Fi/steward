import { resolve } from "node:path";

export const PHANTOM_CHROME_EXTENSION_ID = "bfnaelmomeimhlpmgjnjophhpkkoljpa";

export function phantomExtensionPath(cwd = process.cwd()): string {
  return resolve(cwd, ".cache-synpress", PHANTOM_CHROME_EXTENSION_ID);
}
