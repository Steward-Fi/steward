import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { BrowserContext } from "@playwright/test";
import { environmentWithoutWalletCredentials } from "./credentials";

interface WalletBrowserProfileOptions<TContext extends Pick<BrowserContext, "close">> {
  prefix: string;
  prepare?: (profile: string) => Promise<void>;
  launch: (profile: string, environment: Readonly<NodeJS.ProcessEnv>) => Promise<TContext>;
  use: (context: TContext) => Promise<void>;
  environment?: Readonly<NodeJS.ProcessEnv>;
}

/**
 * Own one temporary wallet profile from creation through browser shutdown.
 * Preparation and launch intentionally run inside the cleanup boundary.
 */
export async function withWalletBrowserProfile<TContext extends Pick<BrowserContext, "close">>({
  prefix,
  prepare,
  launch,
  use,
  environment = process.env,
}: WalletBrowserProfileOptions<TContext>): Promise<void> {
  const profileRoot = process.env.STEWARD_WALLET_PROFILE_ROOT ?? tmpdir();
  await mkdir(profileRoot, { recursive: true, mode: 0o700 });
  const profile = await mkdtemp(join(profileRoot, prefix));
  let context: TContext | undefined;
  try {
    await prepare?.(profile);
    context = await launch(profile, environmentWithoutWalletCredentials(environment));
    await use(context);
  } finally {
    try {
      await context?.close();
    } finally {
      await rm(profile, { force: true, recursive: true });
    }
  }
}
