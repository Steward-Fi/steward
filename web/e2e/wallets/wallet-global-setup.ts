import type { FullConfig } from "@playwright/test";
import globalSetup from "../global-setup";
import { assertWalletE2EPasswords, environmentWithoutWalletCredentials } from "./credentials";

export default async function walletGlobalSetup(config: FullConfig): Promise<void> {
  assertWalletE2EPasswords();
  await globalSetup(config, environmentWithoutWalletCredentials());
}
