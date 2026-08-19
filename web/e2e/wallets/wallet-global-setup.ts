import type { FullConfig } from "@playwright/test";
import globalSetup from "../global-setup";
import { assertWalletE2ECredentials, environmentWithoutWalletCredentials } from "./credentials";

export default async function walletGlobalSetup(config: FullConfig): Promise<void> {
  assertWalletE2ECredentials();
  await globalSetup(config, environmentWithoutWalletCredentials());
}
