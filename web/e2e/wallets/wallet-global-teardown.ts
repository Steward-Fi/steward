import { runDefaultGlobalTeardown } from "../global-teardown";
import { environmentWithoutWalletCredentials } from "./credentials";

export default async function walletGlobalTeardown(): Promise<void> {
  await runDefaultGlobalTeardown(environmentWithoutWalletCredentials());
}
