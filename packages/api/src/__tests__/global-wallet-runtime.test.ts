import { describe, expect, it } from "bun:test";
import { withRuntimeEnvironment } from "@stwd/shared/runtime-env";
import { globalWalletFeatureFlags } from "../services/global-wallet-runtime";

const enabledBindings = {
  STEWARD_ALLOW_UNSAFE_MESSAGE_SIGNING: "true",
  STEWARD_ALLOW_GLOBAL_WALLET_PERSONAL_SIGN: "true",
  STEWARD_ALLOW_GLOBAL_WALLET_TYPED_DATA_SIGNING: "true",
  STEWARD_ALLOW_GLOBAL_WALLET_SEND_TRANSACTION: "true",
};

describe("global wallet request-local feature gates", () => {
  it("does not retain enabled gates across an overlapping disabled Worker request", async () => {
    let releaseEnabled!: () => void;
    const enabledCanFinish = new Promise<void>((resolve) => {
      releaseEnabled = resolve;
    });
    let enabledStarted!: () => void;
    const enabledDidStart = new Promise<void>((resolve) => {
      enabledStarted = resolve;
    });

    const enabled = withRuntimeEnvironment(enabledBindings, async () => {
      enabledStarted();
      await enabledCanFinish;
      return globalWalletFeatureFlags();
    });
    await enabledDidStart;

    const disabled = withRuntimeEnvironment({}, async () => {
      expect(globalWalletFeatureFlags()).toEqual({
        unsafeMessageSigning: false,
        personalSign: false,
        typedDataSigning: false,
        sendTransaction: false,
      });
      releaseEnabled();
      return globalWalletFeatureFlags();
    });

    expect(await enabled).toEqual({
      unsafeMessageSigning: true,
      personalSign: true,
      typedDataSigning: true,
      sendTransaction: true,
    });
    expect(await disabled).toEqual({
      unsafeMessageSigning: false,
      personalSign: false,
      typedDataSigning: false,
      sendTransaction: false,
    });
  });

  it("requires exact lowercase true opt-ins", () => {
    expect(
      withRuntimeEnvironment(
        {
          STEWARD_ALLOW_UNSAFE_MESSAGE_SIGNING: "TRUE",
          STEWARD_ALLOW_GLOBAL_WALLET_PERSONAL_SIGN: "1",
          STEWARD_ALLOW_GLOBAL_WALLET_TYPED_DATA_SIGNING: "yes",
          STEWARD_ALLOW_GLOBAL_WALLET_SEND_TRANSACTION: " true ",
        },
        () => globalWalletFeatureFlags(),
      ),
    ).toEqual({
      unsafeMessageSigning: false,
      personalSign: false,
      typedDataSigning: false,
      sendTransaction: false,
    });
  });
});
