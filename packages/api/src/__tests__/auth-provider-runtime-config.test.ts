import { describe, expect, it } from "bun:test";
import { withRuntimeEnvironment } from "@stwd/shared/runtime-env";
import { getPasskeyAuth, getPhoneAuth } from "../routes/auth";

describe("request-local auth provider configuration", () => {
  it("isolates overlapping Twilio credentials and rejects missing request credentials", async () => {
    let markSecondReady!: () => void;
    const secondReady = new Promise<void>((resolve) => {
      markSecondReady = resolve;
    });
    let releaseFirst!: () => void;
    const firstCanRead = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });

    const first = withRuntimeEnvironment(
      {
        NODE_ENV: "production",
        TWILIO_ACCOUNT_SID: "AC-first",
        TWILIO_AUTH_TOKEN: "first-token",
        TWILIO_FROM: "+14155550101",
      },
      async () => {
        await secondReady;
        await firstCanRead;
        return getPhoneAuth();
      },
    );
    const second = withRuntimeEnvironment(
      {
        NODE_ENV: "production",
        TWILIO_ACCOUNT_SID: "AC-second",
        TWILIO_AUTH_TOKEN: "second-token",
        TWILIO_FROM: "+14155550102",
      },
      async () => {
        markSecondReady();
        const auth = getPhoneAuth();
        releaseFirst();
        return auth;
      },
    );

    const [firstAuth, secondAuth] = await Promise.all([first, second]);
    expect(firstAuth).not.toBe(secondAuth);
    expect((firstAuth as any).provider.accountSid).toBe("AC-first");
    expect((secondAuth as any).provider.accountSid).toBe("AC-second");
    expect(() => withRuntimeEnvironment({ NODE_ENV: "production" }, () => getPhoneAuth())).toThrow(
      "SMS provider not configured",
    );
  });

  it("isolates overlapping WebAuthn relying-party configuration", async () => {
    const first = await withRuntimeEnvironment(
      {
        PASSKEY_RP_ID: "first.example.com",
        PASSKEY_RP_NAME: "First RP",
        PASSKEY_ORIGIN: "https://first.example.com",
      },
      () => getPasskeyAuth("https://first.example.com"),
    );
    const second = await withRuntimeEnvironment(
      {
        PASSKEY_RP_ID: "second.example.com",
        PASSKEY_RP_NAME: "Second RP",
        PASSKEY_ORIGIN: "https://second.example.com",
      },
      () => getPasskeyAuth("https://second.example.com"),
    );

    expect(first).not.toBe(second);
    expect((first as any).config).toMatchObject({
      rpName: "First RP",
      rpID: "first.example.com",
      origin: ["https://first.example.com"],
    });
    expect((second as any).config).toMatchObject({
      rpName: "Second RP",
      rpID: "second.example.com",
      origin: ["https://second.example.com"],
    });
  });
});
