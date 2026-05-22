/**
 * Pluggable SMS provider interface. Implementations send a short text body
 * to an E.164-formatted phone number.
 */
export interface SmsProvider {
  send(to: string, body: string): Promise<void>;
}

export class ConsoleSmsProvider implements SmsProvider {
  async send(to: string, body: string): Promise<void> {
    console.log(
      [
        "─────────────────────────────────────────",
        `[ConsoleSmsProvider] SMS`,
        `To: ${to}`,
        "",
        body,
        "─────────────────────────────────────────",
      ].join("\n"),
    );
  }
}

export interface TwilioSmsProviderConfig {
  accountSid: string;
  authToken: string;
  /** Sender — phone number, alphanumeric ID, or Messaging Service SID (MGxxxx). */
  from: string;
}

export class TwilioSmsProvider implements SmsProvider {
  private accountSid: string;
  private authToken: string;
  private from: string;

  constructor(config: TwilioSmsProviderConfig) {
    if (!config.accountSid || !config.authToken || !config.from) {
      throw new Error("TwilioSmsProvider: accountSid, authToken, and from are required");
    }
    this.accountSid = config.accountSid;
    this.authToken = config.authToken;
    this.from = config.from;
  }

  async send(to: string, body: string): Promise<void> {
    const url = `https://api.twilio.com/2010-04-01/Accounts/${this.accountSid}/Messages.json`;
    const params = new URLSearchParams({ To: to, Body: body });
    if (this.from.startsWith("MG")) {
      params.set("MessagingServiceSid", this.from);
    } else {
      params.set("From", this.from);
    }
    const auth = btoa(`${this.accountSid}:${this.authToken}`);
    const res = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Basic ${auth}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: params.toString(),
    });
    if (!res.ok) {
      throw new Error(`Twilio send failed (${res.status}): ${await res.text()}`);
    }
  }
}

export interface MockSmsMessage {
  to: string;
  body: string;
  sentAt: Date;
  code?: string;
}

const OTP_RE = /\b(\d{6,8})\b/;

class MockSmsInboxRegistry {
  private byPhone = new Map<string, MockSmsMessage[]>();
  push(msg: MockSmsMessage): void {
    const list = this.byPhone.get(msg.to) ?? [];
    list.push(msg);
    this.byPhone.set(msg.to, list);
  }
  last(phone: string): MockSmsMessage | undefined {
    const list = this.byPhone.get(phone);
    return list?.[list.length - 1];
  }
  all(phone: string): MockSmsMessage[] {
    return [...(this.byPhone.get(phone) ?? [])];
  }
  clear(phone?: string): void {
    if (phone) this.byPhone.delete(phone);
    else this.byPhone.clear();
  }
}

export const MockSmsInbox = new MockSmsInboxRegistry();

export class MockSmsProvider implements SmsProvider {
  async send(to: string, body: string): Promise<void> {
    MockSmsInbox.push({ to, body, sentAt: new Date(), code: body.match(OTP_RE)?.[1] });
  }
}
