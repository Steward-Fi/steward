import { Resend } from "resend";

/**
 * Pluggable email provider interface.
 * Swap implementations without touching EmailAuth logic.
 */
export interface EmailProvider {
  send(
    to: string,
    subject: string,
    text: string,
    html?: string,
    options?: { replyTo?: string },
  ): Promise<void>;
}

// ---------------------------------------------------------------------------
// ResendProvider — production provider backed by resend.com
// ---------------------------------------------------------------------------

export interface ResendProviderConfig {
  apiKey: string;
  from: string; // e.g. "Steward <login@steward.fi>"
  replyTo?: string;
}

export class ResendProvider implements EmailProvider {
  private client: Resend;
  private from: string;
  private replyTo?: string;

  constructor(config: ResendProviderConfig) {
    this.client = new Resend(config.apiKey);
    this.from = config.from;
    this.replyTo = config.replyTo;
  }

  async send(
    to: string,
    subject: string,
    text: string,
    html?: string,
    options?: { replyTo?: string },
  ): Promise<void> {
    const { error } = await this.client.emails.send({
      from: this.from,
      to,
      subject,
      text,
      ...(options?.replyTo || this.replyTo ? { replyTo: options?.replyTo || this.replyTo } : {}),
      ...(html ? { html } : {}),
    });

    if (error) {
      throw new Error(`Resend error: ${error.message}`);
    }
  }
}

// ---------------------------------------------------------------------------
// ConsoleProvider — development / testing provider (logs to stdout)
// ---------------------------------------------------------------------------

export class ConsoleProvider implements EmailProvider {
  async send(
    to: string,
    subject: string,
    text: string,
    _html?: string,
    options?: { replyTo?: string },
  ): Promise<void> {
    console.log(
      [
        "─────────────────────────────────────────",
        `[ConsoleProvider] Magic link email`,
        `To:      ${to}`,
        `Subject: ${subject}`,
        ...(options?.replyTo ? [`Reply-To: ${options.replyTo}`] : []),
        "",
        text,
        "─────────────────────────────────────────",
      ].join("\n"),
    );
  }
}

// ---------------------------------------------------------------------------
// MockEmailProvider — in-memory inbox for e2e testing.
//
// Stores every sent message in a process-wide registry keyed by recipient.
// A test harness can read the most recent message (or the embedded magic-link
// token) via `MockEmailInbox.last(email)` or the static helpers.
//
// NEVER enable in production. The wrapper in the API layer gates this behind
// an explicit `EMAIL_PROVIDER=mock` env var and NODE_ENV !== "production".
// ---------------------------------------------------------------------------

export interface MockEmailMessage {
  to: string;
  subject: string;
  text: string;
  html?: string;
  replyTo?: string;
  sentAt: Date;
  /** Magic-link token extracted from the text body, if present. */
  token?: string;
  /** Full magic-link URL extracted from the text body, if present. */
  magicLink?: string;
}

const MAGIC_LINK_RE = /https?:\/\/\S*[?&]token=([A-Za-z0-9_-]+)/;

function parseMagicLink(text: string): { magicLink?: string; token?: string } {
  const match = text.match(MAGIC_LINK_RE);
  if (!match) return {};
  return { magicLink: match[0], token: match[1] };
}

class MockEmailInboxRegistry {
  private byEmail = new Map<string, MockEmailMessage[]>();

  push(msg: MockEmailMessage): void {
    const key = msg.to.toLowerCase();
    const existing = this.byEmail.get(key) ?? [];
    existing.push(msg);
    this.byEmail.set(key, existing);
  }

  last(email: string): MockEmailMessage | undefined {
    const list = this.byEmail.get(email.toLowerCase());
    return list?.[list.length - 1];
  }

  all(email: string): MockEmailMessage[] {
    return [...(this.byEmail.get(email.toLowerCase()) ?? [])];
  }

  clear(email?: string): void {
    if (email) this.byEmail.delete(email.toLowerCase());
    else this.byEmail.clear();
  }
}

export const MockEmailInbox = new MockEmailInboxRegistry();

export class MockEmailProvider implements EmailProvider {
  async send(
    to: string,
    subject: string,
    text: string,
    html?: string,
    options?: { replyTo?: string },
  ): Promise<void> {
    MockEmailInbox.push({
      to,
      subject,
      text,
      ...(html ? { html } : {}),
      ...(options?.replyTo ? { replyTo: options.replyTo } : {}),
      sentAt: new Date(),
      ...parseMagicLink(text),
    });
  }
}
