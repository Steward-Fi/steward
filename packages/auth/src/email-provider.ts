import { Resend } from "resend";

/**
 * Pluggable email provider interface.
 * Swap implementations without touching EmailAuth logic.
 */
export interface EmailProvider {
  send(to: string, subject: string, text: string, html?: string): Promise<void>;
}

// ---------------------------------------------------------------------------
// ResendProvider — production provider backed by resend.com
// ---------------------------------------------------------------------------

export interface ResendProviderConfig {
  apiKey: string;
  from: string; // e.g. "Steward <login@steward.fi>"
}

export class ResendProvider implements EmailProvider {
  private client: Resend;
  private from: string;

  constructor(config: ResendProviderConfig) {
    this.client = new Resend(config.apiKey);
    this.from = config.from;
  }

  async send(
    to: string,
    subject: string,
    text: string,
    html?: string,
  ): Promise<void> {
    const { error } = await this.client.emails.send({
      from: this.from,
      to,
      subject,
      text,
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
  async send(to: string, subject: string, text: string): Promise<void> {
    console.log(
      [
        "─────────────────────────────────────────",
        `[ConsoleProvider] Magic link email`,
        `To:      ${to}`,
        `Subject: ${subject}`,
        "",
        text,
        "─────────────────────────────────────────",
      ].join("\n"),
    );
  }
}
