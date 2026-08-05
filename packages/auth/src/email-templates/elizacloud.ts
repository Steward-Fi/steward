import type { MagicLinkTemplateData, OtpTemplateData, RenderedMagicLinkTemplate } from "./default";
import { escapeEmailHtml } from "./default";

/**
 * Eliza Cloud auth email templates.
 *
 * Brand-matched to the shipped elizaOS product surfaces (see
 * elizaOS/eliza `packages/shared/src/brand` and the Eliza Cloud
 * `packages/lib/email/templates/welcome.html` transactional email):
 *   - black field (#000000), white text, #888888 muted
 *   - brand orange #FF5800 (mark) / #FF6B00 (CTA pill, per product emails)
 *   - #141414 card with #222222 border, 12px radius
 *   - Helvetica/Arial stack (email-safe stand-in for Poppins)
 *   - hosted eliza mark: app.elizacloud.ai/brand/favicons (public, 200)
 *
 * Email-client constraints: table layout, inline styles only, no third-party
 * CSS, dark `color-scheme` hints, bulletproof CTA (bgcolor + inline a).
 */

const SANS = "Helvetica, Arial, sans-serif";
const MONO = "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace";
const BLACK = "#000000";
const CARD = "#141414";
const BORDER = "#222222";
const WHITE = "#ffffff";
const MUTED = "#888888";
const FAINT = "#555555";
const CTA_ORANGE = "#ff6b00";
const LOGO_URL = "https://app.elizacloud.ai/brand/favicons/android-chrome-192x192.png";

function shell(preheader: string, inner: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <meta name="color-scheme" content="dark" />
  <meta name="supported-color-schemes" content="dark" />
</head>
<body style="margin:0;padding:0;background-color:${BLACK};color:${WHITE};font-family:${SANS};">
  <div style="display:none;max-height:0;overflow:hidden;opacity:0;color:${BLACK};font-size:1px;line-height:1px;">
    ${preheader}
  </div>
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:${BLACK};">
    <tr>
      <td align="center" style="padding:40px 16px 60px 16px;">
        <table role="presentation" width="440" cellpadding="0" cellspacing="0" border="0" style="max-width:440px;width:100%;">
          <tr>
            <td align="center" style="padding:20px 0 32px 0;">
              <img src="${LOGO_URL}" alt="Eliza" width="48" height="48" style="display:block;width:48px;height:48px;" />
            </td>
          </tr>
${inner}
          <tr>
            <td align="center" style="padding:28px 8px 0 8px;font-family:${SANS};font-size:11px;line-height:1.6;color:${FAINT};">
              Powered by <span style="color:${MUTED};">elizaOS</span> &bull; <a href="https://elizacloud.ai" style="color:${MUTED};text-decoration:none;">elizacloud.ai</a>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`;
}

export function renderElizaCloudTemplate({
  magicLink,
  expiresInMinutes,
}: MagicLinkTemplateData): RenderedMagicLinkTemplate {
  const inner = `          <tr>
            <td style="background-color:${CARD};border:1px solid ${BORDER};border-radius:12px;padding:40px 32px;">
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
                <tr>
                  <td align="center" style="font-family:${SANS};font-size:26px;font-weight:400;line-height:1.25;color:${WHITE};padding-bottom:10px;">
                    Sign in to Eliza Cloud
                  </td>
                </tr>
                <tr>
                  <td align="center" style="font-family:${SANS};font-size:14px;line-height:1.6;color:${MUTED};padding-bottom:32px;">
                    Tap the button below and we&rsquo;ll put you back where you were.<br />
                    This link expires in ${expiresInMinutes} minutes and can be used once.
                  </td>
                </tr>
                <tr>
                  <td align="center" style="padding-bottom:32px;">
                    <table role="presentation" cellpadding="0" cellspacing="0" border="0">
                      <tr>
                        <td align="center" bgcolor="${CTA_ORANGE}" style="border-radius:50px;background-color:${CTA_ORANGE};">
                          <a href="${magicLink}" target="_blank"
                             style="display:inline-block;padding:14px 40px;font-family:${SANS};font-size:16px;font-weight:500;color:${WHITE};text-decoration:none;border-radius:50px;">
                            Sign in
                          </a>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
                <tr>
                  <td style="border-top:1px solid ${BORDER};padding-top:24px;font-family:${SANS};font-size:11px;line-height:1.6;color:${MUTED};">
                    Or copy this link into your browser:<br />
                    <a href="${magicLink}" style="color:${CTA_ORANGE};text-decoration:none;word-break:break-all;font-family:${MONO};font-size:11px;">${magicLink}</a>
                  </td>
                </tr>
                <tr>
                  <td style="padding-top:20px;font-family:${SANS};font-size:11px;line-height:1.6;color:${FAINT};">
                    If this wasn&rsquo;t you, ignore this email. Nothing happens until you click.
                  </td>
                </tr>
              </table>
            </td>
          </tr>`;

  return {
    subject: "Sign in to Eliza Cloud",
    text: [
      "Eliza Cloud",
      "",
      "Tap the link below to sign in:",
      "",
      magicLink,
      "",
      `This link expires in ${expiresInMinutes} minutes and can be used once.`,
      "If this wasn't you, ignore this email. Nothing happens until you click.",
      "",
      "Powered by elizaOS — elizacloud.ai",
    ].join("\n"),
    html: shell(`Your Eliza Cloud sign-in link expires in ${expiresInMinutes} minutes.`, inner),
  };
}

export function renderElizaCloudOtpTemplate({
  code,
  expiresInMinutes,
}: OtpTemplateData): RenderedMagicLinkTemplate {
  const escapedCode = escapeEmailHtml(code);
  const inner = `          <tr>
            <td style="background-color:${CARD};border:1px solid ${BORDER};border-radius:12px;padding:40px 32px;">
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
                <tr>
                  <td align="center" style="font-family:${SANS};font-size:26px;font-weight:400;line-height:1.25;color:${WHITE};padding-bottom:10px;">
                    Your sign-in code
                  </td>
                </tr>
                <tr>
                  <td align="center" style="font-family:${SANS};font-size:14px;line-height:1.6;color:${MUTED};padding-bottom:28px;">
                    Enter this code in Eliza Cloud to verify your email.<br />
                    It expires in ${expiresInMinutes} minutes.
                  </td>
                </tr>
                <tr>
                  <td align="center" style="padding-bottom:28px;">
                    <span style="display:inline-block;background-color:${BLACK};border:1px solid ${BORDER};border-radius:12px;color:${WHITE};font-size:32px;font-weight:700;letter-spacing:0.35em;padding:16px 24px 16px 34px;font-family:${MONO};">${escapedCode}</span>
                  </td>
                </tr>
                <tr>
                  <td style="border-top:1px solid ${BORDER};padding-top:20px;font-family:${SANS};font-size:11px;line-height:1.6;color:${FAINT};">
                    If you didn&rsquo;t request this code, you can safely ignore this email.
                  </td>
                </tr>
              </table>
            </td>
          </tr>`;

  return {
    subject: `${code} is your Eliza Cloud sign-in code`,
    text: [
      `Your Eliza Cloud sign-in code is: ${code}`,
      "",
      `It expires in ${expiresInMinutes} minutes. If you didn't request this, ignore this email.`,
      "",
      "Powered by elizaOS — elizacloud.ai",
    ].join("\n"),
    html: shell(`${code} is your Eliza Cloud sign-in code.`, inner),
  };
}
