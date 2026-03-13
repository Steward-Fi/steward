export default function Home() {
  return (
    <main
      style={{
        minHeight: "100vh",
        background: "#0a0a0a",
        color: "#fafafa",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        padding: "2rem",
      }}
    >
      <div style={{ maxWidth: 720, textAlign: "center" }}>
        <h1
          style={{
            fontSize: "3.5rem",
            fontWeight: 700,
            letterSpacing: "-0.03em",
            marginBottom: "0.5rem",
            background: "linear-gradient(135deg, #fff 0%, #888 100%)",
            WebkitBackgroundClip: "text",
            WebkitTextFillColor: "transparent",
          }}
        >
          steward
        </h1>

        <p
          style={{
            fontSize: "1.25rem",
            color: "#888",
            marginBottom: "3rem",
            lineHeight: 1.6,
          }}
        >
          Agent wallet infrastructure with user-controlled policy enforcement.
          <br />
          Give your agents wallets. Keep the keys safe. Let users set the rules.
        </p>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
            gap: "1.5rem",
            textAlign: "left",
            marginBottom: "3rem",
          }}
        >
          {[
            {
              title: "Vault",
              desc: "Encrypted keystore. Private keys never touch agent runtime. Sign transactions through a secure API.",
            },
            {
              title: "Policies",
              desc: "Users set spending limits, approved addresses, auto-approve thresholds, time windows, rate limits.",
            },
            {
              title: "Identity",
              desc: "ERC-8004 on-chain agent identity. Transaction history builds reputation. Verifiable across platforms.",
            },
            {
              title: "Open Source",
              desc: "Self-hostable. No token dependency. No per-transaction rent. MIT licensed.",
            },
          ].map((card) => (
            <div
              key={card.title}
              style={{
                padding: "1.5rem",
                border: "1px solid #222",
                borderRadius: "12px",
                background: "#111",
              }}
            >
              <h3
                style={{
                  fontSize: "1rem",
                  fontWeight: 600,
                  marginBottom: "0.5rem",
                  marginTop: 0,
                  color: "#fff",
                }}
              >
                {card.title}
              </h3>
              <p style={{ fontSize: "0.875rem", color: "#666", margin: 0, lineHeight: 1.5 }}>
                {card.desc}
              </p>
            </div>
          ))}
        </div>

        <div style={{ display: "flex", gap: "1rem", justifyContent: "center", flexWrap: "wrap" }}>
          <a
            href="https://github.com/0xSolace/steward"
            style={{
              padding: "0.75rem 1.5rem",
              background: "#fff",
              color: "#000",
              borderRadius: "8px",
              textDecoration: "none",
              fontWeight: 600,
              fontSize: "0.9rem",
            }}
          >
            GitHub →
          </a>
          <a
            href="#docs"
            style={{
              padding: "0.75rem 1.5rem",
              background: "transparent",
              color: "#888",
              border: "1px solid #333",
              borderRadius: "8px",
              textDecoration: "none",
              fontWeight: 600,
              fontSize: "0.9rem",
            }}
          >
            Documentation
          </a>
        </div>

        <div
          style={{
            marginTop: "4rem",
            padding: "2rem",
            background: "#111",
            borderRadius: "12px",
            border: "1px solid #222",
            textAlign: "left",
          }}
        >
          <p style={{ color: "#666", fontSize: "0.8rem", margin: "0 0 1rem 0", textTransform: "uppercase", letterSpacing: "0.05em" }}>
            How it works
          </p>
          <pre
            style={{
              color: "#aaa",
              fontSize: "0.85rem",
              lineHeight: 1.7,
              margin: 0,
              overflow: "auto",
              fontFamily: "monospace",
            }}
          >
{`Agent wants to send 0.5 ETH
  → POST /vault/:agentId/sign { to, value }
  → Policy Engine checks user rules:
      ✓ Below daily spending limit
      ✓ Address is whitelisted
      ✓ Under rate limit
      ✗ Above auto-approve threshold
  → Queued for user approval
  → User approves via dashboard
  → Vault decrypts key, signs, broadcasts
  → Agent gets tx hash
  → Key re-encrypted, never exposed`}
          </pre>
        </div>

        <p style={{ color: "#444", fontSize: "0.75rem", marginTop: "4rem" }}>
          Built for the Synthesis Hackathon. Shipping March 2026.
        </p>
      </div>
    </main>
  );
}
