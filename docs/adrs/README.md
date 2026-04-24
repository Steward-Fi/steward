# Architecture Decision Records

This directory holds Steward's ADRs — short documents that record
technical decisions, why they were made, and what they cost.

ADRs are not a product spec. They are a commitment device: "we decided
X, for these reasons, and here is what we gave up." If you want to
change a decision, open a new ADR that supersedes the old one.

## Tone

Sober. Opinionated where opinionated is earned. No marketing copy. If
something is a known tradeoff or a gap, the ADR says so. When the
vision docs say one thing and the code says another, the ADRs side
with the code.

## Index

| # | Title | Status |
|---|-------|--------|
| [0001](./0001-crypto-choices.mdx) | Cryptographic choices for vault and secret storage | Accepted |
| [0002](./0002-runtime-choice.mdx) | Why Bun and Hono | Accepted |
| [0003](./0003-deployment-model.mdx) | Single container, multiple services deploy | Accepted |
| [0004](./0004-policy-enforcement-model.mdx) | Where policies are enforced | Accepted |

## Related

- [`../security/threat-model.mdx`](../security/threat-model.mdx) —
  explicit threat model. Every ADR that touches a security boundary
  should cross-reference this.

## Writing a new ADR

1. Copy the last ADR as a template.
2. Number it `NNNN-kebab-title.mdx`, four-digit zero-padded.
3. Frontmatter: `title`, `status` (`Proposed` / `Accepted` /
   `Deprecated` / `Superseded by NNNN`), `date`.
4. Sections: **Context** (what forces the decision), **Decision**
   (what we're doing), **Consequences** (what it costs), **Related**
   (links).
5. Add the entry to the table above.

Keep ADRs short. One decision per document. If you find yourself
writing a whitepaper, split it.
