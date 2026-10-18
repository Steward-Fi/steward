# @stwd/eliza-plugin

ElizaOS integration for Steward-scoped wallet and provider capabilities. It adds policy-enforced transfers, transaction signing, trades, provider actions, governed API calls, spend checks, and approval tracking to an elizaOS agent.

## Install

```bash
bun add @stwd/eliza-plugin
```

```typescript
import { stewardPlugin } from "@stwd/eliza-plugin";

const character = {
  name: "TradingAgent",
  plugins: [stewardPlugin],
};
```

## Connection settings

| Setting | Required | Purpose |
|---|---|---|
| `STEWARD_API_URL` | yes | Steward API base URL. Plaintext `http://` is only allowed for localhost. |
| `STEWARD_API_KEY` or `STEWARD_JWT` | yes | Tenant API key or agent JWT. |
| `STEWARD_AGENT_ID` | no | Agent id in Steward. Defaults to the runtime agent id. |
| `STEWARD_TENANT_ID` | for auto-register | Tenant for `STEWARD_AUTO_REGISTER=true`. |

If the URL, credentials, or agent id are missing, the plugin stays loaded but disabled, and every wallet action is unavailable.

## Who can use the wallet (sender authorization)

Being connected to Steward is not enough. Every action also checks who is asking and where.

- The sender is the platform-verified `message.entityId`. Message text, display names, `content.name`, and metadata are never read, so typing or displaying the owner's name does nothing.
- The conversation type comes from the stored room, never from the message.
- Read actions (`STEWARD_CHECK_SPEND`, `STEWARD_LIST_APPROVALS`, `STEWARD_REQUEST_APPROVAL`) need at least a known member.
- Spend actions (`STEWARD_TRANSFER`, `STEWARD_SIGN_TRANSACTION`, `SUBMIT_TRADE`, `STEWARD_PROVIDER_ACTION`, `STEWARD_CALL_GOVERNED_API`) run only for the owner, only in a direct message.
- A denied request never reaches Steward. The user gets a short message saying why, and nothing is queued.
- The check fails closed. If Steward is down, the sender's role cannot be resolved, or the room type is missing or unrecognized, the action is denied.
- Steward's own policies (limits, allowlists, manual approval) still apply to everything that passes.

### Authorization settings

#### `STEWARD_OWNER_ENTITY_IDS`

The elizaOS entity UUIDs of the wallet owner, as a JSON array or a comma separated list:

```bash
STEWARD_OWNER_ENTITY_IDS=4f9c2a1e-0b7d-4c3e-9a51-2d6f8e0c1b23
```

You can also set `character.settings.steward.ownerEntityIds` to an array. This is the entity id elizaOS assigns to the owner's connector account (Discord, Telegram, and so on), not the platform user id or a name. Only well formed UUIDs are kept. Wildcards and names are ignored.

When this is set, it is the only source of owner authority. A user that elizaOS core considers an `OWNER` of the world but who is not on this list is capped at admin and cannot spend.

**When unset:** the plugin falls back to elizaOS core roles (`checkSenderRole`) on cores that export it (2.0.x). On older cores that do not export it, there is no fallback. If neither source names an owner, **every human is a stranger and spend actions are unavailable to everyone**. That is safe, but it looks broken until you configure an owner.

#### `STEWARD_API_ROOMS_ARE_DM`

Set to `true` to treat the agent's own HTTP chat API rooms (room type `API`) as direct messages.

Whether an API caller's entity id can be trusted depends on how you expose the API, so this is off by default.

**When unset:** `API` rooms are an unknown audience, and every read and spend action is denied there, including for the owner.

#### `STEWARD_ALLOW_AUTONOMOUS_SPEND`

Set to `true` to let the agent itself spend, from its own `SELF` or `AUTONOMOUS` rooms (for example scheduled or autonomous tasks).

**When unset:** the agent can still run read actions on its own behalf, but **agent-initiated spend is denied**. Spend only happens when the owner asks in a DM.

### What a user sees when denied

| Situation | Result |
|---|---|
| Stranger or member asks for a transfer | "Only the wallet owner can request this. Nothing was sent to Steward, and there is no approval queued." |
| Owner asks for a transfer in a group | "Wallet spending only runs from a direct message with the owner. Ask me again in a DM. Nothing was sent to Steward." |
| Steward not connected | "Steward is not connected, so this wallet action is unavailable. Nothing was sent." |
| Room type unknown or unreadable | "I could not verify what kind of conversation this is, so I did not run this wallet action." |

Spend actions are also hidden from the planner (`validate` returns false) for anyone who may not run them, and the handler checks again before executing.

The policy table is exported as `STEWARD_ACTION_POLICIES`, and the guard as `authorizeSender` / `guardAction`, for agents that compose their own actions.

## Changelog

See [CHANGELOG.md](./CHANGELOG.md).
