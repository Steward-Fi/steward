# Immutable release operations

Steward enables GitHub's repository-level immutable releases setting. Every
release workflow run also performs a preflight before dependency installation
or package publication:

- no release for the tag: continue with the first publication;
- an existing draft for the tag: continue draft recovery;
- an existing published release: stop without publishing or replacing assets.

The preflight also tombstones the known legacy `v0.3.16` draft, so pushing or
rerunning that tag fails before any registry or release write.

The release action is pinned to a full commit SHA. A published immutable
release's tag, metadata, and assets are not an operator repair surface. Publish
a new patch version instead.

GitHub applies this setting only to releases published after it was enabled.
The existing Steward releases through `v0.4.2` currently report
`isImmutable: false`; enabling the setting does not retroactively lock them.
Treat those legacy releases as historical artifacts and do not edit, delete,
or move their tags. The first release published after enablement is the first
one expected to report `isImmutable: true`.

Release workflow runs are serialized per tag with cancellation disabled. A
manual rerun waits for an in-progress publication and then repeats the
published-release preflight; it must not execute registry writes concurrently
with the original run.

## Legacy `v0.3.16` draft

The repository has a legacy `v0.3.16` draft created on 2026-05-21. It has no
assets and no corresponding Git tag, and later versions through `v0.4.2` have
already been published. It must not be published or reused. Keep it as an
explicitly recorded legacy draft until a repository administrator approves its
deletion; deleting it is not required for immutable releases and is deliberately
outside automated release recovery.

## Verification

Before a production release, an administrator must verify the authoritative
repository setting:

```sh
gh api \
  -H 'Accept: application/vnd.github+json' \
  -H 'X-GitHub-Api-Version: 2026-03-10' \
  repos/Steward-Fi/steward/immutable-releases
```

The response must include `"enabled": true`. After the next release, also run
`gh release view <tag> --json isDraft,isImmutable,tagName`; the published release
must report `isDraft: false` and `isImmutable: true`.

The script contract can be checked without a network mutation:

```sh
bun test scripts/__tests__/check-release-rerun.test.ts
```

## Failure and rollback

If first publication fails while the release is still a draft, rerun the same
tag only after checking that package versions and draft assets match the tagged
commit. If the release is already published, do not disable immutability or
move/delete its tag; fix the cause and publish a new patch tag.

Disabling the repository setting is an incident escalation, not a routine
rollback. It requires repository-administrator approval, a recorded reason and
time window, and immediate re-enablement and API verification. Releases that
were published as immutable remain immutable even if the setting is later
disabled; legacy releases published before enablement do not gain that
protection retroactively.
