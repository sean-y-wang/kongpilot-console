# M4 authentication and unresolved-mutation contract

Status: design only. Implement after the M3 acceptance gate. This document records interfaces approved by the root owner; it does not enable M4 behavior.

## Ownership and dependencies

- Review/auth owner owns `modules/auth/*`, authentication/password tests, and `MutationService` durable unresolved-operation checks. Profile endpoints belong to this owner.
- Root owns `AuthorizationService`, `assertConsole`, platform capabilities, request contexts, and the effective four-dimensional authorization policy.
- Storage owns IAM CRUD, roles/teams/grants, and migration 005. IAM must call the canonical auth methods below rather than write password hashes directly.
- Kong owner owns native proxy authorization and transport lease fencing. Native requests cannot receive trusted context flags from a request body or query.

`AuthService` may inject `AuthorizationService`: authorization depends on database, Kong and request context, and does not depend on `AuthService`. Authentication/session storage remains authoritative in PostgreSQL; Redis provides rate limits, identity-flow state and cache cleanup. No JWT-supplied roles, profile fields or `superAdmin` claims grant authority.

## Approved service interfaces

```ts
hashPassword(password: string, options?: { username?: string; previousHash?: string }): Promise<string>
resetPassword(actor: AuthUser, targetId: string, newPassword: string,
              revision: number, confirmed: boolean): Promise<PasswordChangeReceipt>
revokeAllSessions(userId: string, tx: DbService,
  context: { actorId: string; reason: string; requestId?: string; ip?: string }): Promise<void>
```

`resetPassword` independently calls `assertConsole(actor, 'users', 'write', targetId)`. It validates the exact DTO and confirmation, checks target state/local authentication source and revision, changes the password and credential epoch with revision CAS, revokes every session, and appends an audit event in one transaction. Request metadata comes from trusted request context; callers cannot inject an arbitrary transaction into password reset. A CAS conflict has no password/session/audit side effects.

IAM creation calls `hashPassword`; IAM disable, soft-delete and privilege changes call transaction-scoped `revokeAllSessions` as appropriate. Redis cleanup happens after commit and is best effort. A Redis cleanup failure cannot make a revoked database session usable.

Approved password policy: at least 12 characters, at most 72 UTF-8 bytes, containing upper/lower case, digit and symbol. Reject overlong input before bcrypt; do not truncate. Use bcrypt with a centrally configured work factor. Passwords, hashes, tokens, LDAP bind credentials and provider secrets never appear in returned receipts or audit diffs.

## Self-service and authentication boundaries

- Self profile accepts only `display_name`, `locale`, `timezone` and the expected revision. Reject unknown fields, including `id`, `admin`, `super_admin`, `superAdmin`, roles, teams, permissions, status, authentication source, password/hash and credential/permission epochs. The target is always the authenticated actor.
- Self password change verifies the current local password, validates the new password, and atomically revokes all sessions. It cannot select another user ID and cannot change external-provider credentials.
- Bootstrap accounts use the same password hashing/policy helper. Do not expose a path to modify bootstrap or platform-admin flags through clone/profile endpoints.
- Login validates bounded username/password input, uses distributed per-account and per-IP limits, and records failures/lockouts without logging credentials. Unknown users still perform a dummy password comparison. Lock expiry resets the failed-attempt accounting before a new failure can relock the account.
- Access tokens retain strict algorithm, issuer, audience, expiry and UUID subject/session checks. Every authentication re-reads the active, undeleted user and unrevoked, unexpired session.
- Migration 005 initializes user/session credential epochs to 1. New sessions stamp the current user epoch; authentication and refresh require equality. Reset/rotation increments the user epoch and revokes sessions in the same transaction.
- Refresh rotation uses a locked session row and an exact token-hash comparison. An old refresh token cannot refresh twice; replay detection must have an explicit session-family revocation policy. Cookie authentication remains HttpOnly, Secure in production and SameSite, with CSRF required for writes.
- Public user/capability responses are built asynchronously from current database authorization. Effective IAM grants are queried from `iam_effective_grants`; workspace grants do not authorize global account changes.

The two Konga CVE regressions exercise actual HTTP endpoints with an ordinary authenticated session: self-profile privilege mass assignment and another user's password reset. Both front-end restrictions and direct API requests must fail, without password, privilege, session or audit-success changes. Primary exploit evidence and the broader permission matrix are in `RBAC-test-plan.md`.

## Optional LDAP and OIDC

Configured providers are optional. Disabled/unconfigured providers return explicit unavailable capability/error responses; they never fall back to a successful local login.

- Provider endpoints and role mappings are platform-controlled configuration. User input cannot choose arbitrary LDAP, discovery, token or JWKS URLs. Enforce a configured host allowlist, HTTPS/LDAPS or verified StartTLS, trusted CA verification, DNS/address restrictions, and bounded response/timeout limits.
- External subjects are bound by `(provider_type, provider_key, subject)`, with a unique database constraint. LDAP uses a stable directory identifier/DN according to provider policy; OIDC uses verified issuer/provider plus `sub`. Email/username equality cannot automatically link an existing platform admin.
- Provider linking requires explicit authorized account linking and proof for both sides. Provisioned accounts receive only configured role mappings or a pending/no-grant state. Request parameters and unsigned provider claims cannot assign administrator roles.
- LDAP filters escape user input according to RFC 4515. Bind/password failures are generic, LDAP credentials are ephemeral, group membership comes from the configured directory, and provider calls are rate limited.
- OIDC uses authorization code flow with PKCE S256, single-use server-side state, nonce, fixed callback URI and a short TTL. Validate signed token issuer, audience/authorized party, nonce and expiry. Discovery/JWKS/token URLs stay inside the configured provider allowlist.
- The temporary OIDC correlation cookie may use SameSite=Lax for the cross-site callback; authenticated console cookies retain the console policy. Do not put tokens/secrets in URLs or browser storage. Redirect targets are allowlisted relative console paths.
- External login/group synchronization has append-only audit records with redacted metadata. Developer-portal accounts remain separate in M6.

Migration owner should reserve `auth_identities` with user FK and the unique external-subject constraint. Provider-management HTTP endpoints are not required for the first implementation; validated environment configuration can enable optional providers.

## Durable unresolved-operation guard

The browser's 24-hour/30-reference recovery cache is a convenience and cannot authorize another write. Backend enforcement must survive refresh, logout, account changes, another browser and another idempotency key.

Guard order inside the trusted physical-gateway mutation lock:

1. Revalidate actor, cluster, workspace status and operation authorization.
2. Resolve an existing exact idempotency key. A completed receipt may be returned only after its existing actor/hash/workspace/live-object authorization checks; an uncertain/running key is never resent.
3. Derive the proposed operation's affected resource identities from server-validated entity/parent/graph inputs. Query durable unresolved operations before allocating a new operation or sending native writes.
4. Reject overlapping new-key writes with `MUTATION_RECONCILIATION_REQUIRED`. Reveal an operation ID only if the caller can read that receipt; otherwise return a generic scope-conflict message.
5. Continue the existing before-state checks, requested audit and execution path only when no unresolved impact overlaps.

Unresolved state means `running` or `uncertain`, including a crashed operation whose `remote_started` is false. Age does not prove absence of a write. A deterministic, recorded native validation failure remains a different terminal outcome; failed or partial graph operations must use the operation-specific proof rules instead of optimistic retry.

Impact matching must cross submitting actors for the same object. Another actor cannot recreate or overwrite an uncertain object simply because the original receipt is private. It must also cover a changed workspace or aliased registry entry pointing at the same physical Admin endpoint; authorization/cursors/audit still retain the console cluster ID.

Proposed impact descriptors, always derived server-side:

| Operation | Required overlap identity |
| --- | --- |
| Native update/delete | Native type + canonical Kong ID; include affected graph nodes and shared references where relevant |
| Named native create | Native type + natural-name fingerprint; Console workspace cannot change Kong's global uniqueness namespace |
| Consumer create | Username/custom-ID identity when available; otherwise conservative entity-type/workspace exclusion |
| Plugin create/change binding | Name + canonical nonempty Service/Route/Consumer binding tuple, plus instance ID when known |
| Target create/update | Upstream ID + target address; immutable historical ID alone is insufficient |
| Credential create/update | Consumer ID + credential kind + non-secret stable identity when available; otherwise conservative Consumer/kind exclusion |
| Anonymous certificate/route/create | Conservative native type + workspace until fresh proof can identify the object |
| Recycle restore / workspace migration | Entire validated affected set and inherited parent identities |
| Global metadata | Metadata module + canonical record ID, separately from native gateway impact |

Do not put credential values or complete payloads in searchable impact columns. Keep any necessary original input encrypted. A parent migration or a shared-reference write must consider overlapping unresolved child operations; an unknown Target append must not be retried under a new historical ID.

Existing M0–M3 operations can have NULL workspace/impact metadata. Lazily decrypt real before/result/graph evidence and classify its actual root or parent; unknown, multiple or deleted workspace tags never become the default workspace. If original scope/impact cannot be proved, fail closed for the relevant conservative scope and report a recovery requirement. A NULL field is not an exemption.

Generic operation reconciliation is a later M9 endpoint, not an arbitrary state-edit endpoint in M4. M4 must keep read-only receipts available. Existing workspace-migration reconciliation remains allowed because it acquires the trusted lock, reads every object's fresh state, verifies unchanged non-tag configuration and complete children/references, and atomically commits only its own matching receipt with an audit proof. Workflow reconciliation is permitted only through a trusted approved engine context and cannot send native writes as part of a read-only proof action.

## Required M4 attack/behavior tests

- Ordinary user profile `admin`/`super_admin`/role/password payloads are rejected; cross-user password resets fail in service and HTTP paths.
- Password revision conflicts and audit/storage failures roll back password, epoch and revocation; old access/refresh tokens fail after reset/disable; refresh replay cannot mint a second family token.
- Workspace-only IAM grants cannot manage global users; role removal takes effect immediately; JWT role/admin forgery is irrelevant.
- LDAP filter injection, unconfigured provider fallback, rogue provider/JWKS host, wrong issuer/audience/nonce/state, PKCE replay and email-to-admin auto-linking fail.
- New keys from the same and another actor cannot bypass a durable uncertain write; an authorized terminal same-key receipt remains readable without a second write.
- Browser recovery TTL expiry, cache truncation, local storage clearing, logout/login and registry aliases cannot bypass the backend unresolved guard.
- Legacy NULL-scope records with unknown/multiple/deleted tags fail closed; valid parent-derived child scope is preserved without inventing child business tags.
- Read-only receipt/proof requests remain available during a block; unauthorized callers receive no other actor's object/operation identifiers.
- Loss of outer lease during rate waiting, Redis comparison or DNS prevents subsequent HTTP writes; reconciliation cannot commit proof after losing its lease.

Open implementation coordination: migration 005 impact-column/index requirements and canonical `transportScope` persistence will be agreed before feature coding. The guard must not infer a shared Kong database from a direct database connection, nor claim to discover different Admin nodes sharing a datastore.
