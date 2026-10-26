# Outbound preparation/network deadline correction

Root's original Consumer restore attempt stopped before the synchronous wire
spend: `wireSpent=false`, immutable SQL21 `failed-known-not-sent`, original
mutation `uncertain`/`remote_started=true`, five earlier successful native
packets, and the final ACL packet unattempted. This source change does not
replay that attempt, alter its facts, raise `KONG_TIMEOUT_MS` or create recovery
authority.

`outboundRaw` previously began one deadline before DNS and awaited post-DNS
durable permission/graph preparation against that same socket budget. Once
preparation exceeded 5000ms it raised `ETIMEDOUT` before the final wire guard.
The correction preserves the existing independent bounded DNS race, pinned
address and prohibited-answer checks. After successful preparation, the
unchanged final synchronous caller guard runs; only then does the original
network timeout begin in the same synchronous turn as request allocation.
Outer Context/lease/window/revocation fences remain mandatory and unchanged.
No retry, socket, native packet or lease is created during preparation.

Only `apps/console-api/src/infrastructure/kong/outbound.ts` and a new focused
unit were edited. The new fixture is synthetic Node HTTP/HTTPS + DNS + fake
time, explicitly not runtime native authority or transport acceptance. Its
real Context tickets prove that a 120001ms expired execution or closed HTTP
frame still rejects before any HTTP request is allocated.

Observed focused validation:

```text
npx vitest run tests/unit/m11-outbound-preparation-deadline.test.ts tests/security/outbound.test.ts tests/security/outbound-http.test.ts

Test Files  3 passed (3)
     Tests  42 passed (42)
  Start at  18:01:47
  Duration  1.38s
```

New 13 tests cover preparation >5000ms with a successful 4900ms network
response, independent stalled DNS/network limits, unchanged pinned lookup,
mixed forbidden DNS answers, rejected preparation, final synchronous
revocation, real Context expiry/closure, unchanged HTTPS hostname/certificate
validation defaults, response-budget failure with no write retry, and text
transport. Existing URL policy and local HTTP transport suites also passed.

The parallel API type check initially exited 2 solely in the other owner's
in-progress scheduled Authority evidence typing (lines 439–441); no such error
occurred in these owned files. The owner then fixed and froze its typed evidence
guard; final shared API type check exited 0 at 18:02:57, recorded in
`gate4-scheduled-partial-truth-api-typecheck-attempt1.log`. No redundant type
check or Docker, SQL, remote HTTP or private harness operation was run.

Frozen SHA256:

- `outbound.ts`: `cdef145ee78c410b2bf5e93ef2d6d86d8de5ace9966c90029432edb8b825544e`
- New unit: `91e92b7275ff0684b7cbb212b8ea2aa46831ed3ade37ad4939c76603939e754d`
