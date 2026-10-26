# Project history

[简体中文](README.zh-CN.md)

This page summarizes how KongPilot reached v1.0.0. It is a curated summary of the original development record; per-run evidence and lab logs were intentionally not published.

## Milestone timeline

| Milestone | Scope | Outcome |
|---|---|---|
| M0 | Deployment baseline: Kong OSS 1.5.1, separate PostgreSQL for Kong and console, Redis, Node.js 22 BFF, Nginx web | Compose deployment; BFF never connects to Kong's database |
| M1 | Core entities: Services, Routes, Upstreams/Targets, Consumers, Certificates, SNIs, six credential types, recycle bin | Verified against real Kong 1.5.1 |
| M2 | Dynamic plugin center: schema-driven forms, binding, priority view | 1,142 live HTTP checks; 34 installed plugins life-cycled |
| M3 | Workspaces (tag-based soft isolation) | 763 live HTTP checks + browser flow |
| M4 | Identity, four-dimension RBAC, sessions, independent security review | 1,095 live HTTP assertions |
| M5 | Monitoring (Prometheus / Loki vitals) | 2,630 live HTTP checks, numeric cross-checks per cluster |
| M6 | Developer portal (apps, credentials, docs), deployment contract | Portal shipped as a separate app |
| M7 | Append-only audit, events and notifications (webhook / SMTP) | Every successful write traced to an audit record |
| M8 | Snapshots, YAML import/export, decK 1.x-compatible GitOps adapter, proxy TLS | Pinned decK diff/sync verified |
| M9 | Operations toolbox: node status, cache keys, route simulator (native PCRE1), proxy probes, batch changes | Verified on real gateway |
| M10 | Configuration governance center | Technical acceptance |
| M11 | Change tickets & approval workflow, scheduled execution, unknown-result handling, release hardening | Release acceptance closed on v1.0.0-rc.2 |

## M11 acceptance journey

| Step | What it closed |
|---|---|
| Approver-may-execute decision | Documented as a permission rule with SoD guidance ([ADR 0001](../decisions/0001-approver-may-execute-approved-tickets.md)) |
| Scope reduction | Write SLA and off-site DR declared out of scope; kept light concurrency + PostgreSQL backup/restore ([ADR 0002](../decisions/0002-no-write-sla-or-offsite-dr.md)) |
| Production compose (bridge network) | Full production-style deployment; found Kong worker OOM, fixed by defaulting workers to 2 ([ADR 0007](../decisions/0007-kong-worker-processes-default-2.md)) |
| Offline DNS | Destination resolution moved to c-ares with bounded fallback; offline smoke 17/22 → 22/22 ([ADR 0008](../decisions/0008-destination-dns-c-ares.md)) |
| Lock message + fault injection | Cluster-level write lock message; Redis stop / Kong pause drills 17/17 |
| v1.0.0-rc.1 | Flaky tests fixed (full suite green twice), tag + formal vulnerability rescan |
| rc.1 regression & browser matrix | Backend suites passed; browser E2E matrix brought to 11/11 with proper fixtures |
| Portal republish hardening | Same-revision republish rejected at prepare ([ADR 0006](../decisions/0006-portal-republish-same-revision-rejected.md)) |
| Rebrand + manual screenshots | Legacy branding removed; 15 manual screenshots re-shot |
| v1.0.0-rc.2 | Re-tag after the hardening fix; formal rescan; audit pagination confirmed as contract ([ADR 0005](../decisions/0005-audit-integrity-pagination.md)) |
| Clean single-pass regression | All five suites in one uninterrupted run; acceptance closed by the maintainer |

### Why rc.2

The portal republish hardening landed after `v1.0.0-rc.1` was tagged. Rather than accept a release that differed from the scanned artifact, a new tag `v1.0.0-rc.2` was cut and both the vulnerability rescan and the full regression were rerun on it. Later failures were in test scripts and lab setup only, so no further tag was needed.

## Final verification (v1.0.0-rc.2)

Images built from the tag, production-style compose, real Kong 1.5.1, no upstream DNS, one uninterrupted pass:

| Suite | Result |
|---|---|
| Smoke | 22/22 |
| Concurrency (20 admins) | 800 requests, 0 errors, p95 ≈ 281 ms |
| Fault injection (Redis stop, Kong pause) | 17/17 |
| PostgreSQL backup/restore | 9/9 (data and audit chain intact) |
| Browser E2E matrix | 11/11 |
| Unit / security suites | ≈16.8k tests passing |

### Vulnerability rescan

Pinned grype 0.120.1, gates not relaxed: 39/39 acceptance checks, **0 Critical**, **0 fixable**, 0 unaccepted. 13 High findings with no upstream fix are tracked in [`deploy/security/image-vulnerability-acceptance.json`](../../deploy/security/image-vulnerability-acceptance.json); every waiver **expires 2026-12-31** and must be re-reviewed. One fixable CVE in `brotli-libs` was fixed in-image instead of waived ([ADR 0010](../decisions/0010-brotli-libs-in-image-upgrade.md)).

## Known gaps

- UI is Chinese-only; English locale planned.
- Uncertain *create* operations left by fault drills have no in-product reconcile path yet; they block config import on that cluster until resolved manually.
- Multi-service promote preflight is bounded by the 500-call budget; very large promotions may need to be split.
- Kong OSS 1.5.x only.

## Lessons learned

- **Never relax a gate to get green.** Every failure was traced to product, test or lab; fixes went to the right layer.
- **Point-in-time evidence is not a release.** Suites that passed on different commits were rerun together on one tagged image in a single pass.
- **Offline is a real environment.** DNS behaviour without upstream resolvers exposed a genuine starvation bug.
- **Defaults matter.** `auto` worker count looked harmless until it OOM-killed Kong on a bigger host.
- **Distinguish lab from product.** Shared source IPs hitting rate limits, wrong time zones for schedule inputs and leftover Kong data were test-harness issues, fixed in the harness.
- **Bounded APIs are contracts.** Paginated audit verification is by design; clients must follow the cursor.
