# Archive manifest / 归档清单

Where every path from the former internal repository (`work/m11-continue` @ `b2b6e7c`) that was absent from the public tree ended up. Per-file list: [`archive-manifest.json`](archive-manifest.json).

内部仓库中、开源时公开树里没有的每个路径的去向；逐文件明细见 `archive-manifest.json`。

**Totals / 合计:** 4251 paths — published 已公开 **230** · covered 已有公开对应 **4** · private 保留私有 **4017**

| Internal group | Published | Covered | Private | Public location / reason |
|---|---:|---:|---:|---|
| `IMPLEMENTATION-CONTRACT.md` | 1 | 0 | 0 | `docs/project-history/milestones/` |
| `artifacts/M0` | 2 | 0 | 18 | `docs/project-history/verification/evidence/m0/`; raw lab evidence private: lab host/container identifiers, fixture IDs, pre-rebrand screenshots, CA material, discarded attempts |
| `artifacts/M1` | 0 | 0 | 12 | raw lab evidence private: lab host/container identifiers, fixture IDs, pre-rebrand screenshots, CA material, discarded attempts |
| `artifacts/M10` | 0 | 0 | 87 | raw lab evidence private: lab host/container identifiers, fixture IDs, pre-rebrand screenshots, CA material, discarded attempts |
| `artifacts/M11` | 64 | 0 | 1719 | `docs/project-history/verification/evidence/m11/`, `docs/project-history/verification/evidence/m11/runs/20261024-functional-verification/`, `docs/project-history/verification/evidence/m11/runs/20261025-1316-browser-e2e-matrix/` …; raw lab evidence private: lab host/container identifiers, fixture IDs, pre-rebrand screenshots, CA material, discarded attempts |
| `artifacts/M2` | 0 | 0 | 36 | raw lab evidence private: lab host/container identifiers, fixture IDs, pre-rebrand screenshots, CA material, discarded attempts |
| `artifacts/M3` | 1 | 0 | 39 | `docs/project-history/verification/evidence/m3/`; raw lab evidence private: lab host/container identifiers, fixture IDs, pre-rebrand screenshots, CA material, discarded attempts |
| `artifacts/M4` | 0 | 0 | 72 | raw lab evidence private: lab host/container identifiers, fixture IDs, pre-rebrand screenshots, CA material, discarded attempts |
| `artifacts/M5` | 1 | 0 | 102 | `docs/project-history/verification/evidence/m5/`; raw lab evidence private: lab host/container identifiers, fixture IDs, pre-rebrand screenshots, CA material, discarded attempts |
| `artifacts/M6` | 0 | 0 | 501 | raw lab evidence private: lab host/container identifiers, fixture IDs, pre-rebrand screenshots, CA material, discarded attempts |
| `artifacts/M7` | 0 | 0 | 232 | raw lab evidence private: lab host/container identifiers, fixture IDs, pre-rebrand screenshots, CA material, discarded attempts |
| `artifacts/M8` | 0 | 0 | 605 | raw lab evidence private: lab host/container identifiers, fixture IDs, pre-rebrand screenshots, CA material, discarded attempts |
| `artifacts/M9` | 0 | 0 | 68 | raw lab evidence private: lab host/container identifiers, fixture IDs, pre-rebrand screenshots, CA material, discarded attempts |
| `artifacts/Production` | 0 | 0 | 176 | raw lab evidence private: lab host/container identifiers, fixture IDs, pre-rebrand screenshots, CA material, discarded attempts |
| `artifacts/Rebrand` | 0 | 0 | 38 | raw lab evidence private: lab host/container identifiers, fixture IDs, pre-rebrand screenshots, CA material, discarded attempts |
| `artifacts/ReleaseV1_0` | 1 | 0 | 5 | `docs/project-history/verification/evidence/release-v1.0/`; raw lab evidence private: lab host/container identifiers, fixture IDs, pre-rebrand screenshots, CA material, discarded attempts |
| `artifacts/VisualRefinement` | 3 | 0 | 35 | `docs/project-history/verification/evidence/visualrefinement/`; raw lab evidence private: lab host/container identifiers, fixture IDs, pre-rebrand screenshots, CA material, discarded attempts |
| `artifacts/planning` | 0 | 0 | 29 | raw lab evidence private: lab host/container identifiers, fixture IDs, pre-rebrand screenshots, CA material, discarded attempts |
| `artifacts/production` | 0 | 0 | 243 | raw lab evidence private: lab host/container identifiers, fixture IDs, pre-rebrand screenshots, CA material, discarded attempts |
| `deploy/compose.bff-live-evidence.yml` | 1 | 0 | 0 | `deploy/compose/` |
| `deploy/compose.kp010-platform-source.yml` | 1 | 0 | 0 | `deploy/compose/` |
| `deploy/compose.live-kong-evidence.yml` | 1 | 0 | 0 | `deploy/compose/` |
| `deploy/compose.live-kong-secondary-evidence.yml` | 1 | 0 | 0 | `deploy/compose/` |
| `deploy/compose.production-hostnetwork-evidence.yml` | 1 | 0 | 0 | `deploy/compose/` |
| `deploy/releases` | 2 | 0 | 0 | `docs/project-history/verification/release-candidates/20261025-801941c15e6f/` |
| `deploy/scripts` | 26 | 0 | 0 | `scripts/verification/` |
| `docs/acceptance` | 2 | 0 | 0 | `docs/project-history/acceptance/` |
| `docs/deck-1.5-compatibility.md` | 0 | 1 | 0 | `docs/reference/deck-1.5-compatibility.md` |
| `docs/design` | 1 | 0 | 0 | `docs/design/` |
| `docs/drafts` | 5 | 0 | 0 | `docs/project-history/milestones/drafts/` |
| `docs/kong-1.5-compatibility.md` | 0 | 1 | 0 | `docs/reference/kong-1.5-compatibility.md` |
| `docs/milestones` | 71 | 0 | 0 | `docs/project-history/acceptance/`, `docs/project-history/milestones/`, `docs/project-history/verification/milestones/` |
| `docs/multicluster-validation.md` | 0 | 1 | 0 | `docs/operations/multicluster-validation.md` |
| `docs/progress` | 6 | 0 | 0 | `docs/project-history/milestones/checkpoints/` |
| `docs/security` | 18 | 0 | 0 | `docs/architecture/security/` |
| `docs/security-review.md` | 0 | 1 | 0 | `docs/architecture/security-review.md` |
| `tests/security` | 16 | 0 | 0 | `tests/security/lab-evidence/` |
| `tests/unit` | 5 | 0 | 0 | `tests/unit/lab-evidence/` |

## Never published / 永不公开

- Lab env files (`*.env`), TLS keys/certs, bootstrap/DB/OIDC credentials, the lab harness `secrets.json`.
- Discarded regression attempts 0–4 (harness/lab causes, not counted) and raw per-run JSON/log dumps.
- The internal git history (kept offline by the maintainer).

Sanitization of published copies: operator-local paths → `/opt/...` or `$REPO`/`$OUT`/`$PRIVATE`; former working-brand string → `〔former working name〕`; lab IPs/ports → env vars (`KONG_ADMIN_HOST`, `CONSOLE_DB_HOST`, `KP_LAB_SECRETS`, `PORTAL_ORIGIN`); links to unpublished evidence turned into plain text marked *not public*. Ticket-named scripts were renamed to feature names (see `scripts/verification/README.md`).
