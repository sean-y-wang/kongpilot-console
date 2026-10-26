# §49 Portal republish of an already-proven revision → clean 409 at prepare (2026-10-25 UTC+8)

## Problem (observed in §48)
Publication proofs are keyed by (cluster, workspace, publication, publication_revision). Re-publishing the same revision after a cluster revision change (e.g. direct→approval switch) passed plan creation, ran the acl/key-auth native steps, then collided on the proof primary key at apply time: the publish step ended `uncertain`, and later attempts got `PORTAL_PUBLICATION_RECOVERY_REQUIRED`.

## Fix (apps/console-api/src/modules/portal/portal-admin.service.ts)
- `assertRevisionUnproven` runs on publish **before** plugin scan/plan, and again inside the plan transaction (race), → `409 PORTAL_PUBLICATION_REVISION_ALREADY_PUBLISHED` (`publicationRevision`, message tells the operator to save a new draft revision first).
- Defense in depth: the workflow handler prepare also refuses (plans persisted before the fix / races) with the same code, before the apply transaction.
- Unpublish is unaffected. No gate relaxed.

## Tests
- `tests/security/m6-publication-retry-review.test.ts` +4 cases: refused before plugin scan / CAS / persist / execute, publication unchanged; allowed after a new draft revision; in-transaction recheck; unpublish unaffected. File 50/50.
- Full vitest: 749 files / 16870 tests passed (`unit-vitest.txt`).

## Bridge verification (rc.1 + this patch, lab image `kongpilot/console-api:rc1-s49-lab`, no tag; cluster B kong 1.5.1)
`bridge-verify.json`: proof minted at cluster-B revision 1 (direct) → approval switch → revision 2 → republish same revision: **409 PORTAL_PUBLICATION_REVISION_ALREADY_PUBLISHED, 0 workflows created, publication unchanged**; new draft revision (two-person workflow) succeeded; publish of the new revision (two-person) succeeded; proxy without key 401 before/after; DB: all workflows `succeeded`, none `uncertain`.
Full browser matrix on the patched stack: **11/11 PASS** (`browser-e2e/`).
Fixture: console DB restored from the 18:41 pre-matrix dump (lab fixture reset), reseeded. After the run the stack was switched back to the rc.1 console-api image.
