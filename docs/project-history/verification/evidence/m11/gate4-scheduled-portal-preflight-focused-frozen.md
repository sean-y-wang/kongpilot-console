# Genuine scheduled Portal preflight validation

Only `PortalAuthBoundaryService.assertPreparedChange` was changed. Ordinary
HTTP still requires its SID. A no-SID caller must have a genuine original
scheduled namespace verified by the real Context, with exact current owner,
cluster/workspace, owner epoch and transport scope. The same sealed proof and
current frame are revalidated after every possible return or Portal graph
failure. No native permit/managed-object exception was added.

All existing historical managed Consumer/credential checks, full bounded
service/route/plugin capture, prospective authentication analysis and published
revision proof checks remain active.

Observed validation command:

```text
npx vitest run tests/unit/m11-scheduled-portal-preflight.test.ts tests/security/m6-portal-boundary-service.test.ts tests/unit/m11-scheduled-entity-boundary.test.ts

Test Files  3 passed (3)
     Tests  65 passed (65)
  Start at  17:52:13
  Duration  2.05s
```

`npm run typecheck -w @kongpilot/api` exited 0.

The new tests use real Context and real Namespace issuance through original
authority handles from a controlled adapter. They never seed private maps,
create SQL facts, run HTTP, or simulate native transport success. They cover
the original HTTP SID path, genuine scheduled empty-history checks, copied
namespace/proof rejection, cluster/workspace/transport mismatch, fresh owner
and material revocation across awaits, retained historical management,
complete bounded Portal capture, unsafe authentication rejection, and immutable
published revision checks. This is source evidence; Root's next fresh intent
must establish runtime acceptance.
