# Scheduled Root Kernel source review

Scope: read-only review of Root's Context/Kernel and the scheduled Authority,
Namespace and entity Boundary. Only a new unit-test file and these artifacts
were written. No HTTP/SQL/harness/container/native runtime action was performed.

Validation:

- Four focused files, 37 tests passed; see
  `gate4-scheduled-root-kernel-review-20261013T1703.log`.
- New `tests/unit/m11-scheduled-root-kernel.test.ts`: 12 tests passed.
- `npm run typecheck -w @kongpilot/api`: process exit 0.

The new test uses public `Kernel.onModuleInit` to capture the fixed executor
delegate, original authority handles from an explicitly controlled adapter,
the real Namespace service and the real Context ALS/private registries. It
never seeds Kernel private maps and never simulates a successful native write.
Both pre-source refusal and Kernel-created Source followed by baseline failure
close with original failed completion evidence and zero packet/writer/native
calls. Authority and repository can verify the same original completion twice;
copied evidence and contradictory durable facts are rejected. Ordinary HTTP
SID behavior remains in place; an active conflicting schedule blocks a native
send at its reservation check.

No concrete recursive Namespace verification, same-workflow Redis-lock
reentry, or generic NULL-SID waiver was found in this reviewed candidate.
Namespace verifier calls Authority's pure current DB subject/reviewer checks;
scheduled execution uses shared `runExecution` without reacquiring the outer
workflow lock. Current frame ancestry, opaque identities, full sealed tuples,
fresh authorization and synchronous expiry/Redis checks remain required.

Open lifecycle obligation: Authority can fail in its initial live claim
verification or workflow-lock acquisition before invoking Root. Its private
handle closes while SQL progress remains `claimed`. This is safely closed to
native sends and automatic retry, but requires a dedicated metadata recovery
path to produce a terminal, truthful result. Absence of SQL source rows alone
must not grant replay or infer a known-unsent outcome. Scheduled recycle and
Target/health adapters also remain explicitly closed in this candidate.

Reviewed source SHA256 snapshots:

- Kernel: `a75a5e8bf9877cc565e971dc7a0cd012576fe4e111be85b4f3801999ca8235c0`
- Context: `ecf9be4e26b2039874f6c95aaa38e6cf476bbe75c39dd4f809cae833e6ef6802`
- Authority: `393112b53b92e0d284f928ffee0d7d01eadbdf88e579d5014af5bee2260cb3e0`
- Namespace: `fadcda5626b07172306db34bdb894ee6e61e44d667e8fdf4cdc55a53c7332299`
- Boundary: `cc104278d4c5e96e3e8bdbf8f2e286ff1afb40a04c60fefdc13609b229cf68cb`
- New unit: `bbe68c6600a793aa265b6547ac327590c6eca299019b450bcb2c5564af79d507`

This is source-level review evidence, not real SQL024/runtime/native authority
acceptance or a commercial release approval.
