# Release tag v1.0.0-rc.1 formal image rescan
- Tag: annotated `v1.0.0-rc.1` on 8e9c5a3 (owner approved 2026-10-25 16:22 UTC+8); pushed as single ref, no force.
- Formal gate: CI run 40178277334 (workflow_dispatch on tag), job immutable-images-amd64 = success; grype 0.120.1 pinned, DB v6.1.10 (<72h); acceptance 39/39, 0 unaccepted, 0 stale, 0 fixable, 0 Critical; native pcre CPE control passed.
- Local pre-check on images built from the tag worktree: same result (39/39).
- Waiver/gate rules unchanged (deploy/security/image-vulnerability-acceptance.json). Raw grype reports kept private, not committed.
- commercialClosed=false. Remaining: rebrand screenshots.
