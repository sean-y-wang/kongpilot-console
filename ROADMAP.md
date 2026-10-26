# Roadmap

Priorities after v1.0.0 (subject to change; discuss in issues):

- [ ] English UI locale and English manuals
- [ ] In-product reconcile path for *uncertain* create operations left by interrupted writes
- [ ] Chunked / continuation execution for very large multi-service promotions (beyond the 500-call budget)
- [ ] Remove the `brotli-libs` overlay once the nginx base image ships the fix ([ADR 0010](docs/decisions/0010-brotli-libs-in-image-upgrade.md))
- [ ] Re-review vulnerability waivers before they expire on 2026-12-31
- [ ] Published production-compose smoke / fault-injection harness

Out of scope: data-plane proxying, write SLA, built-in off-site DR ([ADR 0002](docs/decisions/0002-no-write-sla-or-offsite-dr.md)).
