# 0010. In-image brotli-libs upgrade until the nginx base image is updated

- Status: Accepted
- Date: 2026-10-25

## Context

The pinned `nginx:stable-alpine` base used by console-web and portal-web shipped a `brotli-libs` version affected by a CVE, while Alpine already published a fixed package.

## Decision

- Install the fixed `brotli-libs` at an exact version in the web/portal Dockerfiles, with an install-identity assertion. No risk-acceptance entry is added for this CVE.
- Remove the overlay once a reviewed newer base image digest includes the fix. General `apk upgrade` remains forbidden.

## Consequences

- See [immutable-image-acceptance](../operations/immutable-image-acceptance.md).
