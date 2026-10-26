# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
FROM node:26.12.1-bookworm@sha256:5c4012d11d9857c42713ba511fbc19645cac1706bb710d51d42b0d301dff7f88 AS build
WORKDIR /app
COPY package.json package-lock.json ./
COPY apps/console-api/package.json apps/console-api/package.json
COPY apps/console-web/package.json apps/console-web/package.json
COPY apps/portal-web/package.json apps/portal-web/package.json
COPY packages/contracts/package.json packages/contracts/package.json
RUN --mount=type=secret,id=proxy_ca \
    set -eu; \
    if [ -f /run/secrets/proxy_ca ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/proxy_ca; fi; \
    npm ci --workspace @kongpilot/web --include-workspace-root --strict-ssl=true
COPY apps/console-web apps/console-web
# Portal administration shares the safe document readers with the independent
# Portal. Include those imported sources in the isolated Console build.
COPY apps/portal-web/src/components/DocumentReaders.tsx apps/portal-web/src/components/document-safety.ts apps/portal-web/src/components/
# The in-product manual page bundles these reviewed Markdown sources (?raw).
COPY docs/manuals/console-user-guide.md docs/manuals/production-operations-guide.md docs/manuals/
COPY packages packages
RUN npm run build -w @kongpilot/web

FROM nginx:stable-alpine@sha256:47928bf67eb62a1863cb08d9ecb52d3e704304ba614eaee17884204677702951 AS runtime
LABEL org.opencontainers.image.title="KongPilot" org.opencontainers.image.description="Kong 网关管理平台"
# Runtime base digest stays frozen in deploy/images/toolchain.json. Prefer updating
# that reviewed digest over mutable APK repositories. The temporary brotli-libs pin
# below is the only approved exception; remove it when the digest catches up.
# TEMPORARY overlay (owner-approved 2026-10-25): pin Alpine brotli-libs to the
# fixed 1.2.1-r0 for CVE-2026-111497. The reviewed nginx:stable-alpine digest above
# still ships vulnerable 1.2.0-r1; Alpine v3.24 main already has the fix. This is an
# exact-version `apk add` of one package only — not a general repository upgrade and
# not a risk-acceptance entry. Remove this RUN (and the matching
# deploy/images/toolchain.json runtimePackageOverlays entry) as soon as a newer
# reviewed nginx:stable-alpine digest that already contains brotli-libs>=1.2.1-r0 is
# adopted. See docs/operations/immutable-image-acceptance.md.
RUN set -eu; \
    apk add --no-cache 'brotli-libs=1.2.1-r0'; \
    installed="$(apk info -e -v brotli-libs)"; \
    test "$installed" = 'brotli-libs-1.2.1-r0'
COPY --chmod=0644 deploy/nginx/console-nginx.conf /etc/nginx/nginx.conf
COPY --chmod=0644 deploy/nginx/default.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/apps/console-web/dist /usr/share/nginx/html
USER 101:101
EXPOSE 8080
ENTRYPOINT ["nginx"]
CMD ["-g", "daemon off;"]
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
  CMD wget -Y off -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1
