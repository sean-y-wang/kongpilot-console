# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
FROM node:22.23.3-bookworm@sha256:0e5f906573693feaa1e21057ebdcfdb5bd5021f050b2dc7c9deceb629c7da2a8 AS build
WORKDIR /app
# .dockerignore excludes local secrets, modules, build output and evidence.
# A single source layer keeps managed Docker's vfs disk usage bounded.
COPY . .
RUN --mount=type=secret,id=proxy_ca \
    set -eu; \
    if [ -f /run/secrets/proxy_ca ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/proxy_ca; fi; \
    test "$(node --version)" = "v22.23.3"; \
    test -x /usr/bin/cc; \
    node deploy/scripts/prepare-pcre1-engine.mjs; \
    chmod 0755 apps/console-api/native-bin; \
    npm ci --workspace @kongpilot/api --include-workspace-root --strict-ssl=true; \
    npm run build -w @kongpilot/api; \
    mkdir -p /runtime/apps/console-api /runtime/apps/console-web /runtime/apps/portal-web /runtime/packages/contracts; \
    cp package.json package-lock.json /runtime/; \
    cp apps/console-api/package.json /runtime/apps/console-api/; \
    cp apps/console-web/package.json /runtime/apps/console-web/; \
    cp apps/portal-web/package.json /runtime/apps/portal-web/; \
    cp packages/contracts/package.json /runtime/packages/contracts/; \
    cd /runtime; \
    npm ci --workspace @kongpilot/api --omit=dev --strict-ssl=true; \
    cp -a /app/apps/console-api/dist /runtime/apps/console-api/dist; \
    cp -a /app/apps/console-api/native-bin /runtime/apps/console-api/native-bin; \
    cp -a /app/apps/console-api/src/infrastructure/migrations /runtime/apps/console-api/dist/infrastructure/migrations

FROM gcr.io/distroless/nodejs22-debian13:nonroot@sha256:ec2313763dd43931543bd03830466e0c409ce73a487e8d46f10db72d3b816c1c AS runtime
LABEL org.opencontainers.image.title="KongPilot API" org.opencontainers.image.description="Kong 网关管理平台"
# Runtime has Node, production dependencies and the fixed sandboxed PCRE1 worker.
# Native compiler/headers/source archive stay in the build stage. Keep shell, npm
# and dependency installation in the build stage.
ENV PATH=/nodejs/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV NODE_ENV=production
WORKDIR /app/apps/console-api
# Preserve root and workspace-local dependencies; only API production packages remain.
COPY --from=build --chown=1000:1000 /runtime /app
USER 1000:1000
ENTRYPOINT []
EXPOSE 3000
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=5 \
  CMD node -e "fetch('http://127.0.0.1:3000/api/v1/health/ready').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"
CMD ["node", "dist/main.js"]
