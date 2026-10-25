# syntax=docker/dockerfile:1
FROM curlimages/curl:8.14.1 AS toolchain
USER root
RUN --mount=type=secret,id=proxy_ca \
    set -eu; \
    cp /etc/ssl/certs/ca-certificates.crt /tmp/deck-ca.pem; \
    if [ -f /run/secrets/proxy_ca ]; then cat /run/secrets/proxy_ca >> /tmp/deck-ca.pem; fi; \
    curl --fail --silent --show-error --location --cacert /tmp/deck-ca.pem \
      https://github.com/Kong/deck/releases/download/v1.2.4/deck_1.2.4_linux_amd64.tar.gz -o /tmp/deck.tar.gz; \
    printf '%s  %s\n' '6eef6dc36a8c251f10f0e3ffa40ec5289d42de131ad043f76ad45d2de390beae' '/tmp/deck.tar.gz' | sha256sum -c -; \
    mkdir /tool; tar -xzf /tmp/deck.tar.gz -C /tool; \
    printf '%s  %s\n' '642f49fd64e83aff867939705dbd927c5e750b241a99e8539ab22d18930427ed' '/tool/deck' | sha256sum -c -; \
    mkdir -p /runtime/usr/local/bin /runtime/usr/share/licenses/decK; \
    cp /tool/deck /runtime/usr/local/bin/deck; \
    cp /tool/LICENSE /runtime/usr/share/licenses/decK/LICENSE; \
    chmod 0755 /runtime/usr/local/bin/deck; \
    chmod 0644 /runtime/usr/share/licenses/decK/LICENSE; \
    rm /tmp/deck-ca.pem /tmp/deck.tar.gz

# Host umask and release archive modes must not control runtime permissions.
COPY --chown=0:0 --chmod=0644 deploy/deck-runner/runner.mjs deploy/deck-runner/verify-toolchain.mjs /runtime/opt/kongos/
# COPY's file mode also applies to newly created destination directories.
# Directories need traversal permission before the single runtime-tree copy.
RUN chmod 0755 /runtime/opt /runtime/opt/kongos

FROM node:22-bookworm-slim
LABEL org.opencontainers.image.title="KongPilot decK Runner" org.opencontainers.image.description="Kong 网关管理平台"
# A single copy also avoids duplicating the Node rootfs per file under vfs.
COPY --from=toolchain --chown=0:0 /runtime/ /
USER node
WORKDIR /tmp
ENTRYPOINT ["node", "/opt/kongos/runner.mjs"]
