FROM node:22-bookworm-slim
WORKDIR /opt/kongos-event-receiver
COPY --chown=node:node deploy/event-receivers/*.mjs ./
USER node
CMD ["node", "server.mjs"]
