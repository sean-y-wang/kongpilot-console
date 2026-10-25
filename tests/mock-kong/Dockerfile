FROM node:22-bookworm-slim
WORKDIR /app
COPY --chown=node:node tests/mock-kong/server.mjs tests/mock-kong/server.mjs
COPY --chown=node:node tests/fixtures/kong-1.5.1 tests/fixtures/kong-1.5.1
ENV MOCK_KONG_HOST=0.0.0.0 MOCK_KONG_PORT=8001
USER node
EXPOSE 8001
CMD ["node", "tests/mock-kong/server.mjs"]
