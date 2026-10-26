#!/usr/bin/env bash
# Starts a throwaway 3-master Redis Cluster and runs the cluster integration suite.
set -euo pipefail
cd "$(dirname "$0")/../.."
export REDIS_CLUSTER_TEST_PASSWORD="${REDIS_CLUSTER_TEST_PASSWORD:-kongpilot-cluster-test}"
compose=(docker compose -p kongpilot-redis-cluster-test -f tests/integration/redis-cluster/compose.yml)
trap '"${compose[@]}" down -v >/dev/null 2>&1 || true' EXIT
"${compose[@]}" up -d
for port in 7101 7102 7103; do
  for _ in $(seq 1 50); do "${compose[@]}" exec -T redis-7101 redis-cli -p "$port" -a "$REDIS_CLUSTER_TEST_PASSWORD" --no-auth-warning ping 2>/dev/null | grep -q PONG && break; sleep 0.2; done
done
"${compose[@]}" exec -T redis-7101 redis-cli -a "$REDIS_CLUSTER_TEST_PASSWORD" --no-auth-warning --cluster create 127.0.0.1:7101 127.0.0.1:7102 127.0.0.1:7103 --cluster-replicas 0 --cluster-yes
for _ in $(seq 1 50); do "${compose[@]}" exec -T redis-7101 redis-cli -p 7101 -a "$REDIS_CLUSTER_TEST_PASSWORD" --no-auth-warning cluster info | grep -q 'cluster_state:ok' && break; sleep 0.2; done
REDIS_CLUSTER_TEST_NODES=127.0.0.1:7101,127.0.0.1:7102,127.0.0.1:7103 npx vitest run --config tests/integration/redis-cluster/vitest.config.ts
