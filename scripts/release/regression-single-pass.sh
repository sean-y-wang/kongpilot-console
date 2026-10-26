#!/usr/bin/env bash
# LAB ONLY. Sanitized copy of the runner used for the v1.0.0-rc.2 clean single-pass
# regression (see docs/project-history/verification/rc2-final-regression/).
# Required env: REPO (checkout), OUT (evidence dir), PRIVATE (dir holding rc1-e2e.env,
# drill/<dump>, and tests/e2e/lab-harness copied with its secrets.json).
# Optional: CONSOLE_DB_HOST (default console-db), FIXTURE_DUMP, PORTAL_ORIGIN.
: "${REPO:?}" "${OUT:?}" "${PRIVATE:?}"
export CONSOLE_DB_HOST="${CONSOLE_DB_HOST:-console-db}" PORTAL_ORIGIN="${PORTAL_ORIGIN:-https://portal.kp.test:49443}"
set -x
cd "$REPO"
echo "start single-pass HEAD=$(git rev-parse --short HEAD) $(TZ=Asia/Shanghai date +%T)" >> ${OUT}/progress.log
export NODE_TLS_REJECT_UNAUTHORIZED=0
docker rm -f kp-bridge-kong-b-1 kp-bridge-kong-b-db-1 kp-bridge-e2e-echo-1 kp-bridge-kong-b-migrations-1 2>/dev/null; docker compose -p kp-bridge --env-file $PRIVATE/rc1-e2e.env -f docker-compose.yml -f deploy/compose/compose.production.yml up -d --wait || exit 2
docker compose -p kp-bridge --env-file $PRIVATE/rc1-e2e.env -f docker-compose.yml -f deploy/compose/compose.production.yml stop console-api
docker exec kp-bridge-console-db-1 psql -U kongos -d postgres -qc "select pg_terminate_backend(pid) from pg_stat_activity where datname='kongos' and pid<>pg_backend_pid()" -c "drop database kongos" -c "create database kongos owner kongos" || exit 6
docker exec -i kp-bridge-console-db-1 pg_restore -U kongos -d kongos --no-owner < $PRIVATE/drill/${FIXTURE_DUMP:-console-fixture.dump} || exit 6
docker compose -p kp-bridge --env-file $PRIVATE/rc1-e2e.env -f docker-compose.yml -f deploy/compose/compose.production.yml up -d --wait || exit 6
docker run --rm --network container:kp-bridge-console-api-1 --entrypoint node kongpilot/console-api:v1.0.0-rc.2 -e 'const A="http://kong:8001";(async()=>{const s=(await (await fetch(A+"/services?size=1000")).json()).data;let n=0;for(const x of s){if(!/^(e2e|rc1e2e)-/.test(x.name))continue;const rs=(await (await fetch(A+"/services/"+x.id+"/routes")).json()).data;for(const r of rs)await fetch(A+"/routes/"+r.id,{method:"DELETE"});await fetch(A+"/services/"+x.id,{method:"DELETE"});n++}console.log("kong-cleaned",n)})()'
(cd $PRIVATE/e2e && node -e "0" && node mode.mjs direct 2>/dev/null | head -1 | tee /tmp/modeA0; grep -q 'before direct' /tmp/modeA0) || exit 6
echo "precondition: fixture reset (pre-race dump) + Kong residue cleanup, cluster A direct verified, overlay removed $(TZ=Asia/Shanghai date +%T)" >> ${OUT}/progress.log
docker exec kp-bridge-console-api-1 node -e "require('dns').lookup('example.com',e=>console.log('dns',e&&e.code))"
BRIDGE_ENV=$PRIVATE/rc1-e2e.env PCE_OUT=${OUT} node scripts/verification/production-smoke.mjs; echo "smoke exit $? $(TZ=Asia/Shanghai date +%T)" >> ${OUT}/progress.log
PCE_PROJECT=kp-bridge REDIS_SERVICE=redis KONG_SERVICE=kong BFF_BASE=https://127.0.0.1:48443 FAULT_ENV_FILE=$PRIVATE/rc1-e2e.env PCE_OUT=${OUT} COMPOSE_FILES=docker-compose.yml,deploy/compose/compose.production.yml node scripts/verification/fault-injection.mjs; echo "fault exit $? $(TZ=Asia/Shanghai date +%T)" >> ${OUT}/progress.log
DRILL_MODE=inplace DRILL_OUT=${OUT} DRILL_PRIVATE=$PRIVATE/drill BRIDGE_ENV=$PRIVATE/rc1-e2e.env node scripts/verification/pg-backup-restore-drill.mjs; echo "pg exit $? $(TZ=Asia/Shanghai date +%T)" >> ${OUT}/progress.log
C="docker compose -p kp-bridge --env-file $PRIVATE/rc1-e2e.env -f docker-compose.yml -f deploy/compose/compose.production.yml -f deploy/compose/compose.e2e-cluster-b.yml"
$C stop console-api
docker exec kp-bridge-console-db-1 psql -U kongos -d postgres -qc "select pg_terminate_backend(pid) from pg_stat_activity where datname='kongos' and pid<>pg_backend_pid()" -c "drop database kongos" -c "create database kongos owner kongos"
docker exec -i kp-bridge-console-db-1 pg_restore -U kongos -d kongos --no-owner < $PRIVATE/drill/${FIXTURE_DUMP:-console-fixture.dump}
$C up -d --wait
echo "fixture reset done $(TZ=Asia/Shanghai date +%T)" >> ${OUT}/progress.log
cd $PRIVATE/e2e; docker rm -f kp-rc1-kong-ro-tap; docker run -d --name kp-rc1-kong-ro-tap --user 0 --network container:kp-bridge-console-api-1 -v $PWD/sock:/s --entrypoint node kongpilot/console-api:v1.0.0-rc.2 /s/kong-readonly-tap.js; pkill -f 'node out.js'; (setsid node out.js > /tmp/out.log 2>&1 &); sleep 3
export NODE_TLS_REJECT_UNAUTHORIZED=0
node seed.mjs || exit 3
python3 - <<'PY'
import json,os,urllib.parse
env=dict(l.split('=',1) for l in open('../rc1-e2e.env').read().splitlines() if '=' in l and not l.startswith('#'))
S=json.load(open('secrets.json'))
S['dbUrl']='postgres://kongos:%s@%s:5432/kongos'%(urllib.parse.quote(env['CONSOLE_DATABASE_PASSWORD'],safe=''),os.environ['CONSOLE_DB_HOST'])
S['portalOrigin']=os.environ['PORTAL_ORIGIN']
json.dump(S,open('secrets.json','w'),indent=1)
PY
chmod 600 secrets.json
node mode.mjs approval | tee /tmp/modeA; grep -q ' approval' /tmp/modeA || exit 4
node mode.mjs approval $(python3 -c "import json;print(json.load(open('secrets.json'))['clusterB'])") | tee /tmp/modeB; grep -q ' approval' /tmp/modeB || exit 4
node publish-approval.mjs || exit 5
# kong residue cleanup (console DB restore does not wipe Kong DB; stale e2e services push fixtures off page 1)
KEEP=$(python3 -c "import json;print(json.load(open('secrets.json'))['kp004Service'])")
docker run --rm --network container:kp-bridge-console-api-1 -e KEEP="$KEEP" --entrypoint node kongpilot/console-api:v1.0.0-rc.2 -e 'const A="http://kong:8001";(async()=>{const s=(await (await fetch(A+"/services?size=1000")).json()).data;let n=0;for(const x of s){if(!/^(e2e|rc1e2e)-/.test(x.name)||x.name===process.env.KEEP)continue;const rs=(await (await fetch(A+"/services/"+x.id+"/routes")).json()).data;for(const r of rs)await fetch(A+"/routes/"+r.id,{method:"DELETE"});await fetch(A+"/services/"+x.id,{method:"DELETE"});n++}console.log("kong-cleaned",n)})()'
echo "kong residue cleanup keep=$KEEP $(TZ=Asia/Shanghai date +%T)" >> ${OUT}/progress.log
echo "seed+mode+publish done $(TZ=Asia/Shanghai date +%T)" >> ${OUT}/progress.log
cd "$REPO"
TZ=Asia/Shanghai KP_E2E_SELF_SIGNED=true NODE_TLS_REJECT_UNAUTHORIZED=0 KP_LAB_E2E=true KP_LAB_SECRETS=$PRIVATE/e2e/secrets.json KP_E2E_OUT=${OUT}/browser-e2e timeout 1800 node tests/e2e/m11-browser-matrix.mjs > ${OUT}/browser-e2e-run.log 2>&1; echo MX_EXIT $?
echo "matrix done $(TZ=Asia/Shanghai date +%T)" >> ${OUT}/progress.log
docker rm -f kp-rc1-kong-ro-tap; pkill -f 'node out.js'
echo MXDONE
echo "ALL DONE $(TZ=Asia/Shanghai date +%T)" >> ${OUT}/progress.log
