import {resolve} from 'node:path';

// A pure plan lets offline checks prove later stages preserve monitoring keys
// and running collectors before any authorized runtime command is executed.
export function stagePlan({stage,compose,multicluster=false,observability=false,portal=false,notificationsTest=false,gitopsRunner=false,captureMetricsTokens=false,captureExistingMetrics=false,transitionStorage=false}) {
  const initialMetrics=observability&&stage==='M5';
  const portalActivation=portal&&stage==='M6';
  const deliveryActivation=notificationsTest&&stage==='M7';
  const steps=[];
  if(gitopsRunner)steps.push(['build-fixed-deck-runner','docker',[...compose,'build','console-deck-runner']],['verify-fixed-deck-toolchain','docker',['run','--rm','--network','none','--user','1000:1000','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges=true','--tmpfs','/tmp:rw,noexec,nosuid,nodev,size=256m,mode=1777','--entrypoint','node','kongpilot/deck-runner:1.2.4','/opt/kongos/verify-toolchain.mjs']]);
  if(portalActivation)steps.push(['continuity-before','node',['deploy/scripts/verify-m6-runtime-continuity.mjs','--before']]);
  if(portal)steps.push(['portal-environment','node',['deploy/scripts/prepare-portal-environment.mjs']]);
  if(deliveryActivation)steps.push(['isolated-delivery-materials','node',['deploy/scripts/prepare-event-receivers.mjs']]);
  steps.push(['compile','node',['deploy/scripts/prepare-development.mjs']],['migrate','docker',[...compose,'run','--rm','--no-deps','console-migrations']]);
  if(initialMetrics)steps.push(['enroll-metrics','node',['deploy/scripts/enroll-metrics.mjs','--discover',...(multicluster?['--multicluster']:[]),...(captureMetricsTokens?['--test-private-reference']:[])]]);
  if(transitionStorage)steps.push(
    ['move-kong-databases-preserving-volumes','docker',[...compose,'up','-d','--no-deps','--no-build','--force-recreate','--wait','--wait-timeout','45','kong-db','kong-secondary-db']],
    ['move-kong-gateways-preserving-volumes','docker',[...compose,'up','-d','--no-deps','--no-build','--force-recreate','--wait','--wait-timeout','45','kong','kong-secondary']],
  );
  if(deliveryActivation)steps.push(['build-isolated-delivery-receiver','docker',[...compose,'build','event-receiver']],['start-isolated-delivery-receivers','docker',[...compose,'up','-d','--no-deps','--no-build','--wait','--wait-timeout','45','event-receiver','event-mail']]);
  if(transitionStorage||initialMetrics||portalActivation||deliveryActivation)steps.push(['apply-api-config','docker',[...compose,'up','-d','--no-deps','--no-build','--force-recreate','--wait','--wait-timeout','45','console-api']]);
  if(initialMetrics)steps.push(
    ['prepare-metrics-storage','node',['deploy/scripts/prepare-metrics-storage.mjs',...(multicluster?['--multicluster']:[])]],
    ['prometheus-config','docker',['run','--rm','--network','none','--user','1000:1000','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges=true','--mount',`type=bind,src=${resolve('deploy/private/metrics/prometheus')},dst=/etc/prometheus,readonly`,'--entrypoint','/bin/promtool','prom/prometheus:v3.3.1','check','config','/etc/prometheus/prometheus.yml']],
    ['apply-metrics-services','docker',[...compose,'up','-d','--no-deps','--no-build','--wait','--wait-timeout','45','telemetry-collector','prometheus','loki']],
    ['prometheus-reload','docker',[...compose,'exec','-T','prometheus','wget','-Y','off','-q','-O','/dev/null','--post-data=','http://127.0.0.1:9090/-/reload']],
  );
  steps.push(['apply-web-config','docker',[...compose,'up','-d','--no-deps','--no-build','console-web']],['nginx-config','docker',[...compose,'exec','-T','console-web','nginx','-t']]);
  if(portal)steps.push(['apply-portal-web','docker',[...compose,'up','-d','--no-deps','--no-build','portal-web']],['portal-nginx-config','docker',[...compose,'exec','-T','portal-web','nginx','-t']]);
  steps.push(['restart','docker',[...compose,'restart',...(transitionStorage||initialMetrics||portalActivation||deliveryActivation?[]:['console-api']),'console-web',...(portal?['portal-web']:[])]]);
  if(portalActivation)steps.push(['continuity-after','node',['deploy/scripts/verify-m6-runtime-continuity.mjs','--after']]);
  if(captureExistingMetrics)steps.push(['capture-existing-metrics-test-reference','node',['deploy/scripts/capture-existing-metrics-test-reference.mjs','M6','--test-only',...(multicluster?['--multicluster']:[])]]);
  return steps;
}
