import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { parse } from 'yaml';

describe('KP-009 production overlay evidence contract (no false closure)', () => {
  it('ships the evidence script and keeps commercialClosed false on static run', () => {
    expect(existsSync('scripts/verification/production-overlay.mjs')).toBe(true);
    const run = spawnSync(process.execPath, ['scripts/verification/production-overlay.mjs'], {
      encoding: 'utf8',
      env: { ...process.env, KP009_EVIDENCE_OUT: 'artifacts/M11/runs/20261024-live-kp' },
      timeout: 30_000,
    });
    expect(run.status).toBe(0);
    const evidence = JSON.parse(readFileSync('artifacts/M11/runs/20261024-live-kp/kp009-production-overlay-evidence.json', 'utf8'));
    expect(evidence).toMatchObject({
      commercialClosed: false,
      claimsClosed: false,
      runtimeVerified: false,
      secretsPrinted: false,
    });
    expect(evidence.totals.failed).toBe(0);
    expect(evidence.remainingForClosure.length).toBeGreaterThan(3);
    expect(evidence.checks.some((c: any) => c.id === 'csp_console_production_nginx' && c.passed)).toBe(true);
    expect(evidence.checks.some((c: any) => c.id === 'api_healthcheck_ready_path' && c.passed)).toBe(true);
    expect(evidence.checks.some((c: any) => c.id.startsWith('runtime_') && c.skipped)).toBe(true);
  });
});

describe('KP-004/006/007 live Kong evidence harness boundaries', () => {
  it('pins Kong OSS 1.5.1 and documents host-network rationale without production merge', () => {
    const compose = parse(readFileSync('deploy/compose/compose.live-kong-evidence.yml', 'utf8'));
    expect(compose.services['live-kong'].image).toBe('kong:1.5.1');
    expect(compose.services['live-kong-migrations'].image).toBe('kong:1.5.1');
    expect(compose.services['live-kong'].profiles).toEqual(['live-kong-evidence']);
    expect(compose.services['live-kong'].network_mode).toBe('host');
    expect(compose.services['live-kong'].environment.KONG_ADMIN_LISTEN).toBe('127.0.0.1:18001');
    expect(compose.services['live-kong'].environment.KONG_PROXY_LISTEN).toBe('127.0.0.1:18000');
    const text = readFileSync('deploy/compose/compose.live-kong-evidence.yml', 'utf8');
    expect(text).toContain('Never merge into production overlays');
    expect(text).toContain('198.18.0.0/15');
    expect(existsSync('scripts/verification/portal-live-kong.mjs')).toBe(true);
    const script = readFileSync('scripts/verification/portal-live-kong.mjs', 'utf8');
    expect(script).toContain('commercialClosed: false');
    expect(script).toContain('claimsClosed: false');
    expect(script).toContain('productBffHttp: false');
  });

  it('records prior live evidence artifact without claiming product closure when present', () => {
    const path = 'artifacts/M11/runs/20261024-live-kp/live-kong-proxy-evidence.json';
    if (!existsSync(path)) return;
    const evidence = JSON.parse(readFileSync(path, 'utf8'));
    expect(evidence.commercialClosed).toBe(false);
    expect(evidence.claimsClosed).toBe(false);
    expect(evidence.scope.productBffHttp).toBe(false);
    expect(evidence.scope.portalBrowser).toBe(false);
    expect(evidence.scope.fiveRootRecycle).toBe(false);
    if (evidence.allPassed) {
      const ids = evidence.steps.map((s: any) => s.id);
      expect(ids).toContain('kp006_proxy_with_issued_key');
      expect(ids).toContain('kp006_proxy_after_revoke_denied');
      expect(ids).toContain('kp004_proxy_after_reissue_ok');
      expect(ids).toContain('kp007_admin_cross_consumer_key_denied');
      expect(evidence.steps.every((s: any) => s.passed)).toBe(true);
    }
  });
});

describe('BFF/Portal HTTP live evidence harness boundaries', () => {
  it('ships BFF evidence compose + script without claiming commercial closure', () => {
    expect(existsSync('deploy/compose/compose.bff-live-evidence.yml')).toBe(true);
    expect(existsSync('scripts/verification/portal-http-flow.mjs')).toBe(true);
    const compose = parse(readFileSync('deploy/compose/compose.bff-live-evidence.yml', 'utf8'));
    expect(compose.services['bff-evidence-db'].network_mode).toBe('host');
    expect(compose.services['bff-evidence-redis'].network_mode).toBe('host');
    expect(compose.services['bff-evidence-db'].profiles).toEqual(['bff-live-evidence']);
    const script = readFileSync('scripts/verification/portal-http-flow.mjs', 'utf8');
    expect(script).toContain('commercialClosed: false');
    expect(script).toContain('claimsClosed: false');
    expect(script).toContain('portalIssueRevokeHttpVerified');
    const upstream = readFileSync('deploy/compose/compose.live-kong-evidence.yml', 'utf8');
    expect(upstream).toContain('0.0.0.0:25678');
  });

  it('records BFF/Portal HTTP artifact without commercialClosed when present', () => {
    const path = 'artifacts/M11/runs/20261024-bff-portal/bff-portal-http-evidence.json';
    if (!existsSync(path)) return;
    const evidence = JSON.parse(readFileSync(path, 'utf8'));
    expect(evidence.commercialClosed).toBe(false);
    expect(evidence.claimsClosed).toBe(false);
    expect(evidence.secretsPrinted).toBe(false);
    if (evidence.portalIssueRevokeHttpVerified) {
      for (const id of [
        'portal_credential_issue_approve_execute',
        'portal_issued_key_proxy_200',
        'portal_credential_revoke_approve_execute',
        'portal_revoked_key_proxy_denied',
      ]) {
        expect(evidence.checks.some((c: any) => c.id === id && c.passed)).toBe(true);
      }
    }
  });
});

describe('KP-009 runtime immutable image ready evidence contract', () => {
  it('ships runtime evidence script and keeps commercialClosed false on artifact', () => {
    expect(existsSync('scripts/verification/runtime-image-readiness.mjs')).toBe(true);
    const script = readFileSync('scripts/verification/runtime-image-readiness.mjs', 'utf8');
    expect(script).toContain('commercialClosed: false');
    expect(script).toContain('runtimeVerifiedPartial');
    const path = 'artifacts/M11/runs/20261024-bff-portal/kp009-runtime-image-ready-evidence.json';
    if (!existsSync(path)) return;
    const evidence = JSON.parse(readFileSync(path, 'utf8'));
    expect(evidence.commercialClosed).toBe(false);
    expect(evidence.claimsClosed).toBe(false);
    expect(evidence.secretsPrinted).toBe(false);
    expect(evidence.remainingForClosure.length).toBeGreaterThan(2);
    if (evidence.runtimeVerifiedPartial) {
      expect(evidence.checks.some((c: any) => c.id === 'runtime_health_ready_http_200' && c.passed)).toBe(true);
      expect(evidence.checks.some((c: any) => c.id === 'immutable_container_running' && c.passed)).toBe(true);
    }
  });

  it('records KP-004 five-root live recycle evidence without commercialClosed', () => {
    expect(existsSync('scripts/verification/recycle-bin-restore.mjs')).toBe(true);
    const script = readFileSync('scripts/verification/recycle-bin-restore.mjs', 'utf8');
    expect(script).toContain('PORTAL_PUBLISHED_OBJECT');
    expect(script).toContain('fiveRootOrdinaryCycleVerified');
    expect(script).toContain("commercialClosed");
    const path = 'artifacts/M11/runs/20261024-kp004-five-root/kp004-five-root-recycle-evidence.json';
    expect(existsSync(path)).toBe(true);
    const evidence = JSON.parse(readFileSync(path, 'utf8'));
    expect(evidence.commercialClosed).toBe(false);
    expect(evidence.claimsClosed).toBe(false);
    expect(evidence.portalPublishedDeleteFailFast).toBe(true);
    expect(evidence.fiveRootOrdinaryCycleVerified).toBe(true);
    expect(evidence.totals.failed).toBe(0);
    const ids = evidence.checks.map((c: { id: string }) => c.id);
    expect(ids).toContain('kp004_portal_published_delete_failfast');
    expect(ids).toContain('kp004_five_root_archive_delete_restore_all');
    for (const root of ['services', 'routes', 'consumers', 'upstreams', 'certificates']) {
      expect(ids).toContain(`original_id_restored_${root}`);
    }
  });

});
