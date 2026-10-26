import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { parseDocument } from 'yaml';

const document = parseDocument(readFileSync('deploy/compose/compose.release-persistent.yml', 'utf8'), {
  customTags: [{ tag: '!reset', collection: 'seq', resolve: value => value }],
});
const overlay = document.toJS();

describe('persistent isolated acceptance overlay storage and telemetry isolation', () => {
  it('resets inherited PostgreSQL tmpfs and binds two separate named data volumes', () => {
    expect(document.errors).toEqual([]);
    for (const name of ['console-db', 'kong-db']) {
      expect(document.getIn(['services', name, 'tmpfs'], true)?.tag).toBe('!reset');
      expect(overlay.services[name].tmpfs).toEqual([]);
      expect(overlay.services[name].volumes).toEqual([`${name}-persistent:/var/lib/postgresql/data`]);
      expect(overlay.volumes[`${name}-persistent`]).toEqual({});
    }
  });

  it('keeps Redis authentication while enabling AOF in a named volume', () => {
    expect(overlay.services.redis.command).toEqual(['redis-server', '--requirepass', '${LAB_REDIS_PASSWORD:?}',
      '--appendonly', 'yes', '--appendfsync', 'everysec']);
    expect(overlay.services.redis.volumes).toEqual(['redis-persistent:/data']);
    expect(overlay.volumes['redis-persistent']).toEqual({});
  });

  it('exposes optional Prometheus only to the console edge without a host port or Admin network', () => {
    const prom = overlay.services.prometheus;
    expect(prom.profiles).toEqual(['release-monitoring']);
    expect(prom.networks).toEqual(['console-edge']);
    expect(prom).not.toHaveProperty('ports');
    expect(prom).not.toHaveProperty('network_mode');
    expect(prom.volumes).toContain('./prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro');
    expect(prom.volumes).toContain('prometheus-persistent:/prometheus');
    const config = readFileSync('deploy/prometheus/prometheus.yml', 'utf8');
    expect(config).toContain('console-api:3000');
    expect(config).not.toMatch(/targets:\s*\[[^\]]*(?:kong-admin|8001)/);
  });

  it('keeps an explicit host allowlist and does not change migration, application or Kong commands', () => {
    expect(overlay.services['console-api'].environment.OUTBOUND_ALLOWED_HOSTS)
      .toBe('${LAB_OUTBOUND_ALLOWED_HOSTS:-kong-admin,kong,echo,prometheus}');
    expect(overlay.services['console-api']).not.toHaveProperty('command');
    expect(overlay.services).not.toHaveProperty('console-migrations');
    expect(overlay.services).not.toHaveProperty('kong-migrations');
    expect(overlay.services).not.toHaveProperty('kong');
  });
});
