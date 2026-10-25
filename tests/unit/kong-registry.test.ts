import 'reflect-metadata';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SecretService } from '../../apps/console-api/src/infrastructure/secret.service';
import { ClustersService } from '../../apps/console-api/src/modules/clusters/clusters.service';
import { DataSourcesService } from '../../apps/console-api/src/modules/data-sources/data-sources.service';

const clusterId = 'efc85a7f-d60d-45b9-8685-1efc6d4e776c';
const sourceId = 'a3ea3b8c-aa2b-48ae-9d7a-d8e8123b978b';
const actor = { user: { id: 'a35313a2-9968-4818-9f31-7b3066ce1728',username:'registry-admin',superAdmin:true }, requestId: 'rotation-request', ip: '127.0.0.1' };

describe('M0 registry metadata isolation and redacted audit', () => {
  let secrets: SecretService;
  let db: any;
  let audit: any;
  let kong: any;
  let authz: any;
  let registry: ClustersService;
  let dataSources: DataSourcesService;
  let previousClusterSecret: string;
  let previousSourceSecret: string;
  const clusterPublic = { id: clusterId, name: 'production', admin_url: 'http://kong:8001', environment: 'prod', labels: [], execution_mode: 'direct', connection_configured: true, revision: 1 };
  const sourcePublic = { id: sourceId, cluster_id: clusterId, name: 'metrics', type: 'prometheus', base_url: 'http://prometheus:9090', enabled: true, auth_configured: true, revision: 1 };
  beforeEach(() => {
    vi.stubEnv('CONSOLE_ENCRYPTION_KEY', 'ab'.repeat(32));
    vi.stubEnv('OUTBOUND_ALLOWED_HOSTS', 'kong,prometheus,loki');
    secrets = new SecretService();
    previousClusterSecret = secrets.encrypt({ type: 'bearer', token: 'previous-admin-token' }, `cluster:${clusterId}`);
    previousSourceSecret = secrets.encrypt({ type: 'bearer', token: 'previous-metrics-token' }, `data-source:${clusterId}:${sourceId}`);
    db = { exec: vi.fn().mockResolvedValue(1), query: vi.fn().mockResolvedValue([]), one: vi.fn(), transaction: vi.fn() };
    db.transaction.mockImplementation((fn: any) => fn(db));
    db.one.mockImplementation(async (sql: string) => sql.includes('lower(name)')?null:sql.startsWith('SELECT connection_secret') ? { connection_secret: previousClusterSecret } : sql.startsWith('SELECT auth_secret') ? { auth_secret: previousSourceSecret } : sql.includes('FROM data_sources') ? sourcePublic : clusterPublic);
    audit = { append: vi.fn().mockResolvedValue(undefined) };
    kong = { invalidate: vi.fn() };
    authz={assertConsole:vi.fn().mockResolvedValue(undefined),assertCluster:vi.fn().mockResolvedValue(undefined),isPlatformAdmin:vi.fn().mockResolvedValue(true),capabilities:vi.fn().mockResolvedValue({platformAdmin:true,clusters:[]}),snapshot:vi.fn().mockResolvedValue({user:{superAdmin:true},grants:[]}),permissionVersion:vi.fn().mockResolvedValue('version-1')};
    const operations:any={completed:vi.fn().mockResolvedValue(null),execute:vi.fn(async(_ctx:any,fn:any)=>db.transaction(fn))};
    registry = new ClustersService(db, secrets, kong, audit,authz,operations,{runActor:async(_c:any,fn:any)=>fn()} as any);
    dataSources = new DataSourcesService(db, secrets, registry, audit,authz,operations);
  });
  afterEach(() => vi.unstubAllEnvs());

  it('records admin auth rotation fingerprints while returning public configuration', async () => {
    const result = await registry.update(clusterId, { revision: 1, connection_auth: { type: 'bearer', token: 'rotated-admin-token' } }, actor);
    expect(result).not.toHaveProperty('connection_secret');
    const [event, tx] = audit.append.mock.calls[0];
    expect(tx).toBe(db);
    expect(event.before.connection_secret).toBe(previousClusterSecret);
    expect(event.after.connection_secret).not.toBe(previousClusterSecret);
    expect(secrets.redact(event.after).connection_secret).toMatch(/^\[REDACTED:/);
    expect(secrets.redact(event.after).connection_secret).not.toBe(secrets.redact(event.before).connection_secret);
    expect(JSON.stringify(event)).not.toContain('rotated-admin-token');
    expect(JSON.stringify(db.exec.mock.calls)).not.toContain('rotated-admin-token');
    expect(kong.invalidate).toHaveBeenCalledWith(clusterId);
  });
  it('records data-source auth rotation in the mutation transaction without exposing credentials', async () => {
    const result = await dataSources.update(clusterId, sourceId, { revision: 1, auth: { type: 'bearer', token: 'rotated-metrics-token' } }, actor);
    expect(result).not.toHaveProperty('auth_secret');
    const [event, tx] = audit.append.mock.calls[0];
    expect(tx).toBe(db);
    expect(event.before.auth_secret).toBe(previousSourceSecret);
    expect(secrets.redact(event.after).auth_secret).not.toBe(secrets.redact(event.before).auth_secret);
    expect(JSON.stringify(event)).not.toContain('rotated-metrics-token');
    expect(JSON.stringify(db.exec.mock.calls)).not.toContain('rotated-metrics-token');
  });
  it('preserves secret material and fingerprint during unrelated metadata edits', async () => {
    await registry.update(clusterId, { revision: 1, name: 'renamed' }, actor);
    const event = audit.append.mock.calls[0][0];
    expect(event.before.connection_secret).toBe(event.after.connection_secret);
    expect(db.exec.mock.calls[0][0]).not.toContain('connection_secret=');
  });
  it('requires both cluster and data-source identifiers in every resource lookup', async () => {
    await dataSources.get(clusterId, sourceId,actor);
    expect(db.one).toHaveBeenLastCalledWith(expect.stringContaining('WHERE cluster_id=$1 AND id=$2 AND deleted_at IS NULL'), [clusterId, sourceId]);
    db.one.mockImplementation(async (sql: string) => sql.includes('FROM data_sources') ? null : clusterPublic);
    await expect(dataSources.get(clusterId, sourceId,actor)).rejects.toMatchObject({ status: 404 });
  });
  it('rejects stale edits before appending a success audit', async () => {
    db.exec.mockResolvedValue(0);
    await expect(registry.update(clusterId, { revision: 1, name: 'stale-edit' }, actor)).rejects.toMatchObject({ status: 409 });
    expect(audit.append).not.toHaveBeenCalled();
  });
  it('requires exact name and explicit second confirmation before soft deactivation', async () => {
    await expect(registry.deactivate(clusterId, { confirm: true, confirm_name: 'wrong', revision: 1 }, actor)).rejects.toMatchObject({ status: 400 });
    await expect(registry.deactivate(clusterId, { confirm_name: 'production', revision: 1 }, actor)).rejects.toMatchObject({ status: 400 });
    expect(db.exec).not.toHaveBeenCalled();
    await expect(registry.deactivate(clusterId, { confirm: true, confirm_name: 'production', revision: 1 }, actor)).resolves.toEqual({ id: clusterId, deactivated: true });
    expect(db.exec.mock.calls[0][0]).toContain('deleted_at=now()');
    expect(db.exec.mock.calls[0][0]).not.toMatch(/DELETE FROM/);
    expect(audit.append).toHaveBeenCalledWith(expect.objectContaining({ action: 'deactivate' }), db);
  });
  it('rejects unsafe destinations and auth headers before saving', async () => {
    await expect(registry.create({ name: 'unsafe', admin_url: 'http://169.254.169.254' }, actor)).rejects.toMatchObject({ status: 403 });
    await expect(registry.update(clusterId, { revision: 1, connection_auth: { type: 'header', header_name: 'Host', header_value: 'evil' } }, actor)).rejects.toMatchObject({ status: 400 });
    expect(db.exec).not.toHaveBeenCalled();
  });
  it.each(['clusters-list','clusters-get','sources-list','sources-get'])('refuses %s data when permissions change during its metadata query',async read=>{
    let changed=false;
    authz.permissionVersion.mockImplementation(async()=>changed?'version-revoked':'version-1');
    db.query.mockImplementation(async()=>{changed=true;return [read.startsWith('clusters')?clusterPublic:sourcePublic];});
    const originalOne=db.one.getMockImplementation();
    db.one.mockImplementation(async(sql:string,...args:any[])=>{const value=await originalOne(sql,...args);if(sql.includes('FROM data_sources')||sql.includes('FROM clusters'))changed=true;return value;});
    const request=read==='clusters-list'?()=>registry.list(actor):read==='clusters-get'?()=>registry.get(clusterId,actor):read==='sources-list'?()=>dataSources.list(clusterId,actor):()=>dataSources.get(clusterId,sourceId,actor);
    await expect(request()).rejects.toMatchObject({status:403,response:{code:'PERMISSIONS_CHANGED'}});
    expect(db.exec).not.toHaveBeenCalled();
  });
});
