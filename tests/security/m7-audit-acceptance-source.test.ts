// @ts-nocheck -- passive ESM runner helper with synthetic sessions and transport.
import { describe, expect, it, vi } from 'vitest';
import { randomUUID, createHash } from 'node:crypto';

vi.mock('node:child_process', () => ({execFileSync: () => {throw Error('NO_RUNTIME_PROCESS_ALLOWED');}}));
import { auditAcceptance, auditAllWritesCoverage, auditDownloadTailAcceptance, auditIntegrityAcceptance, auditPatchMatches, auditWorkflowAcceptance, parseAuditCsv } from './lib/m7-audit-acceptance.mjs';

const cid = randomUUID(), wid = randomUUID(), foreignWid = randomUUID();
const fields = ['id', 'occurredAt', 'actorId', 'actorType', 'sourceIp', 'clusterId', 'workspaceId', 'entityType', 'entityId', 'action', 'result', 'requestId', 'workflowId', 'before', 'after', 'jsonPatch'];
function response(value, status = 200, bytes, headers = {}) {
  return {status, payload: {success: status < 300, data: value}, bytes: bytes ?? Buffer.from(JSON.stringify(value)), requestId: randomUUID(), response: {headers: {get: key => headers[key.toLowerCase()] ?? null}}};
}
function fixture(fault = '') {
  const users = new Map(), roles = new Map(), jobs = new Map(), audits = [], writes = [], checks = [];
  const admin = {label: 'synthetic-admin', user: {id: randomUUID()}}, readonly = {label: 'synthetic-readonly', user: {id: randomUUID()}};
  const actors = {admin, readonly, direct: {cid, wid}, foreign: {cid, wid: foreignWid}};
  let native, annotation;
  const h = {state: {testTag: 'm7-source-only', accounts: [], fixtures: [], requests: [], secrets: ['synthetic-secret-not-for-output'], eventOperations: []}, save: vi.fn(), remember: vi.fn(),
    check(condition, name, facts = {}) { if (!condition) throw Error(name); checks.push({name, ...facts}); },
    data(result) { h.check(result.status >= 200 && result.status < 300, 'synthetic JSON success'); return result.payload.data; },
    async login(label, username) { return {label, username, sid: randomUUID(), user: {id: users.get(username).id}}; },
    async poll(read, predicate, name) { const value = await read(); h.check(predicate(value), name); return value; },
  };
  const displayed = value => ({...structuredClone(value), tags: value.tags.map(tag => tag === 'kos-ws-synthetic' ? 'workspace:synthetic' : tag)});
  const deny = actor => actor.label.endsWith('tag-union') || actor.label.endsWith('entity-wrong-type') || actor.revoked;
  function view(action, before, after, requestId, patch, entityType = 'services') {
    const value = {id: randomUUID(), actorId: admin.user.id, actorType: 'user', sourceIp: '127.0.0.1', clusterId: cid, workspaceId: wid, entityType, entityId: native.id, action, before: structuredClone(before), after: structuredClone(after), jsonPatch: patch, workflowId: null, result: 'success', requestId, occurredAt: new Date().toISOString(), scopeQuality: 'verified'};
    audits.push(value); return value;
  }
  h.request = vi.fn(async (actor, path, method = 'GET', body, options = {}) => {
    const uri = new URL('https://synthetic.invalid' + path), route = uri.pathname, id = route.split('/').at(-1), requestId = randomUUID();
    const packet = {method, path: '/api/v1' + route, clusterId: route.includes('/clusters/') ? cid : null, workspaceId: uri.searchParams.get('workspaceId'), requestId, actorId: actor?.user?.id, sessionId: actor?.sid, body, bodySha256: createHash('sha256').update(JSON.stringify(body ?? null)).digest('hex'), key: options.key, state: 'response_observed', status: method === 'POST' ? 201 : 200};
    const write = method !== 'GET'; if (write) { h.state.requests.push(packet); writes.push(packet); }
    let result;
    if (route === '/iam/roles' && method === 'POST') { const value = {id: randomUUID(), revision: 1, ...body}; roles.set(value.id, value); result = response(value, 201); }
    else if (/\/iam\/roles\/[^/]+\/permissions$/.test(route)) {
      const value = roles.get(route.split('/')[3]);
      if (method === 'PUT') { value.permissions = body.permissions; value.revision++; if (!body.permissions.length) h.state.accounts.filter(account => account.role.id === value.id).forEach(account => {account.session.revoked = true;}); }
      result = response({items: value.permissions, revision: value.revision});
    } else if (route === '/iam/users' && method === 'POST') { const value = {id: randomUUID(), username: body.username}; users.set(value.username, value); result = response(value, 201); }
    else if (/\/iam\/users\/[^/]+\/role-bindings$/.test(route)) result = response({id: randomUUID(), ...body}, 201);
    else if (route.endsWith('/entities/services') && method === 'POST') {
      native = {id: randomUUID(), name: body.name, host: body.host, protocol: body.protocol, port: body.port, path: null, retries: 5, connect_timeout: 60000, read_timeout: 60000, write_timeout: 60000, created_at: 1700000000, updated_at: 1700000000, tags: [...body.tags, 'kos-ws-synthetic'], client_certificate: null, tls_verify: null, tls_verify_depth: null, ca_certificates: null};
      view('create', null, native, requestId, [{op: 'replace', path: '', value: structuredClone(native)}]); result = response({entity: displayed(native)}, 201);
    } else if (route.includes('/entities/services/')) {
      if (method === 'PATCH') {
        if (fault === 'unknown-write') { packet.state = 'response_unknown'; throw Error('M7_RESPONSE_UNKNOWN_STOP_ORIGINAL_PACKET_RETAINED'); }
        const before = structuredClone(native); native = {...native, ...body, tags: body.tags ? [...body.tags, 'kos-ws-synthetic'] : native.tags};
        const patch = [{op: 'replace', path: '/tags', value: [...native.tags]}, {op: 'replace', path: '/retries', value: native.retries}];
        const terminal = view('update', before, native, requestId, patch);
        if (fault === 'sparse-audit') { delete terminal.after.read_timeout; terminal.jsonPatch.push({op: 'remove', path: '/read_timeout'}); }
        if (fault === 'wrong-patch') terminal.jsonPatch = [];
        result = response({entity: displayed(native)});
      } else result = actor.label.startsWith('m7-source-only') || actor.label.includes('audit-') ? response(null, 403) : response({entity: displayed(native)});
    } else if (route.endsWith('/workspaces')) result = response({items: [{id: wid}]});
    else if (route.includes('/entity-annotations/')) {
      if (method === 'PUT') { annotation = {cluster_id: cid, entity_type: 'services', kong_id: native.id, ...body, revision: 1}; view('annotation.metadata.created', null, annotation, requestId, [{op: 'replace', path: '', value: structuredClone(annotation)}]); }
      result = response(annotation ?? {revision: 0, description: ''});
    } else if (route.endsWith('/audit/integrity')) result = actor === admin ? response({status: 'verified', scope: 'cluster', checkedRows: audits.length, complete: true, intervalComplete: true, reasonCodes: [], nextCursor: null}) : response(null, 403);
    else if (route.endsWith('/audit/exports') && method === 'POST') {
      const selected = audits.filter(value => value.requestId === body.requestId && value.entityType === body.entityType && value.entityId === body.entityId && (!body.action || value.action === body.action));
      const jobId = randomUUID(), cell = value => '"' + (typeof value === 'string' ? value : value == null ? '' : JSON.stringify(value)).replaceAll('"', '""') + '"';
      const bytes = Buffer.from(body.format === 'ndjson' ? selected.map(value => JSON.stringify(value)).join('\n') + '\n' : fields.map(cell).join(',') + '\r\n' + selected.map(value => fields.map(field => cell(value[field])).join(',')).join('\r\n') + '\r\n');
      const job = {id: jobId, state: 'succeeded', complete: true, format: body.format, rowCount: selected.length, bytesCount: bytes.length, capabilities: {download: true}};
      jobs.set(jobId, {job, bytes, actor, key: options.key}); result = response({domain: 'audit-export', durable: true, jobId, job}, 201);
    } else if (route.includes('/audit/exports/')) {
      const row = route.includes('/by-key/') ? [...jobs.values()].find(value => value.key === id) : jobs.get(route.endsWith('/download') ? route.split('/').at(-2) : id);
      if (row.actor !== actor) result = response(null, 404);
      else if (actor.revoked) result = response(null, 403);
      else if (route.endsWith('/download')) result = response(null, 200, row.bytes, {'content-length': String(row.bytes.length), 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'content-disposition': `attachment; filename="audit-${row.job.id}.${row.job.format}"`});
      else result = response(route.includes('/by-key/') ? {domain: 'audit-export', durable: true, jobId: row.job.id, job: row.job} : row.job);
    } else if (route.endsWith('/audit')) {
      const items = deny(actor) ? [] : audits.filter(value => ['requestId', 'entityType', 'entityId', 'action', 'result', 'workflowId'].every(key => !uri.searchParams.has(key) || value[key] === uri.searchParams.get(key)));
      result = response({items: structuredClone(items), total: null, size: 100, nextCursor: null});
    } else if (route.includes('/audit/')) result = method !== 'GET' || uri.searchParams.get('workspaceId') === foreignWid ? response(null, 404) : deny(actor) ? response(null, 403) : response(structuredClone(audits.find(value => value.id === id)));
    else throw Error('Unexpected synthetic BFF route');
    result.requestId = requestId; packet.status = result.status; packet.responseData = structuredClone(result.payload.data);
    if ((options.expected ?? [200, 201]).includes(result.status) === false) throw Error('Unexpected synthetic BFF status');
    return result;
  });
  const originalLogin = h.login;
  h.login = async (...args) => {const session = await originalLogin(...args); h.state.accounts.find(account => account.label === args[0]).session = session; return session;};
  return {h, actors, roles, jobs, audits, writes, checks};
}

describe('independent M7 actual-BFF audit helper source', () => {
  it('reads quoted JSON cells with embedded CRLF and doubled quotes using an independent CSV parser', () => {
    expect(parseAuditCsv('"id","after"\r\n"a","{""description"":""=SUM(1,2)\r\ntext""}"\r\n')).toEqual([['id', 'after'], ['a', '{"description":"=SUM(1,2)\r\ntext"}']]);
  });
  it.each(['"truncated', 'a,"b"garbage\r\n', 'bad"quote,cell\r\n', 'a,b\rc,d'])('rejects malformed independent CSV input without accepting partial records', value => {expect(() => parseAuditCsv(value)).toThrow(/M7_CSV_/);});
  it('independently verifies root arrays and JSON pointer escaping and rejects a plausible incorrect patch', () => {
    expect(auditPatchMatches({before: null, after: {values: [1, 2]}, jsonPatch: [{op: 'replace', path: '', value: {values: [1, 2]}}]})).toBe(true);
    expect(auditPatchMatches({before: {'a/b': {'~': [1]}}, after: {'a/b': {'~': [2, 3]}}, jsonPatch: [{op: 'replace', path: '/a~1b/~0', value: [2, 3]}]})).toBe(true);
    expect(auditPatchMatches({before: {retries: 5}, after: {retries: 3}, jsonPatch: [{op: 'replace', path: '/retries', value: 4}]})).toBe(false);
    expect(auditPatchMatches({before: {}, after: {}, jsonPatch: [{op: 'remove', path: '/missing'}]})).toBe(false);
  });
  it('executes complete transcript through only the supplied journal harness, with isolated exact historical grants and original export receipts', async () => {
    const f = fixture(), value = await auditAcceptance(f.h, f.actors);
    expect(value.auditEventIds).toHaveLength(2); expect(value.exportJobIds).toHaveLength(2);
    const union = [...f.roles.values()].find(value => value.code.endsWith('audit-tag-union')).permissions;
    expect(union).toHaveLength(2); expect(union.map(value => value.scope_values)).toEqual([['m7-source-only-audit-before'], ['m7-source-only-audit-after']]);
    expect(union.every(value => value.module === 'audit' && value.action === 'read' && value.scope_type === 'tag_group')).toBe(true);
    expect([...f.roles.values()].find(value => value.code.endsWith('audit-entity-wrong-type')).permissions[0].scope_values).toEqual([{entity_type: 'routes', entity_id: value.service.id}]);
    expect([...f.roles.values()].find(value => value.code.endsWith('audit-tag-complete')).permissions).toEqual([]);
    expect(f.writes.filter(value => value.path.endsWith('/audit/exports'))).toHaveLength(2);
    expect(new Set(f.writes.filter(value => value.path.endsWith('/audit/exports')).map(value => value.key)).size).toBe(2);
    expect(f.h.public.audit).toMatchObject({directScalarFormulaFixture: false, csvNestedFormulaFixture: true, sameGrantRequired: true, currentRevocation: true, integrity: {complete: true, intervalComplete: true}});
    expect(f.h.state.fixtures.some(entry => entry.type === 'entity_annotations' && entry.id === value.service.id)).toBe(true);
    expect(JSON.stringify(f.h.public)).not.toContain('synthetic-secret-not-for-output');
  });
  it.each(['sparse-audit', 'wrong-patch'])('rejects %s terminal before claiming full readbacks or creating restricted accounts', async fault => {
    const f = fixture(fault);
    await expect(auditAcceptance(f.h, f.actors)).rejects.toThrow(fault === 'sparse-audit' ? 'full actual before and after' : 'RFC6902');
    expect(f.writes.some(value => value.path === '/api/v1/iam/roles')).toBe(false); expect(f.h.public).toBeUndefined();
  });
  it('propagates original unknown native write without retries, replacement keys or later fixtures', async () => {
    const f = fixture('unknown-write');
    await expect(auditAcceptance(f.h, f.actors)).rejects.toThrow('M7_RESPONSE_UNKNOWN_STOP_ORIGINAL_PACKET_RETAINED');
    expect(f.writes.filter(value => value.method === 'PATCH')).toHaveLength(1);
    expect(f.writes.at(-1).state).toBe('response_unknown'); expect(f.roles.size).toBe(0); expect(f.jobs.size).toBe(0);
  });
});

describe('actual integrity and workflow helper evidence limits', () => {
  function harness(responses) { const requested = [], h = {check: (condition, name) => {if (!condition) throw Error(name);}, data: result => result.payload.data, request: vi.fn(async (_actor, path) => {requested.push(path); return response(responses.shift());})}; return {h, requested}; }
  it('continues a real opaque chain cursor through captured full-chain EOF', async () => {
    const f = harness([{status: 'partial', scope: 'cluster', checkedRows: 1000, complete: false, intervalComplete: false, reasonCodes: ['AUDIT_BUDGET_REACHED'], nextCursor: 'opaque-cursor'}, {status: 'verified', scope: 'cluster', checkedRows: 3, complete: true, intervalComplete: true, reasonCodes: [], nextCursor: null}]);
    expect(await auditIntegrityAcceptance(f.h, {}, cid)).toEqual({checkedRows: 1003, complete: true, intervalComplete: true});
    expect(f.requested).toEqual([`/clusters/${cid}/audit/integrity`, `/clusters/${cid}/audit/integrity?cursor=opaque-cursor`]);
  });
  it.each(['mismatch', 'unavailable'])('rejects actual %s result without reporting a completed interval', async status => {
    const f = harness([{status, scope: 'cluster', checkedRows: 0, complete: false, intervalComplete: false, reasonCodes: ['AUDIT_CONTENT_HASH_MISMATCH'], nextCursor: null}]);
    await expect(auditIntegrityAcceptance(f.h, {}, cid)).rejects.toThrow('real integrity page validates');
  });
  it('does not mistake partial interval success for a verified full chain', async () => {
    const f = harness([{status: 'verified', scope: 'cluster', checkedRows: 1, complete: false, intervalComplete: true, reasonCodes: [], nextCursor: null}]);
    await expect(auditIntegrityAcceptance(f.h, {}, cid)).rejects.toThrow('real interval EOF');
  });
  it('retains the exact requested trusted interval across cursor pages and verifies its final bounds', async () => {
    const interval = {fromSequence: '101', toSequence: '1101'}, f = harness([{status: 'partial', scope: 'cluster', checkedRows: 1000, complete: false, intervalComplete: false, reasonCodes: ['AUDIT_BUDGET_REACHED'], nextCursor: 'opaque'}, {status: 'verified', scope: 'cluster', checkedRows: 1, complete: false, intervalComplete: true, reasonCodes: [], nextCursor: null, verifiedInterval: interval}]);
    expect(await auditIntegrityAcceptance(f.h, {}, cid, interval)).toEqual({checkedRows: 1001, complete: false, intervalComplete: true});
    expect(f.requested[1]).toBe(`/clusters/${cid}/audit/integrity?fromSequence=101&toSequence=1101&cursor=opaque`);
  });
  it('rejects12 exhausted opaque pages without claiming complete verification', async () => {
    const f = harness(Array.from({length: 12}, () => ({status: 'partial', scope: 'cluster', checkedRows: 1000, complete: false, intervalComplete: false, reasonCodes: ['AUDIT_BUDGET_REACHED'], nextCursor: 'opaque'})));
    await expect(auditIntegrityAcceptance(f.h, {}, cid)).rejects.toThrow('real interval EOF'); expect(f.h.request).toHaveBeenCalledTimes(12);
  });
  it('requires actual approval receipts before workflow audit acceptance', async () => {
    const f = fixture(); await expect(auditWorkflowAcceptance(f.h, f.actors)).rejects.toThrow('actual completed original event workflow receipts'); expect(f.h.request).not.toHaveBeenCalled();
  });
  it('binds actual handler and completion to the observed execute request rather than a guessed workflow ID', async () => {
    const f = fixture(), workflowId = randomUUID(), requestId = randomUUID(), entityId = randomUUID();
    f.h.state.eventOperations.push({approval: true, workflowId, handler: 'event.channel.save', cid, wid});
    f.h.state.requests.push({method: 'POST', path: `/api/v1/clusters/${cid}/workflows/${workflowId}/execute`, clusterId: cid, workspaceId: wid, requestId, actorId: f.actors.admin.user.id, status: 201});
    const common = {actorId: f.actors.admin.user.id, actorType: 'user', sourceIp: '127.0.0.1', clusterId: cid, workspaceId: wid, before: null, after: null, jsonPatch: [], workflowId, result: 'success', requestId, occurredAt: new Date().toISOString(), scopeQuality: 'verified'};
    f.audits.push({...common, id: randomUUID(), entityType: 'notification_channels', entityId, action: 'event.channel.save'}, {...common, id: randomUUID(), entityType: 'workflows', entityId: workflowId, action: 'workflow.execute'});
    expect(await auditWorkflowAcceptance(f.h, f.actors)).toHaveLength(2);
    f.audits[0].requestId = randomUUID(); await expect(auditWorkflowAcceptance(f.h, f.actors)).rejects.toThrow('correlated completion audit');
  });
});

describe('original audit download checkpoint unused tail, source only', () => {
  async function checkpoint() {
    const f = fixture(), original = f.h.request; let tamper = true;
    f.h.request = vi.fn(async (...args) => {
      const result = await original(...args);
      if (args[1].includes('/download') && args[4]?.raw === true && tamper) {
        tamper = false; const headers = result.response.headers;
        result.response.headers = {get: key => key.toLowerCase() === 'content-disposition' ? 'attachment; filename="wrong-file.ndjson"' : headers.get(key)};
      }
      return result;
    });
    await expect(auditAcceptance(f.h, f.actors)).rejects.toThrow('exact bounded bytes');
    expect(f.jobs.size).toBe(1); expect([...f.jobs.values()][0].job.format).toBe('ndjson');
    f.h.request = original; return f;
  }
  it('reads the original NDJSON job and performs only the first CSV export and disposable grant revocation', async () => {
    const f = await checkpoint(), packets = structuredClone(f.h.state.requests), prefixLength = packets.length;
    const value = await auditDownloadTailAcceptance(f.h, f.actors);
    expect(f.h.state.requests.slice(0, prefixLength)).toEqual(packets);
    const unusedWrites = f.h.state.requests.slice(prefixLength);
    expect(unusedWrites).toHaveLength(2);
    expect(unusedWrites[0]).toMatchObject({method: 'POST', path: `/api/v1/clusters/${cid}/audit/exports`, body: {format: 'csv'}});
    expect(unusedWrites[1]).toMatchObject({method: 'PUT', body: {permissions: []}});
    expect(f.jobs.size).toBe(2); expect(value.exportJobIds[0]).toBe([...f.jobs.values()][0].job.id);
    expect(f.h.public.audit).toMatchObject({sameGrantRequired: true, typedEntityScope: true, currentRevocation: true, originalNdjsonExportRecreated: false, originalNativeWritesReplayed: false, originalAccountsRecreated: false});
    expect(f.h.state.auditDownloadTail.state).toBe('completed');
    await expect(auditDownloadTailAcceptance(f.h, f.actors)).rejects.toThrow('repeated tail');
    expect(f.h.state.requests).toHaveLength(prefixLength + 2);
  });
  it.each(['unknown', 'foreign-actor', 'foreign-SID', 'body-hash', 'wrong-kind', 'missing-account', 'duplicate-job', 'already-csv', 'already-revoked'])('rejects %s checkpoint before any read or new write', async variant => {
    const f = await checkpoint(), exportPacket = f.h.state.requests.find(packet => packet.path.endsWith('/audit/exports')), account = f.h.state.accounts.find(account => account.label === 'audit-tag-complete');
    if (variant === 'unknown') exportPacket.state = 'response_unknown';
    if (variant === 'foreign-actor') exportPacket.actorId = randomUUID();
    if (variant === 'foreign-SID') exportPacket.sessionId = randomUUID();
    if (variant === 'body-hash') exportPacket.bodySha256 = '0'.repeat(64);
    if (variant === 'wrong-kind') exportPacket.body.format = 'csv';
    if (variant === 'missing-account') f.h.state.accounts = f.h.state.accounts.filter(value => value !== account);
    if (variant === 'duplicate-job') f.h.state.fixtures.push({...f.h.state.fixtures.find(value => value.type === 'audit_export_jobs')});
    if (variant === 'already-csv') f.h.state.requests.push({method: 'POST', path: `/api/v1/clusters/${cid}/audit/exports`, body: {format: 'csv', requestId: f.h.state.requests.find(packet => packet.path.includes('/entity-annotations/')).requestId}});
    if (variant === 'already-revoked') f.h.state.requests.push({method: 'PUT', path: `/api/v1/iam/roles/${account.role.id}/permissions`, body: {permissions: []}});
    const count = f.h.state.requests.length; f.h.request.mockClear();
    await expect(auditDownloadTailAcceptance(f.h, f.actors)).rejects.toThrow();
    expect(f.h.request).not.toHaveBeenCalled(); expect(f.h.state.requests).toHaveLength(count);
  });
  it.each(['nosniff, nosniff', 'nosniff, unsafe', '', null])('keeps strict single nosniff contract: %s fails original read before unused CSV or revocation', async value => {
    const f = await checkpoint(), original = f.h.request, prefixLength = f.h.state.requests.length;
    f.h.request = vi.fn(async (...args) => {
      const result = await original(...args);
      if (args[1].includes('/download') && args[4]?.raw === true) {
        const headers = result.response.headers;
        result.response.headers = {get: key => key.toLowerCase() === 'x-content-type-options' ? value : headers.get(key)};
      }
      return result;
    });
    await expect(auditDownloadTailAcceptance(f.h, f.actors)).rejects.toThrow('exact bounded bytes');
    expect(f.h.state.requests).toHaveLength(prefixLength); expect(f.jobs.size).toBe(1);
    expect(f.h.state.auditDownloadTail.state).toBe('started'); expect(f.h.public?.audit).toBeUndefined();
    expect(f.h.request.mock.calls[0][1]).toContain('/audit/exports/by-key/');
    expect(f.h.request.mock.calls.every(args => (args[2] ?? 'GET') === 'GET')).toBe(true);
  });
  it('an unknown first CSV create stops before revocation, integrity or any replacement export key', async () => {
    const f = await checkpoint(), original = f.h.request, prefixLength = f.h.state.requests.length;
    f.h.request = vi.fn(async (...args) => {
      if (args[2] === 'POST' && args[3]?.format === 'csv') {
        f.h.state.requests.push({method: args[2], path: args[1], body: structuredClone(args[3]), key: args[4].key, state: 'response_unknown'});
        throw Error('M7_RESPONSE_UNKNOWN_STOP_ORIGINAL_PACKET_RETAINED');
      }
      return original(...args);
    });
    await expect(auditDownloadTailAcceptance(f.h, f.actors)).rejects.toThrow('M7_RESPONSE_UNKNOWN_STOP_ORIGINAL_PACKET_RETAINED');
    expect(f.h.state.requests).toHaveLength(prefixLength + 1); expect(f.h.state.requests.at(-1).state).toBe('response_unknown');
    expect(f.h.state.auditDownloadTail.state).toBe('started'); expect(f.h.public?.audit).toBeUndefined();
    await expect(auditDownloadTailAcceptance(f.h, f.actors)).rejects.toThrow('no unresolved write');
    expect(f.h.state.requests).toHaveLength(prefixLength + 1);
  });
});

describe('100 percent original write audit closure source', () => {
  function coverageFixture() {
    const actorId = randomUUID(), actor = {user: {id: actorId}}, actual = new Map(), calls = [];
    const h = {state: {requests: [], fixtures: [], scopes: {direct: {cid, wid}}, secrets: []}, check(condition, name) {if (!condition) throw Error(name);}, data: result => result.payload.data};
    h.request = vi.fn(async (_actor, path) => {
      calls.push(path); const uri = new URL('https://synthetic.invalid' + path), requestId = uri.searchParams.get('requestId');
      const record = actual.get(requestId), actualCluster = uri.pathname.includes('/clusters/') ? cid : null;
      return response({items: record && record.clusterId === actualCluster ? [record] : [], total: null, nextCursor: null});
    });
    function add({clusterId = null, result = 'success', observedActor = actorId, action = 'iam.write', body, path = '/api/v1/iam/roles', responseData, workflowId = null} = {}) {
      const requestId = randomUUID(), auditId = randomUUID();
      const packet = {method: 'POST', path, state: 'response_observed', status: 201, requestId, actorId, clusterId: null, body, responseData};
      const view = {id: auditId, actorId: observedActor, actorType: 'user', sourceIp: '127.0.0.1', clusterId, workspaceId: clusterId ? wid : null, entityType: 'roles', entityId: randomUUID(), action, before: null, after: null, jsonPatch: [], workflowId, result, requestId, occurredAt: new Date().toISOString(), scopeQuality: 'legacy_unknown'};
      h.state.requests.push(packet); actual.set(requestId, view); return {packet, view};
    }
    return {h, actor, actors: {admin: actor, direct: {cid, wid}}, add, actual, calls};
  }
  it('finds real global auth and IAM snake scoped terminals without trusting packet.clusterId omission', async () => {
    const f = coverageFixture();
    const login = f.add({path: '/api/v1/auth/login', observedActor: randomUUID(), action: 'login'}); login.packet.actorId = null;
    f.add({clusterId: cid, body: {cluster_id: cid, workspace_id: wid}});
    const roleId = randomUUID(); f.h.state.fixtures.push({type: 'roles', id: roleId, cid, wid});
    f.add({clusterId: cid, path: `/api/v1/iam/roles/${roleId}/permissions`});
    const result = await auditAllWritesCoverage(f.h, f.actors);
    expect(result).toMatchObject({successfulWrites: 3, coveredWrites: 3, terminalAuditRows: 3, allCovered: true});
    expect(f.calls).toHaveLength(3); expect(f.calls[0]).toContain('/audit/global?requestId='); expect(f.calls[1]).toContain('/audit?scope=cluster&requestId=');
  });
  it('counts durable workflow submission separately and does not claim configuration execution', async () => {
    const f = coverageFixture(), workflowId = randomUUID();
    f.add({clusterId: cid, action: 'workflow.submit', workflowId, body: {clusterId: cid}, responseData: {domain: 'workflow', workflowId, configurationCommitted: false}});
    expect(await auditAllWritesCoverage(f.h, f.actors)).toMatchObject({successfulWrites: 1, coveredWrites: 1, submissionOnlyWrites: 1, auditedWriteRequests: 0});
  });
  it('refuses pending-only and a terminal attributed to a different actor', async () => {
    const pending = coverageFixture(); pending.add({result: 'pending', action: 'iam.write.requested'});
    await expect(auditAllWritesCoverage(pending.h, pending.actors)).rejects.toThrow('actual successful terminal audit'); expect(pending.h.public).toBeUndefined();
    const wrongActor = coverageFixture(); wrongActor.add({observedActor: randomUUID()});
    await expect(auditAllWritesCoverage(wrongActor.h, wrongActor.actors)).rejects.toThrow('actual successful terminal audit'); expect(wrongActor.h.public).toBeUndefined();
  });
  it('stops before reads if any original write remains unknown or prepared', async () => {
    const f = coverageFixture(); f.add().packet.state = 'response_unknown';
    await expect(auditAllWritesCoverage(f.h, f.actors)).rejects.toThrow('unresolved original request packets'); expect(f.h.request).not.toHaveBeenCalled();
  });
  it('includes a normal same-SID refresh appended by coverage reads in its final actual write denominator', async () => {
    const f = coverageFixture(); f.add(); const read = f.h.request;
    f.h.request = vi.fn(async (...args) => {if (f.h.state.requests.length === 1) f.add({path: '/api/v1/auth/refresh', action: 'refresh'}); return read(...args);});
    expect(await auditAllWritesCoverage(f.h, f.actors)).toMatchObject({successfulWrites: 2, coveredWrites: 2, allCovered: true}); expect(f.h.request).toHaveBeenCalledTimes(2);
  });
});
