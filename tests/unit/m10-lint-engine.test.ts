import { describe, expect, it, vi } from 'vitest';
import { performance } from 'node:perf_hooks';
import { evaluateLintRules, parseLintPath, validateLintRules } from '../../apps/console-api/src/modules/governance/lint-engine';
import type { GovernanceLintRule, LintPredicate } from '../../apps/console-api/src/modules/governance/lint-types';
import { lintFixture, lintObject } from './m10-lint-fixture';

function rule(then: LintPredicate, change: Partial<GovernanceLintRule> = {}): GovernanceLintRule {
  return { code: 'test.rule', given: { entityTypes: ['services'] }, then, enabled: true, severity: 'warn', description: 'Test requirement', ...change };
}
describe('M10 restricted Lint DSL', () => {
  it('freezes validated copies and rejects arbitrary native/script payloads', () => {
    const source = rule({ path: 'port', op: 'min', value: 1 }), frozen = validateLintRules([source]);
    (source.then as any).value = 500; expect((frozen[0].then as any).value).toBe(1); expect(Object.isFrozen(frozen[0].then)).toBe(true);
    expect(() => validateLintRules([{ ...source, nativeRequests: [{ method: 'DELETE', path: '/services' }] }])).toThrow('GOVERNANCE_RULE_UNKNOWN_PROPERTY');
  });
  it.each(['$.host', '..host', 'host()', 'host[0]', 'host[?(@.a)]', 'host.*', 'host.', '__proto__.x', 'x.constructor', 'config.redis_password', 'config.client_secret', 'key'])('rejects dangerous/unsupported path %s', path => {
    expect(() => parseLintPath(path)).toThrow('GOVERNANCE_RULE_INVALID_PATH');
  });
  it('allows finite nested wildcard paths without broad secret-name false positives', () => {
    expect(parseLintPath('healthchecks.active.healthy.http_statuses[*]')).toEqual(['healthchecks', 'active', 'healthy', 'http_statuses', '*']);
    expect(parseLintPath('config.key_names[*]')).toEqual(['config', 'key_names', '*']);
  });
  it.each(['eval', 'sql', 'fetch', 'jsonpath'])('rejects unsupported predicate %s', op => {
    expect(() => validateLintRules([rule({ op } as any)])).toThrow('GOVERNANCE_RULE_UNKNOWN_PREDICATE');
  });
  it('rejects cycles, custom prototypes, nonfinite/function scalars and getters without invoking them', () => {
    const getter = vi.fn(() => 'rule'); const access = { ...rule({ op: 'required' }) }; Object.defineProperty(access, 'code', { get: getter, enumerable: true });
    expect(() => validateLintRules([access])).toThrow('GOVERNANCE_RULE_RESERVED_PROPERTY'); expect(getter).not.toHaveBeenCalled();
    const array = [rule({ op: 'required' })]; Object.defineProperty(array, '0', { get: getter, enumerable: true });
    expect(() => validateLintRules(array)).toThrow('GOVERNANCE_RULE_RESERVED_PROPERTY'); expect(getter).not.toHaveBeenCalled();
    const cyclic: any = rule({ op: 'required' }); cyclic.then = cyclic;
    expect(() => validateLintRules([cyclic])).toThrow('GOVERNANCE_RULE_CYCLIC');
    expect(() => validateLintRules([Object.assign(Object.create({}), rule({ op: 'required' }))])).toThrow('GOVERNANCE_RULE_INVALID_OBJECT');
    expect(() => validateLintRules([rule({ op: 'equals', value: Infinity })])).toThrow('GOVERNANCE_RULE_INVALID_SCALAR');
    expect(() => validateLintRules([rule({ op: 'equals', value: (() => true) as any })])).toThrow('GOVERNANCE_RULE_INVALID_OBJECT');
    const symbolProperty = rule({ op: 'required' }); Object.defineProperty(symbolProperty, Symbol.toPrimitive, { get: getter });
    expect(() => validateLintRules([symbolProperty])).toThrow('GOVERNANCE_RULE_RESERVED_PROPERTY'); expect(getter).not.toHaveBeenCalled();
  });
  it('enforces codes, duplicate identity, rule count, structural depth and byte limits', () => {
    expect(() => validateLintRules([rule({ op: 'required' }), rule({ op: 'required' })])).toThrow('GOVERNANCE_RULE_INVALID_CODE');
    expect(() => validateLintRules(Array.from({ length: 201 }, () => rule({ op: 'required' })))).toThrow('GOVERNANCE_RULE_LIMIT');
    let then: LintPredicate = { op: 'required' }; for (let i = 0; i < 17; i++) then = { not: then };
    expect(() => validateLintRules([rule(then)])).toThrow('GOVERNANCE_RULE_COMPLEXITY');
    expect(() => validateLintRules([rule({ op: 'equals', value: 'x'.repeat(16_385) })])).toThrow('GOVERNANCE_RULE_UNSAFE_VALUE');
    expect(() => validateLintRules([rule({ op: 'equals', value: '[REDACTED:secret]' })])).toThrow('GOVERNANCE_RULE_UNSAFE_VALUE');
  });
  it.each([
    [false, 'required', 0], [0, 'required', 0], [null, 'required', 1], ['', 'required', 1], [[], 'required', 1],
    [null, 'exists', 0], [false, 'exists', 0],
  ] as const)('distinguishes %j for %s rather than treating falsy values as absent', async (host, op, failed) => {
    const result = await evaluateLintRules(lintFixture([lintObject('services', { host })]), [rule({ path: 'host', op })]);
    expect(result.ruleResults[0].failedObjects).toBe(failed); expect(result.ruleResults[0].evaluatedObjects).toBe(1);
  });
  it('distinguishes absent field from explicit null for exists', async () => {
    const object = lintObject('services'); const result = await evaluateLintRules(lintFixture([object]), [rule({ path: 'host', op: 'exists', value: false })]);
    expect(result.findings).toHaveLength(0); expect(result.ruleResults[0].evaluatedObjects).toBe(1);
  });
  it.each([
    [{ path: 'port', op: 'type', value: 'integer' }, { port: 80 }],
    [{ path: 'protocol', op: 'enum', values: ['http', 'https'] }, { protocol: 'https' }],
    [{ path: 'retries', op: 'equals', value: 0 }, { retries: 0 }],
    [{ path: 'tags', op: 'includes', value: 'team:pay' }, { tags: ['team:pay'] }],
    [{ path: 'port', op: 'min', value: 1 }, { port: 80 }],
    [{ path: 'port', op: 'max', value: 65535 }, { port: 80 }],
    [{ path: 'host', op: 'length', min: 1, max: 20 }, { host: 'api.internal' }],
    [{ path: 'tags', op: 'tags_contains', value: 'owner:', match: 'prefix' }, { tags: ['owner:payments'] }],
  ] as const)('executes finite predicate %j', async (then, payload) => {
    const result = await evaluateLintRules(lintFixture([lintObject('services', payload)]), [rule(then as LintPredicate)]);
    expect(result.findings).toHaveLength(0); expect(result.ruleResults[0].evaluatedObjects).toBe(1);
  });
  it('evaluates nested record/array values with schema support', async () => {
    const object = lintObject('upstreams', { healthchecks: { active: { healthy: { http_statuses: [200, 201, 500] } } } });
    const result = await evaluateLintRules(lintFixture([object]), [rule({ op: 'max', value: 299 }, { given: { entityTypes: ['upstreams'], path: 'healthchecks.active.healthy.http_statuses[*]' } })]);
    expect(result.ruleResults[0]).toMatchObject({ evaluatedObjects: 3, failedObjects: 1 }); expect(result.findings[0].status).toBe('confirmed');
  });
  it('reports unsupported schema fields and missing plugin-schema fields as not evaluated', async () => {
    const object = lintObject('services', { imaginary: 'value' });
    const result = await evaluateLintRules(lintFixture([object]), [rule({ path: 'imaginary', op: 'required' })]);
    expect(result.findings[0]).toMatchObject({ status: 'not_evaluated', reasonCodes: ['FIELD_NOT_SUPPORTED_BY_SCHEMA'] });
    const plugin = lintObject('plugins', { name: 'rate-limiting', config: {} });
    const nested = await evaluateLintRules(lintFixture([plugin]), [rule({ path: 'config.imaginary', op: 'required' }, { given: { entityTypes: ['plugins'] } })]);
    expect(nested.findings[0].status).toBe('not_evaluated');
  });
  it('does not call accessor fields or accessor array elements', async () => {
    const getter = vi.fn(() => 'owner:pay'), object = lintObject('services'); Object.defineProperty(object.payload, 'host', { get: getter });
    const tags: any[] = []; Object.defineProperty(tags, '0', { get: getter, enumerable: true }); (object.payload as any).tags = tags;
    const result = await evaluateLintRules(lintFixture([object]), [rule({ all: [{ path: 'host', op: 'exists', value: false }, { path: 'tags', op: 'tags_contains', value: 'owner:', match: 'prefix' }] })]);
    expect(getter).not.toHaveBeenCalled(); expect(result.findings[0].status).toBe('not_evaluated');
  });
  it('honors Boolean unknown logic and filters without exposing values', async () => {
    const object = lintObject('services', { host: '[REDACTED:field]', port: 80 });
    const result = await evaluateLintRules(lintFixture([object]), [rule({ all: [{ path: 'host', op: 'required' }, { path: 'port', op: 'min', value: 100 }] })]);
    expect(result.findings[0].status).toBe('confirmed'); expect(JSON.stringify(result)).not.toContain('[REDACTED');
    const filtered = await evaluateLintRules(lintFixture([object]), [rule({ op: 'required' }, { given: { entityTypes: ['services'], where: { path: 'port', op: 'min', value: 100 } } })]);
    expect(filtered.ruleResults[0].skippedObjects).toBe(1); expect(filtered.findings).toHaveLength(0);
  });
  it('will not inspect inventory sensitive paths even if their safe projection appears present', async () => {
    const object = { ...lintObject('services', { host: 'safe-looking' }), sensitiveFields: ['/host'] };
    const result = await evaluateLintRules(lintFixture([object]), [rule({ path: 'host', op: 'equals', value: 'safe-looking' })]);
    expect(result.findings[0]).toMatchObject({ status: 'not_evaluated', reasonCodes: ['FIELD_MASKED'] });
  });
  it('treats projected/workspace list gaps as unknown references, but authorized cluster absence as a violation', async () => {
    const object = lintObject('services', { client_certificate: { id: 'ca98f7cd-9585-4c7d-92b7-95fd173a7553' } });
    const input = [rule({ path: 'client_certificate', op: 'reference_exists', entityType: 'certificates' })];
    const whole = lintFixture([object]), absent = await evaluateLintRules(whole, input); expect(absent.findings[0].status).toBe('confirmed');
    const workspace = { ...whole, collections: whole.collections.map(collection => ({ ...collection, extent: 'workspace' as const })) };
    expect((await evaluateLintRules(workspace, input)).findings[0].status).toBe('not_evaluated');
    const forbidden = { ...whole, referenceObservations: [{ entityType: 'certificates' as const, nativeId: (object.payload.client_certificate as any).id, state: 'forbidden' as const }] };
    expect((await evaluateLintRules(forbidden, input)).findings[0].status).toBe('not_evaluated');
  });
  it('accepts authorized GET404 proofs but ignores nonauthoritative absent observations', async () => {
    const id = 'ca98f7cd-9585-4c7d-92b7-95fd173a7553', object = lintObject('services', { client_certificate: { id } });
    const context = { ...lintFixture([object]), projection: true, referenceObservations: [{ entityType: 'certificates' as const, nativeId: id, state: 'absent' as const, authoritative: false }] };
    const input = [rule({ path: 'client_certificate', op: 'reference_exists', entityType: 'certificates' })];
    expect((await evaluateLintRules(context, input)).findings[0].status).toBe('not_evaluated');
    expect((await evaluateLintRules({ ...context, referenceObservations: [{ ...context.referenceObservations[0], authoritative: true }] }, input)).findings[0].status).toBe('confirmed');
  });
  it('reports zero selected objects and disabled rules without inventing coverage', async () => {
    const result = await evaluateLintRules(lintFixture(), [rule({ op: 'required' }), rule({ op: 'required' }, { code: 'disabled.rule', enabled: false })]);
    expect(result.ruleResults).toMatchObject([{ evaluatedObjects: 0, state: 'evaluated' }, { evaluatedObjects: 0, state: 'disabled' }]);
  });
  it('reports zero selected wildcard targets for an empty array, while an absent array remains a missing-field requirement', async () => {
    const input = [rule({ op: 'required' }, { given: { entityTypes: ['services'], path: 'tags[*]' } })];
    const empty = await evaluateLintRules(lintFixture([lintObject('services', { tags: [] })]), input);
    expect(empty.ruleResults[0]).toMatchObject({ evaluatedObjects: 0, failedObjects: 0 }); expect(empty.findings).toHaveLength(0);
    const absent = await evaluateLintRules(lintFixture([lintObject('services', { tags: null })]), input); expect(absent.ruleResults[0].failedObjects).toBe(1);
  });
  it('rejects forged oversized/native identifiers before they enter findings or reference indexes', async () => {
    const object = { ...lintObject('services'), nativeId: 'x'.repeat(100_000) };
    await expect(evaluateLintRules(lintFixture([object]), [rule({ op: 'required' })])).rejects.toThrow('GOVERNANCE_INVENTORY_INVALID_OBJECT');
  });
  it('runs regex in one isolated finite batch with honest unsupported/timeout outcomes', async () => {
    const good = await evaluateLintRules(lintFixture([lintObject('services', { name: 'api-pay' })]), [rule({ path: 'name', op: 'matches', pattern: '^api-[a-z]+$' })]);
    expect(good.findings).toHaveLength(0); expect(good.budget.regexCases).toBe(1);
    const bad = await evaluateLintRules(lintFixture([lintObject('services', { name: 'bad name' })]), [rule({ path: 'name', op: 'matches', pattern: '^api-[a-z]+$' })]);
    expect(bad.findings[0].status).toBe('confirmed');
    const unsupported = await evaluateLintRules(lintFixture([lintObject('services', { name: 'api' })]), [rule({ path: 'name', op: 'matches', pattern: '[[:alpha:]]+' })]);
    expect(unsupported.findings[0].status).toBe('not_evaluated');
  });
  it('terminates catastrophic regex and keeps the main event loop responsive', async () => {
    const started = performance.now(); let ticks = 0; const timer = setInterval(() => ticks++, 5);
    const result = await evaluateLintRules(lintFixture([lintObject('services', { name: 'a'.repeat(1000) + '!' })]), [rule({ path: 'name', op: 'matches', pattern: '^(a+)+$' })]);
    clearInterval(timer); expect(performance.now() - started).toBeLessThan(1500); expect(ticks).toBeGreaterThan(1);
    expect(result.findings[0]).toMatchObject({ status: 'not_evaluated', reasonCodes: ['REGEX_UNAVAILABLE_OR_TIMEOUT'] });
  });
  it('bounds a 10000-object x 200-rule run rather than evaluating two million assertions', async () => {
    const objects = Array.from({ length: 10_000 }, () => lintObject('services', { port: 80 }));
    const rules = Array.from({ length: 200 }, (_, index) => rule({ path: 'port', op: 'min', value: 1 }, { code: `rule.${index}` }));
    const started = performance.now(), result = await evaluateLintRules(lintFixture(objects), rules, { operationLimit: 2000 });
    expect(performance.now() - started).toBeLessThan(1000); expect(result.complete).toBe(false); expect(result.reasonCodes).toContain('ANALYSIS_BUDGET_EXHAUSTED');
    expect(result.budget.operations).toBeLessThan(4000);
  });
  it('bounds wildcard expansion, regex cases and finding count', async () => {
    const object = lintObject('services', { tags: Array.from({ length: 300 }, () => 'team:pay') });
    const expanded = await evaluateLintRules(lintFixture([object]), [rule({ op: 'required' }, { given: { entityTypes: ['services'], path: 'tags[*]' } })]);
    expect(expanded.reasonCodes).toContain('ANALYSIS_BUDGET_EXHAUSTED');
    const cases = await evaluateLintRules(lintFixture([lintObject('services', { name: 'one' }), lintObject('services', { name: 'two' })]), [rule({ path: 'name', op: 'matches', pattern: '.*' })], { regexCaseLimit: 1 });
    expect(cases.reasonCodes).toContain('REGEX_CASE_BUDGET_EXHAUSTED'); expect(cases.complete).toBe(false);
    const findings = await evaluateLintRules(lintFixture([lintObject('services', { port: 0 }), lintObject('services', { port: 0 })]), [rule({ path: 'port', op: 'min', value: 1 })], { findingLimit: 1 });
    expect(findings.findings).toHaveLength(1); expect(findings.complete).toBe(false);
  });
});
