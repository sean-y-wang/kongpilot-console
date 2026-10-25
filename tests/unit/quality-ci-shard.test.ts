import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';
const parseYaml = createRequire(resolve('apps/console-api/package.json'))('yaml').parse;
import { qualityTestShard } from '../../deploy/scripts/ci-quality.mjs';
import { mergeShardSummaries } from '../../deploy/scripts/ci-quality-merge.mjs';

const shard = (index: number, count: number, total: number, extra: any = {}, files = [`tests/s${index}.test.ts`]) => ({
  completed: true, allPassed: true, testShard: { index, count },
  stages: [{ id: 'tests', testFiles: files, tests: { total, passed: total, failed: 0, skipped: 0, todo: 0, failedSuites: 0, totalSuites: 10, passedWithoutSkippedTests: true, ...extra } }],
});
const inv = ['tests/s1.test.ts', 'tests/s2.test.ts', 'tests/s3.test.ts'];

describe('sharded quality gate conserves coverage', () => {
  it('parses only bounded i/n shard values', () => {
    expect(qualityTestShard(undefined)).toBeUndefined();
    expect(qualityTestShard('2/3')).toEqual({ index: 2, count: 3 });
    for (const bad of ['0/3', '4/3', '1/9', '1', '1/3 --x', 'a/b']) expect(() => qualityTestShard(bad)).toThrow('CI_QUALITY_TEST_SHARD_INVALID');
  });
  it('passes only when the executed file set equals the unsharded inventory', () => {
    expect(mergeShardSummaries([shard(1, 3, 5), shard(2, 3, 6), shard(3, 3, 4)], inv)).toMatchObject({ allPassed: true, coverageConserved: true, totals: { total: 15 } });
    expect(mergeShardSummaries([shard(1, 3, 5), shard(2, 3, 6), shard(3, 3, 4)], [...inv, 'tests/s4.test.ts'])).toMatchObject({ allPassed: false, coverageConserved: false, missingFiles: ['tests/s4.test.ts'] });
    expect(mergeShardSummaries([shard(1, 3, 5), shard(2, 3, 6), shard(3, 3, 4)], inv.slice(0, 2))).toMatchObject({ allPassed: false, extraFiles: ['tests/s3.test.ts'] });
    expect(() => mergeShardSummaries([shard(1, 3, 5), shard(2, 3, 6, {}, ['tests/s1.test.ts']), shard(3, 3, 4)], inv)).toThrow('CI_MERGE_FILE_DUPLICATED');
  });
  it('rejects missing, duplicated, failed or skipped shards', () => {
    expect(() => mergeShardSummaries([shard(1, 3, 5), shard(2, 3, 6)], inv)).toThrow('CI_MERGE_SHARD_SET_INCOMPLETE');
    expect(() => mergeShardSummaries([shard(1, 3, 5), shard(1, 3, 6), shard(3, 3, 4)], inv)).toThrow('CI_MERGE_SHARD_SET_INCOMPLETE');
    expect(() => mergeShardSummaries([{ ...shard(1, 3, 5), allPassed: false }, shard(2, 3, 6), shard(3, 3, 4)], inv)).toThrow('CI_MERGE_SHARD_FAILED');
    expect(() => mergeShardSummaries([shard(1, 3, 5, { passedWithoutSkippedTests: false }), shard(2, 3, 6), shard(3, 3, 4)], inv)).toThrow('CI_MERGE_SHARD_TESTS_FAILED');
  });
  it('wires three shards, a merge gate and images behind the merge', () => {
    const wf: any = parseYaml(readFileSync('.github/workflows/quality.yml', 'utf8'));
    expect(wf.jobs['source-quality'].strategy.matrix.shard).toEqual([1, 2, 3]);
    expect(wf.jobs['source-quality'].env.KONGPILOT_TEST_SHARD).toBe('${{ matrix.shard }}/3');
    expect(wf.jobs['source-quality-merge'].needs).toBe('source-quality');
    expect(wf.jobs['immutable-images-amd64'].needs).toBe('source-quality-merge');
    for (const job of Object.values<any>(wf.jobs)) for (const step of job.steps.filter((s: any) => s.uses)) expect(step.uses).toMatch(/@[a-f0-9]{40}$/);
  });
});
