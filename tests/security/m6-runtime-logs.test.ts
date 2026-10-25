import { describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { verifyM6RuntimeLogs } from './lib/m6-runtime-logs.mjs';
vi.mock('node:child_process', () => ({ execFileSync: vi.fn(), spawnSync: vi.fn() }));

function fixture(secret: string) {
  vi.mocked(execFileSync).mockImplementation((command, args) => {
    if (args?.[0] === 'compose') return 'a'.repeat(64);
    if (args?.[0] === 'inspect') return 'kongos_console';
    return 'b'.repeat(12);
  });
  return { secrets: [secret], referenceData: { liveStartedAt: new Date().toISOString(), tokens: [] }, requireLive: vi.fn(), check(condition: boolean, id: string, name: string) { if (!condition) throw new Error(`${id}: ${name}`); } };
}
describe('M6 actual-container log verifier offline regressions', () => {
  it('detects a known credential on stderr without publishing its literal value', () => {
    const token = randomUUID(), harness = fixture(token);
    vi.mocked(spawnSync).mockReturnValue({ status: 0, stdout: 'safe access log', stderr: token } as any);
    let error: Error | undefined;
    try { verifyM6RuntimeLogs(harness); } catch (caught) { error = caught as Error; }
    expect(error?.message).toContain('Logs/Redaction');
    expect(error?.message.includes(token)).toBe(false);
  });
  it('checks all six actual services and both output channels on clean logs', () => {
    const harness = fixture(randomUUID());
    vi.mocked(spawnSync).mockReturnValue({ status: 0, stdout: 'safe access log', stderr: 'safe structured error' } as any);
    const evidence = verifyM6RuntimeLogs(harness);
    expect(evidence.allPassed).toBe(true); expect(evidence.rawLogsPublished).toBe(false);
    expect(evidence.services).toHaveLength(6); expect(spawnSync).toHaveBeenCalledTimes(6);
  });
  it('also scans the fixed actual C3 service only with the exact trusted isolated scope',()=>{
    const harness:any=fixture(randomUUID());harness.referenceData.portalTestTargets={primary:{id:randomUUID(),adminUrl:'http://kong-portal-admin-endpoint:8001',proxyOrigin:'http://127.0.0.1:10000'}};
    vi.mocked(spawnSync).mockReturnValue({status:0,stdout:'safe access',stderr:''}as any);const result=verifyM6RuntimeLogs(harness);expect(result.services.map(row=>row.service)).toContain('kong-portal');expect(result.services).toHaveLength(7);
  });
  it.each(['http://kong:8001','http://foreign.invalid:8001'])('rejects untrusted C3 alias %s before log collection',adminUrl=>{
    const harness:any=fixture(randomUUID());harness.referenceData.portalTestTargets={primary:{id:randomUUID(),adminUrl,proxyOrigin:'http://127.0.0.1:10000'}};expect(()=>verifyM6RuntimeLogs(harness)).toThrow();expect(spawnSync).not.toHaveBeenCalled();
  });
});
