import{afterEach,describe,it,expect,vi}from'vitest';
import{createHmac}from'node:crypto';
import{m8SnapshotAuditAckMatches}from'./lib/m8-manual-audit-acceptance.mjs';
afterEach(()=>vi.unstubAllEnvs());
describe('independent snapshot recovery-count audit comparison',()=>{
 it('verifies the keyed count marker and exact remaining ACK fields without changing the original audit',()=>{vi.stubEnv('CONSOLE_ENCRYPTION_KEY','4'.repeat(64));const ack={id:'synthetic',state:'deleted',recovery:{complete:26,requires_secret_input:0,requires_rotation:0,nonrestorable:0}},mask=`[REDACTED:${createHmac('sha256',Buffer.from('4'.repeat(64),'hex')).update('kongos-fingerprint:v1:0').digest('hex').slice(0,16)}]`,after={...ack,recovery:{...ack.recovery,requires_secret_input:mask}};const old=JSON.stringify(after);expect(m8SnapshotAuditAckMatches(after,ack)).toBe(true);expect(JSON.stringify(after)).toBe(old);expect(m8SnapshotAuditAckMatches({...after,state:'ready'},ack)).toBe(false);expect(m8SnapshotAuditAckMatches(after,{...ack,recovery:{...ack.recovery,requires_secret_input:1}})).toBe(false);expect(m8SnapshotAuditAckMatches({...after,recovery:{...after.recovery,requires_secret_input:'[REDACTED:0000000000000000]'}},ack)).toBe(false);});
 it('refuses an unkeyed or arbitrary masked string without opening runtime configuration',()=>{const ack={recovery:{requires_secret_input:'actual-secret'}},after={recovery:{requires_secret_input:'[REDACTED:0000000000000000]'}};expect(m8SnapshotAuditAckMatches(after,ack)).toBe(false);});
});
