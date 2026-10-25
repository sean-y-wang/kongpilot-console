import { describe, expect, it } from 'vitest';
import { assertM8CurrentTimerPolicy } from './lib/m8-current-timer-policy.mjs';
const context = { id:'original',area:{cid:'cluster',wid:'workspace'},actorId:'actor',name:'original timer' };
const policy = { id:'original',clusterId:'cluster',workspaceId:'workspace',ownerUserId:'actor',name:'original timer',state:'active',revision:3,currentVersion:1,intervalMinutes:5,nextRunAt:'2026-10-11T14:24:47.811Z',capabilities:{write:true} };
describe('actual recurring timer current CAS',()=>{
  it('accepts a genuine later interval revision and returns it unchanged',()=>expect(assertM8CurrentTimerPolicy(policy,context)).toBe(policy));
  it.each([{revision:1},{revision:3.5},{currentVersion:2},{ownerUserId:'foreign'},{workspaceId:'foreign'},{clusterId:'foreign'},{state:'paused'},{intervalMinutes:1},{nextRunAt:'bad'},{capabilities:{write:false}}])('rejects a changed current authority/policy %j',(patch)=>expect(()=>assertM8CurrentTimerPolicy({...policy,...patch},context)).toThrow('M8_CURRENT_ORIGINAL_TIMER_POLICY_REQUIRED'));
});
