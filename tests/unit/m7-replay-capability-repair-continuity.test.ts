import{describe,it,expect}from'vitest';
import{REPLAY_REPAIR_LABEL,REPLAY_REPAIR_OUTPUT,replayRepairAfter}from'../../deploy/scripts/verify-m7-replay-capability-repair-continuity.mjs';
describe('independent replay projection repair record',()=>{
 it('preserves old sealed records and rejects any static byte change',()=>{
  expect(REPLAY_REPAIR_OUTPUT).not.toMatch(/outbox-worker|events-query|notification-preference/);
  expect(()=>replayRepairAfter({label:REPLAY_REPAIR_LABEL,allPassed:true},{})).toThrow('SEALED');
  const before={services:['console-api','event-receiver','event-mail'].map(name=>({name,id:name,pid:1,startedAt:'old',health:'healthy'})),migrations:[],materials:[],configurationSHA256:'same',database:{migrations:[],settings:'same',credentials:'same',generations:[2,1,0],nonowner:true},staticAssets:[{sha256:'same'}]};
  const after=structuredClone(before);Object.assign(after.services[0],{pid:2,startedAt:'new'});
  expect(replayRepairAfter({label:REPLAY_REPAIR_LABEL,allPassed:null,before},after).allPassed).toBe(true);
  after.staticAssets[0].sha256='changed';expect(replayRepairAfter({label:REPLAY_REPAIR_LABEL,allPassed:null,before},after).allPassed).toBe(false);
 });
});
