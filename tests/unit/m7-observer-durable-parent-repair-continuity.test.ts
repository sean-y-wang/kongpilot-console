import{it,expect}from'vitest';
import{OBSERVER_REPAIR_LABEL,OBSERVER_REPAIR_OUTPUT,observerRepairAfter}from'../../deploy/scripts/verify-m7-observer-durable-parent-repair-continuity.mjs';
it('keeps observer repair evidence distinct/sealed and protects other process/static facts',()=>{
 expect(OBSERVER_REPAIR_OUTPUT).not.toMatch(/workflow-submit|delivery-replay|notification-preference/);
 expect(()=>observerRepairAfter({label:OBSERVER_REPAIR_LABEL,allPassed:true},{})).toThrow('SEALED');
 const before={services:['console-api','event-receiver','event-mail'].map(name=>({name,id:name,pid:1,startedAt:'old',health:'healthy'})),migrations:[],materials:[],configurationSHA256:'same',database:{migrations:[],settings:'same',credentials:'same',generations:[2,1,0],nonowner:true},consoleAssets:[{sha256:'same'}],portalAssets:[{sha256:'same'}]},after=structuredClone(before),saved={label:OBSERVER_REPAIR_LABEL,allPassed:null,before};Object.assign(after.services[0],{pid:2,startedAt:'new'});
 expect(observerRepairAfter(saved,after).allPassed).toBe(true);after.services[1].pid=3;expect(observerRepairAfter(saved,after).allPassed).toBe(false);after.services[1].pid=1;after.portalAssets[0].sha256='changed';expect(observerRepairAfter(saved,after).allPassed).toBe(false);
});
