import{describe,it,expect}from'vitest';
import{WORKFLOW_AUDIT_REPAIR_LABEL,WORKFLOW_AUDIT_REPAIR_OUTPUT,workflowAuditRepairAfter}from'../../deploy/scripts/verify-m7-workflow-audit-metadata-repair-continuity.mjs';
describe('independent workflow metadata repair continuity',()=>{
 it('does not reuse sealed records and protects the new Nginx configuration and all static assets',()=>{
  expect(WORKFLOW_AUDIT_REPAIR_OUTPUT).not.toMatch(/edge-nosniff|delivery-replay|notification-preference/);
  expect(()=>workflowAuditRepairAfter({label:WORKFLOW_AUDIT_REPAIR_LABEL,allPassed:true},{})).toThrow('SEALED');
  const before={services:['console-api','event-receiver','event-mail'].map(name=>({name,id:name,pid:1,startedAt:'old',health:'healthy'})),migrations:[],materials:[],configurationSHA256:'single-nosniff',database:{migrations:[],settings:'same',credentials:'same',generations:[2,1,0],nonowner:true},consoleAssets:[{sha256:'same'}],portalAssets:[{sha256:'same'}]};
  const after=structuredClone(before);Object.assign(after.services[0],{pid:2,startedAt:'new'});const saved={label:WORKFLOW_AUDIT_REPAIR_LABEL,allPassed:null,before};
  expect(workflowAuditRepairAfter(saved,after).allPassed).toBe(true);after.configurationSHA256='duplicate-nosniff';expect(workflowAuditRepairAfter(saved,after).allPassed).toBe(false);after.configurationSHA256='single-nosniff';after.consoleAssets[0].sha256='changed';expect(workflowAuditRepairAfter(saved,after).allPassed).toBe(false);
 });
});
