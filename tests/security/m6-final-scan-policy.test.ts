import {describe,it,expect} from 'vitest';
// @ts-expect-error Node helper intentionally stays executable without a build.
import {assertFinalM6Evidence,finalM6SecretForms,finalM6RuntimeLogAdapter,finalM6RuntimeLogsPassed} from './lib/m6-final-scan-policy.mjs';

const reference=()=>({phase:'cleanup-complete',browserKeyScan:{phase:'scanner-material-verified',credentialId:'test-issued-credential'}});
const evidence=()=>({http:{passed:1057,failed:0},browser:{passed:1,failed:0},manual:{allPassed:true},cleanup:{allPassed:true},material:{allPassed:true,keyValuePublished:false,keyRetainedPrivately:true,audited:true,scannerRevealPosts:1,nativeWrites:0}});
describe('final M6 credential coverage and post-cleanup logs',()=>{
  it('requires the new browser credential proof even after the other acceptance gates pass',()=>{
    const e=evidence();expect(()=>assertFinalM6Evidence(reference(),e)).not.toThrow();
    for(const field of ['material','cleanup','browser','manual']){
      const bad:any=structuredClone(e);delete bad[field];expect(()=>assertFinalM6Evidence(reference(),bad)).toThrow('FINAL_M6_EVIDENCE_INCOMPLETE');
    }
  });
  it.each(['result-unknown','raw-key-retained','before-single-owner-reveal'])('blocks deletion of private evidence with unresolved material phase %s',phase=>{
    const r=reference();r.browserKeyScan.phase=phase;expect(()=>assertFinalM6Evidence(r,evidence())).toThrow();
  });
  it('does not let cleanup success mask a failed or unaudited material capture',()=>{
    for(const fault of [{allPassed:false},{audited:false},{keyRetainedPrivately:false},{keyValuePublished:true},{scannerRevealPosts:2},{nativeWrites:1}]){
      const e=evidence();Object.assign(e.material,fault);expect(()=>assertFinalM6Evidence(reference(),e)).toThrow();
    }
  });
  it('rejects a missing, nonnumeric or invalid HTTP acceptance count',()=>{
    for(const passed of [undefined,NaN,'1057',Infinity,-1,0]){
      const e:any=evidence();e.http.passed=passed;expect(()=>assertFinalM6Evidence(reference(),e)).toThrow();
    }
  });
  it('scans raw, JSON, URI and base64 forms, including new Unicode keys',()=>{
    const key='temporary-凭证/"\\value';const forms=finalM6SecretForms([key,key,null,'']);
    expect(forms).toContain(key);expect(forms).toContain(JSON.stringify(key).slice(1,-1));
    expect(forms).toContain(encodeURIComponent(key));expect(forms).toContain(Buffer.from(key).toString('base64'));
    expect(new Set(forms).size).toBe(forms.length);
  });
  it('stops the final scan on a missing container or log leak, without publishing the secret',()=>{
    const checks:any[]=[];const h=finalM6RuntimeLogAdapter(reference(),['private-canary'],checks);
    h.requireLive();expect(()=>h.check(false,'Logs/Redaction','actual service failed')).toThrow('FINAL_M6_RUNTIME_LOG_FAILED');
    expect(checks).toEqual([{group:'Logs/Redaction',name:'actual service failed',passed:false}]);
    expect(JSON.stringify(checks)).not.toContain('private-canary');
  });
  it('cannot collect a final log proof before cleanup is finished',()=>{
    const r=reference();r.phase='HTTP-complete';expect(()=>finalM6RuntimeLogAdapter(r,[],[]).requireLive()).toThrow('FINAL_M6_CLEANUP_REQUIRED');
  });
  it('requires seven distinct real service logs, including the isolated Kong, and no raw output',()=>{
    const services=['kong','kong-secondary','kong-portal','console-api','console-web','portal-web','telemetry-collector'].map(service=>({service,knownSecretDetected:false}));
    const logs={services,allPassed:true,rawLogsPublished:false};expect(finalM6RuntimeLogsPassed(logs)).toBe(true);
    for(const patch of [{services:services.filter(s=>s.service!=='kong-portal')},{services:[...services.slice(1),services[1]]},{rawLogsPublished:true},{services:services.map(s=>({...s,knownSecretDetected:s.service==='kong-portal'}))}])expect(finalM6RuntimeLogsPassed({...logs,...patch})).toBe(false);
  });
});
