import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {describe,it,expect} from 'vitest';
import {reconstructExpiredEpochs,METRICS_DIAGNOSTIC_PROGRAM,metadataRestoreDiagnosticContext} from '../../../deploy/scripts/diagnose-metadata-restore-metrics.mjs';

const sha=(value:unknown)=>createHash('sha256').update(JSON.stringify(value)).digest('hex');
function fixture(){
  const rows=Array.from({length:14},(_,i)=>({id:String(i).padStart(3,'0'),value:i,closed_at:i<7?'2026-10-11T05:34:00.000Z':null}));
  const pairs=Array.from({length:7},(_,i)=>({old_id:rows[i].id,new_id:rows[i+7].id,valid_from:'2026-10-11T05:34:00.000Z',
    close_reason:'membership_or_proof_changed',close_matches:true,expired:true,immutable_equal:true,immutable_fingerprint:'a'.repeat(64)}));
  const before=rows.slice(0,7).map(row=>({...row,closed_at:null}));
  return{rows,pairs,expected:{afterCount:14,afterSHA256:sha(rows),beforeCount:7,beforeSHA256:sha(before)}};
}
describe('bounded expired-proof diagnostic policy only; no runtime proof',()=>{
  it('reads the actual sealed public foundation shape without any runtime/private access',()=>{
    const result=metadataRestoreDiagnosticContext(readFileSync('artifacts/M6/portal-metadata-restore-repair-continuity.json'));
    expect(result.input.expected.beforeCount).toBe(2335);expect(result.input.expected.afterCount).toBe(2342);
    expect(result.apiId).toMatch(/^[a-f0-9]{64}$/);expect(result.sealed.allPassed).toBe(false);
  });
  it('restores exactly seven paired closures and reproduces the exact original digest',()=>{
    const f=fixture(),result=reconstructExpiredEpochs(f.rows,f.pairs,f.expected);
    expect(result.proved).toBe(true);expect(result.reconstructedBeforeSHA256).toBe(f.expected.beforeSHA256);
    expect(f.rows[0].closed_at).not.toBeNull();
  });
  it('refuses current drift before considering pair facts',()=>{
    const f=fixture();f.rows[0].value=999;
    expect(reconstructExpiredEpochs(f.rows,f.pairs,f.expected).reason).toBe('CURRENT_SNAPSHOT_DRIFTED');
  });
  it.each(['expired','immutable_equal','close_matches'])('refuses a non-proven %s condition',key=>{
    const f=fixture();f.pairs[0][key]=false;
    expect(reconstructExpiredEpochs(f.rows,f.pairs,f.expected).proved).toBe(false);
  });
  it('refuses a different before digest and only generates a syntactically valid fixed readonly program',()=>{
    const f=fixture();f.expected.beforeSHA256='f'.repeat(64);
    expect(reconstructExpiredEpochs(f.rows,f.pairs,f.expected).proved).toBe(false);
    expect(()=>new Function(METRICS_DIAGNOSTIC_PROGRAM)).not.toThrow();
  });
});
