import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {applyAcceptanceList,validateAcceptanceList} from '../../deploy/scripts/vulnerability-acceptance.mjs';

const NOW=Date.parse('2026-10-24T12:00:00Z');
const entry=(o={})=>({id:'CVE-2026-92392',image:'web',package:'curl',severity:'High',reason:'no upstream fix as of 2026-10-24',accepted:'2026-10-24',expires:'2026-12-31',reviewer:'kongpilot-maintainers',...o});
const finding=(o={})=>({id:'CVE-2026-92392',package:'curl',version:'8.22.0-r0',severity:'High',suppressed:false,fixAvailable:false,...o});
const rep=(component,findings,o={})=>({component,canary:false,inventoryAlerts:0,findings,...o});
const list=entries=>({version:1,entries});

test('exact unfixed match passes and is counted, canary ignored',()=>{
  const r=applyAcceptanceList([rep('web',[finding()]),{component:'native-cpe-control',canary:true,inventoryAlerts:0,findings:[finding({id:'CVE-2016-3191'})]}],list([entry()]),{now:NOW});
  assert.deepEqual({...r},{allFindingsResolved:true,accepted:1,unaccepted:0,entries:1});
});
test('empty list keeps every finding unresolved',()=>{assert.equal(applyAcceptanceList([rep('web',[finding()])],list([]),{now:NOW}).allFindingsResolved,false);});
test('new finding not on the list stays unresolved',()=>{const r=applyAcceptanceList([rep('web',[finding(),finding({id:'CVE-2026-99999'})])],list([entry()]),{now:NOW});assert.equal(r.allFindingsResolved,false);assert.equal(r.unaccepted,1);});
test('same CVE in another image or package is not covered',()=>{
  assert.equal(applyAcceptanceList([rep('web',[finding()]),rep('portal',[finding()])],list([entry()]),{now:NOW}).allFindingsResolved,false);
  assert.throws(()=>applyAcceptanceList([rep('web',[finding({package:'libcurl'})])],list([entry()]),{now:NOW}),{message:'IMAGE_ACCEPTANCE_STALE'});
});
test('severity change makes the entry stale and the finding unresolved',()=>{assert.throws(()=>applyAcceptanceList([rep('web',[finding({severity:'Critical'})])],list([entry()]),{now:NOW}),{message:'IMAGE_ACCEPTANCE_STALE'});});
test('fixable finding can never be accepted',()=>{assert.throws(()=>applyAcceptanceList([rep('web',[finding({fixAvailable:true})])],list([entry()]),{now:NOW}),{message:'IMAGE_ACCEPTANCE_FIXABLE_LISTED'});
  assert.equal(applyAcceptanceList([rep('web',[finding(),finding({id:'CVE-2026-1111',fixAvailable:true})])],list([entry()]),{now:NOW}).allFindingsResolved,false);});
test('stale entry fails',()=>{assert.throws(()=>applyAcceptanceList([rep('web',[])],list([entry()]),{now:NOW}),{message:'IMAGE_ACCEPTANCE_STALE'});});
test('expired entry fails after expiry day, valid on the day',()=>{
  assert.equal(applyAcceptanceList([rep('web',[finding()])],list([entry()]),{now:Date.parse('2026-12-31T23:00:00Z')}).allFindingsResolved,true);
  assert.throws(()=>applyAcceptanceList([rep('web',[finding()])],list([entry()]),{now:Date.parse('2027-01-01T00:00:01Z')}),{message:'IMAGE_ACCEPTANCE_EXPIRED'});
});
test('inventory alerts are never accepted',()=>{assert.equal(applyAcceptanceList([rep('web',[finding()],{inventoryAlerts:1})],list([entry()]),{now:NOW}).allFindingsResolved,false);});
test('malformed entries are rejected',()=>{
  for(const [bad,code] of [[{expires:'2027-06-01'},'IMAGE_ACCEPTANCE_EXPIRY_TOO_LONG'],[{expires:'2026-10-23'},'IMAGE_ACCEPTANCE_EXPIRY_TOO_LONG'],[{reviewer:''},'IMAGE_ACCEPTANCE_REVIEWER_REQUIRED'],
    [{reason:'accepted risk'},'IMAGE_ACCEPTANCE_ENTRY_INVALID'],[{image:'kong'},'IMAGE_ACCEPTANCE_ENTRY_INVALID'],[{id:'free text'},'IMAGE_ACCEPTANCE_ENTRY_INVALID'],[{severity:'Bad'},'IMAGE_ACCEPTANCE_ENTRY_INVALID'],[{extra:'x'},'IMAGE_ACCEPTANCE_ENTRY_INVALID']])
    assert.throws(()=>validateAcceptanceList(list([entry(bad)])),{message:code});
  assert.throws(()=>validateAcceptanceList(list([entry(),entry()])),{message:'IMAGE_ACCEPTANCE_DUPLICATE'});
  assert.throws(()=>validateAcceptanceList({version:2,entries:[]}),{message:'IMAGE_ACCEPTANCE_LIST_INVALID'});
  assert.throws(()=>applyAcceptanceList([rep('web',[finding()])],list([entry({accepted:'2026-11-20',reason:'no upstream fix as of 2026-11-20'})]),{now:NOW}),{message:'IMAGE_ACCEPTANCE_ENTRY_INVALID'});
});
test('checked-in list is scoped to the owner-approved unfixed findings only',()=>{
  const l=validateAcceptanceList(JSON.parse(readFileSync(new URL('../../deploy/security/image-vulnerability-acceptance.json',import.meta.url),'utf8')));
  assert.equal(l.entries.filter(e=>e.image==='api').length,31);
  const alpine=l.entries.filter(e=>e.image!=='api');assert.equal(alpine.length,8);
  assert.ok(alpine.every(e=>e.id==='CVE-2026-92392'&&e.package==='curl'||e.id==='CVE-2025-60876'&&['busybox','busybox-binsh','ssl_client'].includes(e.package)));
  assert.ok(l.entries.every(e=>e.expires==='2026-12-31'&&e.reason==='no upstream fix as of 2026-10-24'&&e.reviewer));
});
