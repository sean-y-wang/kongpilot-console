import {describe,expect,it} from 'vitest';
import {workspaceIndexWhere} from '../../apps/console-api/src/modules/workspaces/workspace-index-scope';
const base:any={workspaceId:'pay',workspaceRevision:1,mode:'tag',workspaceTag:'kos-ws-pay',requestedTags:[],tagOperator:'and'};
describe('workspace index SQL projection',()=>{
 it('keeps workspace membership as an AND predicate when business tags use OR',()=>{const params:unknown[]=['cluster'];const where=workspaceIndexWhere({...base,requestedTags:['team-pay','team-audit'],tagOperator:'or'},params);expect(where.join(' AND ')).toContain('tags @> $2::text[]');expect(where.join(' AND ')).toContain('tags && $3::text[]');expect(where.join(' AND ')).toContain('=1');expect(params).toEqual(['cluster',['kos-ws-pay'],['team-pay','team-audit']]);});
 it('default includes historical untagged objects but excludes unknown or multiple workspace mirrors',()=>{const params:unknown[]=[];const where=workspaceIndexWhere({...base,mode:'default'},params).join(' AND ');expect(where).toContain('<=1');expect(where).toContain("workspace_tag<>'kos-ws-default'");expect(params).toEqual([]);});
 it('allows internal table aliases and rejects arbitrary SQL column input',()=>{expect(workspaceIndexWhere(base,[],'i.tags').join(' AND ')).toContain('unnest(i.tags)');expect(()=>workspaceIndexWhere(base,[],"tags); DROP TABLE users;--")).toThrow('Invalid internal index tags column');});
});
