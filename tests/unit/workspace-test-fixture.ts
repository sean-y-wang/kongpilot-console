import { vi } from 'vitest';
import { NotFoundException } from '@nestjs/common';
import { WorkspaceResolverService } from '../../apps/console-api/src/modules/workspaces/workspace-resolver.service';
export const defaultWorkspaceId='0b7b9c25-cc08-4dad-a128-a9c015ef70e0';
export const payWorkspaceId='8c544f61-654e-48e4-9c14-1fc30430d3a3';
export const opsWorkspaceId='d33c1457-a848-4d53-9361-3243a0221f71';
export function workspaceFixture(clusterId:string){
  const rows=[['default',defaultWorkspaceId],['pay',payWorkspaceId],['ops',opsWorkspaceId]].map(([code,id])=>({id,code,cluster_id:clusterId,name:code,status:'active',is_default:code==='default',revision:1}));
  const db={exec:vi.fn().mockResolvedValue(1),one:vi.fn(async(sql:string,p:any[])=>{
    const row=rows.find(item=>item.cluster_id===p[0]&&(sql.includes("code='default'")?item.is_default:sql.includes('code=$2')?item.code===p[1]:item.id===p[1]));
    return row??null;
  })};
  const resolver=new WorkspaceResolverService(db as any);
  return {resolver,rows,db};
}
