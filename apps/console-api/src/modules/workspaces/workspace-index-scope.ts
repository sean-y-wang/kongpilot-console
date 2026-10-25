import type { WorkspaceFilter } from './workspace-resolver.service';

/** The index is a projection. Consumers must also verify fresh native membership. */
export function workspaceIndexWhere(scope:WorkspaceFilter,params:unknown[],tagsColumn='tags'):string[]{
 if(!/^(?:[a-z_]+\.)?tags$/.test(tagsColumn))throw new Error('Invalid internal index tags column');
 const where:string[]=[];
 const reserved=`(SELECT count(*) FROM unnest(${tagsColumn}) AS workspace_tag WHERE workspace_tag LIKE 'kos-ws-%')`;
 if(scope.mode==='tag'){
  params.push([scope.workspaceTag]);where.push(`${tagsColumn} @> $${params.length}::text[]`,`${reserved}=1`);
 }else{
  where.push(`${reserved}<=1`,`NOT EXISTS (SELECT 1 FROM unnest(${tagsColumn}) AS workspace_tag WHERE workspace_tag LIKE 'kos-ws-%' AND workspace_tag<>'kos-ws-default')`);
 }
 if(scope.requestedTags.length){
  params.push(scope.requestedTags);where.push(`${tagsColumn} ${scope.tagOperator==='or'?'&&':'@>'} $${params.length}::text[]`);
 }
 return where;
}
