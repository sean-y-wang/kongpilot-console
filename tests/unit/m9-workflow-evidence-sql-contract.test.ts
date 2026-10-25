import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import ts from 'typescript';
import { describe,expect,it } from 'vitest';
import { assertWorkflowEvidenceSqlTypes,migrationColumnType } from '../security/lib/m9-workflow-sql-contract';

const path=resolve(process.cwd(),'apps/console-api/src/modules/workflows/workflow.service.ts');
const source=ts.createSourceFile(path,readFileSync(path,'utf8'),ts.ScriptTarget.Latest,true,ts.ScriptKind.TS);
const queries:string[]=[];
function visit(node:ts.Node):void{
  if(ts.isCallExpression(node)&&ts.isPropertyAccessExpression(node.expression)&&node.expression.name.text==='one'){
    const literal=node.arguments[0];
    if(literal&&(ts.isStringLiteral(literal)||ts.isNoSubstitutionTemplateLiteral(literal))&&literal.text.includes('JOIN mutation_operations')&&literal.text.includes('JOIN workspace_migration_plans'))queries.push(literal.text);
  }
  ts.forEachChild(node,visit);
}
visit(source);

describe('M9 migration evidence SQL versus actual DDL types',()=>{
  it('derives the heterogeneous entity identifiers from the historical migrations',()=>{
    expect(migrationColumnType('mutation_operations','entity_id')).toBe('text');
    expect(migrationColumnType('workflow_steps','entity_id')).toBe('uuid');
    expect(migrationColumnType('workspace_migration_plans','id')).toBe('uuid');
  });
  it('validates actual terminal query column comparisons rather than assuming JavaScript string equality is PostgreSQL equality',()=>{
    expect(queries).toHaveLength(1);
    for(const query of queries)expect(()=>assertWorkflowEvidenceSqlTypes(query)).not.toThrow();
  });
  it('rejects the historical uncast UUID-to-text join independently of in-memory row values',()=>{
    const invalid='SELECT p.id FROM workspace_migration_plans p JOIN mutation_operations m ON p.id=m.entity_id';
    expect(()=>assertWorkflowEvidenceSqlTypes(invalid)).toThrow(/uuid = mutation_operations\.entity_id text/);
  });
  it('accepts an explicit text projection and the same-type UUID step anchor',()=>{
    const valid='SELECT p.id FROM workflow_steps s JOIN mutation_operations m ON m.id=s.operation_id JOIN workspace_migration_plans p ON p.id=s.entity_id AND m.entity_id=p.id::text';
    expect(()=>assertWorkflowEvidenceSqlTypes(valid)).not.toThrow();
  });
});
