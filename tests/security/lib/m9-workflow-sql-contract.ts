import { readFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';

const migrationsDirectory=resolve(process.cwd(),'apps/console-api/src/infrastructure/migrations');
const tables=new Map<string,Map<string,string>>();
for(const name of readdirSync(migrationsDirectory).filter(name=>/^\d+.*\.sql$/.test(name)).sort()){
  const sql=readFileSync(resolve(migrationsDirectory,name),'utf8');
  for(const match of sql.matchAll(/CREATE TABLE(?: IF NOT EXISTS)?\s+(\w+)\s*\(([\s\S]*?)\);/gi)){
    const columns=new Map<string,string>();
    for(const column of match[2].matchAll(/^\s*(\w+)\s+(uuid|text|boolean|integer|bigint|jsonb|timestamptz)\b/gmi))columns.set(column[1],column[2].toLowerCase());
    tables.set(match[1],columns);
  }
  for(const match of sql.matchAll(/ALTER TABLE\s+(\w+)\s+ADD COLUMN(?: IF NOT EXISTS)?\s+(\w+)\s+(uuid|text|boolean|integer|bigint|jsonb|timestamptz)\b/gi)){
    if(!tables.has(match[1]))tables.set(match[1],new Map());tables.get(match[1])!.set(match[2],match[3].toLowerCase());
  }
}

export const migrationColumnType=(table:string,column:string):string|undefined=>tables.get(table)?.get(column);

/** A narrow independent schema contract for evidence-query UUID/text joins.
 * This is not a PostgreSQL parser or substitute for real database integration.
 * Types come from the actual migration DDL, rather than mock row values. */
export function assertWorkflowEvidenceSqlTypes(sql:string):void{
  const aliases=new Map<string,string>();
  for(const match of sql.matchAll(/\b(?:FROM|JOIN)\s+(\w+)\s+(\w+)/gi))if(tables.has(match[1]))aliases.set(match[2],match[1]);
  for(const match of sql.matchAll(/\b(\w+)\.(\w+)(?:::([a-z]+))?\s*=\s*(\w+)\.(\w+)(?:::([a-z]+))?\b/gi)){
    const leftTable=aliases.get(match[1]),rightTable=aliases.get(match[4]);
    if(!leftTable||!rightTable)continue;
    const left=match[3]??migrationColumnType(leftTable,match[2]),right=match[6]??migrationColumnType(rightTable,match[5]);
    if(!left||!right)throw new Error(`Unknown evidence column type: ${leftTable}.${match[2]} / ${rightTable}.${match[5]}`);
    if(left==='uuid'&&right==='text'||left==='text'&&right==='uuid')throw new Error(`PostgreSQL equality requires explicit cast: ${leftTable}.${match[2]} ${left} = ${rightTable}.${match[5]} ${right}`);
  }
}
