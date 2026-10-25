import 'reflect-metadata';
import {readFileSync} from 'node:fs';
import {describe,expect,it} from 'vitest';
import {normalizeSchema} from '../../apps/console-api/src/modules/config-transfer/schema-normalization';

const recorded=JSON.parse(readFileSync(new URL('../fixtures/kong-1.5.1/plugin-schema-response-transformer.json',import.meta.url),'utf8'));
describe('Kong 1.5 required record create defaults',()=>{
 it('expands omitted required records and their safe nested defaults in the actual response-transformer schema',()=>{
  const input={add:{headers:['X-KongPilot-Corpus:owned-marker']}};
  const result=normalizeSchema(input,recorded,{defaults:true,required:true});
  expect(result).toMatchObject({remove:{headers:[],json:[]},rename:{headers:[]},replace:{headers:[],json:[],json_types:[]},add:{headers:input.add.headers,json:[],json_types:[]},append:{headers:[],json:[],json_types:[]}});
  expect(input).toEqual({add:{headers:['X-KongPilot-Corpus:owned-marker']}});
 });
 it('still rejects required scalar children after expanding a required record',()=>{
  expect(()=>normalizeSchema({},{fields:[{nested:{type:'record',required:true,fields:[{needed:{type:'string',required:true}}]}}]},{defaults:true,required:true})).toThrow(expect.objectContaining({code:'CONFIGURATION_REQUIRED_FIELD',path:'nested.needed'}));
 });
 it('keeps absent records absent during partial updates',()=>{
  expect(normalizeSchema({},recorded,{defaults:false,required:false})).toEqual({});
 });
 it('does not expand optional or abstract records into invented values',()=>{
  const schema={fields:[{optional:{type:'record',fields:[{safe:{type:'integer',default:1}}]}},{abstract:{type:'record',required:true,abstract:true}}]};
  expect(()=>normalizeSchema({},schema,{defaults:true,required:true})).toThrow(expect.objectContaining({code:'CONFIGURATION_REQUIRED_FIELD',path:'abstract'}));
  expect(normalizeSchema({},{fields:[schema.fields[0]]},{defaults:true,required:true})).toEqual({});
 });
 it('never materializes a secret default while filling a required record',()=>{
  const schema={fields:[{nested:{type:'record',required:true,fields:[{client_secret:{type:'string',default:'synthetic-default-must-not-be-frozen'}},{enabled:{type:'boolean',default:false}}]}}]};
  expect(normalizeSchema({},schema,{defaults:true,required:true})).toEqual({nested:{enabled:false}});
 });
 it('keeps a supplied null required record invalid',()=>{
  expect(()=>normalizeSchema({remove:null},recorded,{defaults:true,required:true})).toThrow(expect.objectContaining({code:'CONFIGURATION_REQUIRED_FIELD',path:'remove'}));
 });
});
