import * as React from 'react';
import { afterEach,beforeEach,describe,expect,it,vi } from 'vitest';
vi.mock('antd',()=>({Input:'test-input',Alert:'test-alert'}));
vi.mock('@ant-design/icons',()=>({ExclamationCircleOutlined:'test-icon'}));
import { ApiError } from '../../apps/console-web/src/api/client';
import { mutationConfirm } from '../../apps/console-web/src/components/MutationConfirm';

const expected='pay-service';
async function flushMicrotasks(){for(let count=0;count<8;count++)await Promise.resolve();}
function findElement(node:any,predicate:(element:any)=>boolean):any{
 if(!node||typeof node!=='object')return undefined;
 if(predicate(node))return node;
 for(const child of React.Children.toArray(node.props?.children)){const found=findElement(child,predicate);if(found)return found;}
 return undefined;
}
function fixture(onConfirm:()=>Promise<void>){
 let config:any,current:any;
 const close=vi.fn(),update=vi.fn((change:any)=>{current={...current,...change};}),modal={confirm:vi.fn((value:any)=>{config=value;current=value;return {update};})};
 mutationConfirm(modal,{title:'删除对象',description:'删除前归档完整对象图',expected,onConfirm});
 const input=findElement(config.content,element=>typeof element.props?.onChange==='function');
 return {modal,close,update,config,view:()=>current,type:(value:string)=>input.props.onChange({target:{value}}),alert:()=>findElement(current.content,element=>element.type==='test-alert')};
}

beforeEach(()=>vi.stubGlobal('React',React));
afterEach(()=>vi.unstubAllGlobals());

describe('M3 explicit-close mutation confirmation regression',()=>{
 it('returns void to AntD, guards duplicate clicks, and closes only after the mutation resolves successfully',async()=>{
  let resolve!:()=>void;const pending=new Promise<void>(done=>{resolve=done;}),onConfirm=vi.fn(()=>pending),f=fixture(onConfirm);
  expect(f.config.onOk.length).toBe(1);expect(f.view().okButtonProps.disabled).toBe(true);
  expect(f.config.onOk(f.close)).toBeUndefined();await flushMicrotasks();expect(onConfirm).not.toHaveBeenCalled();expect(f.close).not.toHaveBeenCalled();
  f.type(expected);expect(f.view().okButtonProps.disabled).toBe(false);
  expect(f.config.onOk(f.close)).toBeUndefined();expect(f.view().okButtonProps).toMatchObject({loading:true,disabled:true});expect(f.config.onOk(f.close)).toBeUndefined();
  await flushMicrotasks();expect(onConfirm).toHaveBeenCalledTimes(1);expect(f.close).not.toHaveBeenCalled();
  resolve();await flushMicrotasks();expect(f.close).toHaveBeenCalledTimes(1);expect(onConfirm).toHaveBeenCalledTimes(1);
 });
 it('handles a known validation failure without a rejected onOk promise, keeps the dialog open and permits an explicit retry',async()=>{
  const onConfirm=vi.fn().mockRejectedValueOnce(new ApiError('标签不合法',400,'KONG_VALIDATION_ERROR')).mockResolvedValueOnce(undefined),f=fixture(onConfirm);f.type(expected);
  expect(f.config.onOk(f.close)).toBeUndefined();await flushMicrotasks();expect(f.close).not.toHaveBeenCalled();expect(onConfirm).toHaveBeenCalledTimes(1);
  expect(f.view().okButtonProps).toMatchObject({loading:false,disabled:false});expect(f.alert().props).toMatchObject({type:'error',message:'操作未完成',description:'标签不合法'});
  expect(f.config.onOk(f.close)).toBeUndefined();await flushMicrotasks();expect(onConfirm).toHaveBeenCalledTimes(2);expect(f.close).toHaveBeenCalledTimes(1);
 });
 it('keeps an unknown-result failure open and locked despite retyping the exact confirmation, with no second write',async()=>{
  const error=new ApiError('写入响应中断',503,'KONG_WRITE_RESULT_UNKNOWN',undefined,undefined,{state:'uncertain',operationId:'bc7bd065-9372-405d-9782-015d31a30aa1'}),onConfirm=vi.fn().mockRejectedValue(error),f=fixture(onConfirm);f.type(expected);
  expect(f.config.onOk(f.close)).toBeUndefined();await flushMicrotasks();expect(f.close).not.toHaveBeenCalled();expect(onConfirm).toHaveBeenCalledTimes(1);
  expect(f.view().okButtonProps).toMatchObject({loading:false,disabled:true});expect(f.alert().props).toMatchObject({type:'warning',message:'写入结果待核验'});
  f.type('');f.type(expected);expect(f.view().okButtonProps).toMatchObject({loading:false,disabled:true});expect(f.config.onOk(f.close)).toBeUndefined();await flushMicrotasks();expect(onConfirm).toHaveBeenCalledTimes(1);expect(f.close).not.toHaveBeenCalled();
 });
});
