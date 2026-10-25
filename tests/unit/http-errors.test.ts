import 'reflect-metadata';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ServiceUnavailableException } from '@nestjs/common';
import { ErrorFilter } from '../../apps/console-api/src/common/http';
function invoke(error:any){const json=vi.fn(),status=vi.fn().mockReturnValue({json});new ErrorFilter().catch(error,{switchToHttp:()=>({getResponse:()=>({status}),getRequest:()=>({requestId:'request-id'})})} as any);return {status,json};}
describe('safe error recovery references',()=>{
 afterEach(()=>vi.restoreAllMocks());
 it('keeps durable receipt identifiers without leaking arbitrary error payloads',()=>{vi.spyOn(console,'error').mockImplementation(()=>undefined);const id='15ac7bd4-92b8-45c6-a3e6-72e7ae8dc25f';const {json}=invoke(new ServiceUnavailableException({code:'MUTATION_UNCERTAIN',message:'需要核验',operationId:id,entryId:id,state:'uncertain',payload:{password:'private-material'},cause:'private-material'}));expect(json.mock.calls[0][0].error).toEqual({code:'MUTATION_UNCERTAIN',message:'需要核验',operationId:id,entryId:id,state:'uncertain'});});
 it('does not log raw unexpected exception text or expose malformed recovery identifiers',()=>{const logger=vi.spyOn(console,'error').mockImplementation(()=>undefined);const {json}=invoke(new Error('unexpected password=private-material'));expect(JSON.stringify(json.mock.calls)).not.toContain('private-material');expect(JSON.stringify(logger.mock.calls)).not.toContain('private-material');const invalid=invoke(new ServiceUnavailableException({message:'safe',operationId:'private-material',state:'<script>'}));expect(invalid.json.mock.calls[0][0].error.operationId).toBeUndefined();});
 it('normalizes parser errors without echoing the malformed secret-bearing body',()=>{const invalid=invoke(Object.assign(new Error('password=private-material'),{type:'entity.parse.failed',status:400,body:'private-material'}));expect(invalid.status).toHaveBeenCalledWith(400);expect(JSON.stringify(invalid.json.mock.calls)).not.toContain('private-material');const large=invoke(Object.assign(new Error('too large'),{type:'entity.too.large',status:413}));expect(large.status).toHaveBeenCalledWith(413);});
});
