import 'reflect-metadata';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import { NestFactory } from '@nestjs/core';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import type { NestExpressApplication } from '@nestjs/platform-express';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import { AppModule } from './app.module';
import { RequestFailureAuditService } from './modules/audit/request-failure-audit.service';
import { EnvelopeInterceptor, ErrorFilter } from './common/http';
import { describeConsoleApi } from './common/openapi';
import { KongExecutionContextService } from './infrastructure/kong/execution-context.service';
import { configurationHttpWait } from './infrastructure/kong/configuration-budget';
import { KongScopeInterceptor } from './modules/authorization/kong-scope.interceptor';
import { NativeKongPolicyService } from './modules/authorization/native-kong-policy.service';

async function bootstrap(){
 for(const path of [resolve(process.cwd(),'.env'),resolve(process.cwd(),'../../.env')])if(existsSync(path)){process.loadEnvFile(path);break;}
 if(!process.env.APP_SECRET||process.env.APP_SECRET.length<32)throw new Error('APP_SECRET must contain at least 32 characters');
 const app=await NestFactory.create<NestExpressApplication>(AppModule,{logger:['error','warn','log'],bodyParser:true});
 const execution=app.get(KongExecutionContextService);
 app.get(NativeKongPolicyService).install();
 app.useBodyParser('json',{limit:'10mb'});
 if(process.env.TRUST_PROXY)app.getHttpAdapter().getInstance().set('trust proxy',Number(process.env.TRUST_PROXY));
 app.use(helmet({contentSecurityPolicy:{directives:{defaultSrc:["'self'"],scriptSrc:["'self'"],styleSrc:["'self'","'unsafe-inline'"],imgSrc:["'self'",'data:'],connectSrc:["'self'"],frameAncestors:["'none'"]}}}));
 app.use(cookieParser());
 app.use((req:any,res:any,next:any)=>{req.requestId=randomUUID();res.setHeader('X-Request-ID',req.requestId);res.setHeader('Cache-Control','no-store');const start=Date.now();execution.runHttp({configurationWait:configurationHttpWait(req.method,req.path),requestId:req.requestId,ip:req.ip,idempotencyKey:typeof req.headers['x-idempotency-key']==='string'&&/^[A-Za-z0-9._:-]{8,128}$/.test(req.headers['x-idempotency-key'])?req.headers['x-idempotency-key']:undefined},()=>{const close=execution.captureHttpCloser();res.once('finish',()=>{close();console.log(JSON.stringify({level:'info',requestId:req.requestId,method:req.method,path:typeof req.route?.path==='string'?req.route.path:'unmatched',status:res.statusCode,durationMs:Date.now()-start}));});res.once('close',close);next();});});
 app.setGlobalPrefix('api/v1');app.useGlobalInterceptors(new KongScopeInterceptor(execution),new EnvelopeInterceptor());app.useGlobalFilters(new ErrorFilter(app.get(RequestFailureAuditService)));
 const config=new DocumentBuilder().setTitle('KongPilot API').setVersion('0.1.0').setDescription('Kong OSS 1.5.x 控制台 BFF；所有网关操作通过集群上下文及权限验证').addCookieAuth('kongos_access').build();
 SwaggerModule.setup('api/docs',app,describeConsoleApi(SwaggerModule.createDocument(app,config)),{swaggerOptions:{withCredentials:true,persistAuthorization:false}});
 app.enableShutdownHooks();await app.listen(Number(process.env.PORT??3000),'0.0.0.0');
}
bootstrap().catch(error=>{console.error(JSON.stringify({level:'fatal',message:error.message}));process.exitCode=1;});
