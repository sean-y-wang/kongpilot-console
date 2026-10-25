import assert from 'node:assert/strict';
import{chromium}from'@playwright/test';
import{readFileSync,writeFileSync,existsSync,mkdirSync}from'node:fs';
import{createHash}from'node:crypto';
assert.equal(process.env.RELEASE_LAB_READY,'true');
const h=JSON.parse(readFileSync('/dev/shm/kongpilot-release-lab/m11-harness.json'));
const user=h.sessions['tag-writer'],original=h.gate3Core.intents.serviceUpdateAfterAppendOnlyFix;
const dir=process.argv.includes('--after-visual-fix')?'artifacts/M11/core-browser-readonly-after-visual-fix-attempt1':'artifacts/M11/core-browser-readonly-attempt1',out=dir+'/verification.json';assert(!existsSync(out));mkdirSync(dir,{recursive:true});
const checks=[],responses=[],screenshots=[];let browser,context,error,blockedWrites=0,adminAttempts=0,pageErrors=0;
const check=(name,value)=>{assert(value,name);checks.push({name,passed:true});};
try{
 browser=await chromium.launch({headless:true,executablePath:'/usr/bin/chromium'});
 context=await browser.newContext({viewport:{width:1440,height:1000},serviceWorkers:'block'});
 const cookies=user.cookie.split('; ').map(p=>{const i=p.indexOf('=');return{name:p.slice(0,i),value:p.slice(i+1),domain:'127.0.0.1',path:'/',httpOnly:!p.startsWith('kongos_csrf='),secure:false,sameSite:'Lax'};});await context.addCookies(cookies);
 await context.addInitScript(({cid,wid})=>{sessionStorage.setItem('kongos.clusterId',cid);sessionStorage.setItem(`kongos.workspaceId.${cid}`,wid);},{cid:h.cid,wid:h.wid});
 await context.route('**/*',async r=>{const u=new URL(r.request().url());if(['8001','8444'].includes(u.port)){adminAttempts++;await r.abort();return;}if(u.pathname.startsWith('/api/v1/')&&!['GET','HEAD'].includes(r.request().method())){blockedWrites++;await r.abort();return;}await r.continue();});
 const page=await context.newPage();page.on('pageerror',()=>pageErrors++);page.on('response',r=>{const u=new URL(r.url());if(u.pathname.startsWith('/api/v1/'))responses.push({method:r.request().method(),path:u.pathname,status:r.status()});});
 const me=await context.request.get('http://127.0.0.1:5455/api/v1/auth/me');check('real server accepts original tag-scoped HTTP session',me.status()===200&&(await me.json()).data.user.id===user.user.id);
 await page.goto(`http://127.0.0.1:5455/workflows/${original.workflowId}`,{waitUntil:'domcontentloaded'});
 await page.getByTestId('workflow-state').waitFor({timeout:30000});await page.getByText('执行前恢复基线',{exact:true}).waitFor({timeout:30000});
 const text=await page.locator('body').innerText();check('actual completed native workflow and persisted baseline render',text.includes('网关逐步结果')&&text.includes(original.workflowId));
 check('server-redacted intent review is visible',text.includes('逐对象变更'));
 if(process.argv.includes('--after-visual-fix')){check('completed workflow has no stale baseline-required warning',!text.includes('EXECUTION_BASELINE_REQUIRED')&&!text.includes('当前变更暂不可执行'));check('completed workflow hides empty approval form',await page.getByRole('textbox',{name:'审批原因',exact:true}).count()===0);check('technical plan and decision records start collapsed',text.includes('计划与影响详情')&&!text.includes('\"read_timeout\"'));}
 check('completed workflow has no execute action',await page.getByRole('button',{name:'执行已确认计划',exact:true}).count()===0);
 for(const key of [h.gate2.fixtures.key,h.gate3Core.newKey])check('actual credential never appears in rendered text '+createHash('sha256').update(key).digest('hex').slice(0,8),!text.includes(key));
 await page.screenshot({path:dir+'/native-detail-light.png',fullPage:true});screenshots.push(dir+'/native-detail-light.png');
 await page.setViewportSize({width:390,height:844});await page.screenshot({path:dir+'/native-detail-mobile.png',fullPage:true});screenshots.push(dir+'/native-detail-mobile.png');
 check('mobile page has no document-width overflow',await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth+2));
 check('browser uses only BFF and sends no business write',blockedWrites===0&&adminAttempts===0);check('no unhandled page errors',pageErrors===0);
}catch(e){error={kind:e.name};}finally{await context?.close();await browser?.close();const report={passed:!error,sourceOnly:false,actualBackend:true,productionDeployment:false,overallM11Accepted:false,checks,responses,screenshots,blockedWrites,adminAttempts,pageErrors,...(error?{failure:error}:{})};writeFileSync(out,JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify({passed:report.passed,checks:checks.length,screenshots:screenshots.length,failure:error}));if(error)process.exitCode=1;}
