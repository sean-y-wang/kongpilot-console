import assert from'node:assert/strict';import{chromium}from'@playwright/test';import{readFileSync,writeFileSync,existsSync,mkdirSync}from'node:fs';
assert.equal(process.env.RELEASE_LAB_READY,'true');
const h=JSON.parse(readFileSync('/dev/shm/kongpilot-release-lab/m11-harness.json'));
assert(process.argv.length<=3&&process.argv.slice(2).every(value=>['--after-web-restart','--after-anchor-assertion-fix','--after-url-encoding-assertion-fix'].includes(value)));
const user=h.sessions.admin,dir=`artifacts/M11/manual-schedule-browser-readonly-${process.argv[2]?.slice(2)??'original'}`,out=dir+'/verification.json';assert(!existsSync(out));mkdirSync(dir,{recursive:true});
const checks=[],responses=[],screenshots=[];let browser,context,error,blockedWrites=0,adminAttempts=0,pageErrors=0;
const check=(name,ok)=>{assert(ok,name);checks.push({name,passed:true});};
try{
 browser=await chromium.launch({headless:true,executablePath:'/usr/bin/chromium'});context=await browser.newContext({viewport:{width:1440,height:1000},serviceWorkers:'block'});
 await context.addCookies(user.cookie.split('; ').map(pair=>{const i=pair.indexOf('=');return{name:pair.slice(0,i),value:pair.slice(i+1),domain:'127.0.0.1',path:'/',httpOnly:!pair.startsWith('kongos_csrf='),secure:false,sameSite:'Lax'};}));
 await context.addInitScript(({cid,wid})=>{sessionStorage.setItem('kongos.clusterId',cid);sessionStorage.setItem(`kongos.workspaceId.${cid}`,wid);},{cid:h.cid,wid:h.wid});
 await context.route('**/*',async route=>{const u=new URL(route.request().url());if(['8001','8444'].includes(u.port)){adminAttempts++;await route.abort();return;}if(u.pathname.startsWith('/api/v1/')&&!['GET','HEAD'].includes(route.request().method())){blockedWrites++;await route.abort();return;}await route.continue();});
 const page=await context.newPage();page.on('pageerror',()=>pageErrors++);page.on('response',r=>{const u=new URL(r.url());if(u.pathname.startsWith('/api/v1/'))responses.push({method:r.request().method(),path:u.pathname,status:r.status()});});
 const me=await context.request.get('http://127.0.0.1:5455/api/v1/auth/me');check('actual admin session accepted without refreshing',me.status()===200&&(await me.json()).data.user.id===user.user.id);
 await page.goto('http://127.0.0.1:5455/help/user-guide',{waitUntil:'domcontentloaded'});await page.locator('.manual-document table').first().waitFor({timeout:30000});
 check('real user manual renders GFM tables',await page.locator('.manual-document table').count()>0);check('manual displays product v1.0',await page.getByText('v1.0',{exact:true}).count()>0);
 check('heading anchors are nonempty and unique',await page.locator('.manual-document').evaluate(el=>{const ids=[...el.querySelectorAll('h1,h2,h3,h4,h5,h6')].map(h=>h.id);return ids.length>5&&ids.every(Boolean)&&new Set(ids).size===ids.length;}));
 const toc=page.getByRole('navigation',{name:'手册目录'}).locator('a[href^="#"]').nth(1);const anchor=decodeURIComponent(await toc.getAttribute('href'));await toc.click();await page.waitForFunction(hash=>decodeURIComponent(location.hash)===hash,anchor);check('actual TOC links reach a real heading',await page.evaluate(hash=>!!document.getElementById(hash.slice(1)),anchor));
 await page.screenshot({path:dir+'/user-manual.png'});screenshots.push(dir+'/user-manual.png');
 const cross=page.getByRole('link',{name:'部署手册交付清单',exact:true});check('cross-manual link retains the chapter fragment',await cross.count()===1&&decodeURIComponent(await cross.getAttribute('href'))==='/help/operations-guide#16-正式站点交付清单');await cross.click();await page.locator('[id="16-正式站点交付清单"]').waitFor({timeout:30000});
 check('cross-manual navigation focuses the actual target chapter',await page.evaluate(()=>location.pathname==='/help/operations-guide'&&decodeURIComponent(location.hash)==='#16-正式站点交付清单'&&document.activeElement?.id==='16-正式站点交付清单'));
 await page.screenshot({path:dir+'/operations-manual-chapter.png'});screenshots.push(dir+'/operations-manual-chapter.png');
 await page.goto(`http://127.0.0.1:5455/workflows?tab=schedules&schedule=${h.gate4ScheduledCore.scheduleId}`,{waitUntil:'domcontentloaded'});await page.getByTestId('entity-schedule-detail').waitFor({timeout:30000});await page.getByText(h.gate4ScheduledCore.scheduleId,{exact:true}).waitFor({timeout:30000});
 check('real failed scheduled receipt is shown',await page.getByTestId('entity-schedule-detail').innerText().then(t=>t.includes('领取记录 ID')&&t.includes('计划执行 · Asia/Shanghai')));
 check('terminal schedule cannot activate or cancel',await page.getByRole('button',{name:'激活定时变更',exact:true}).isDisabled()&&await page.getByRole('button',{name:'撤销定时变更',exact:true}).isDisabled());
 await page.screenshot({path:dir+'/scheduled-detail.png'});screenshots.push(dir+'/scheduled-detail.png');
 await page.goto('http://127.0.0.1:5455/help/user-guide',{waitUntil:'domcontentloaded'});await page.locator('.manual-document table').first().waitFor();await page.setViewportSize({width:390,height:844});
 check('mobile manual has no document-width overflow',await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth+2));await page.screenshot({path:dir+'/user-manual-mobile.png'});screenshots.push(dir+'/user-manual-mobile.png');
 check('no browser business write or direct Admin API attempt',blockedWrites===0&&adminAttempts===0);check('no unhandled page errors',pageErrors===0);
}catch(e){error={kind:e?.name,check:typeof e?.message==='string'&&e.message.length<150?e.message:undefined};}
finally{await context?.close();await browser?.close();const report={passed:!error,sourceOnly:false,actualBackend:true,productionDeployment:false,overallM11Accepted:false,checks,responses,screenshots,blockedWrites,adminAttempts,pageErrors,...(error?{failure:error}:{})};writeFileSync(out,JSON.stringify(report,null,2)+'\n',{flag:'wx'});console.log(JSON.stringify({passed:report.passed,checks:checks.length,screenshots:screenshots.length,failure:error}));if(error)process.exitCode=1;}
