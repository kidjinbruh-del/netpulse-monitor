const {chromium}=require('playwright');
const assert=require('node:assert/strict');
const base=process.env.NP_TEST_URL||'http://127.0.0.1:8796';
(async()=>{
 const browser=await chromium.launch({headless:true,...(process.env.NP_BROWSER_CHANNEL?{channel:process.env.NP_BROWSER_CHANNEL}:{})});
 try{
 const page=await browser.newPage({viewport:{width:1100,height:900}});const errors=[],runs=[];
 page.on('pageerror',e=>errors.push(e.message));
 const data={enabled:true,log:[],runbooks:[{id:'disk-space-local',name:'Диски этого сервера',description:'Только чтение',scope:'local',params:[],supported:true,changes_state:false},{id:'restart-spooler',name:'Перезапустить очередь печати',description:'Spooler на целевом ПК',scope:'remote',params:['host'],fields:[{name:'host',required:true}],supported:true,changes_state:true}]};
 const responses={runbooks:data,hosts:{hosts:[],watchdog:{}},events:{events:[]},diskforecast:{forecasts:[]}};
 await page.route('**/api/**',route=>{const endpoint=new URL(route.request().url()).pathname.split('/').pop();return responses[endpoint]?route.fulfill({json:responses[endpoint]}):route.fallback();});
 await page.route('**/api/runbookexec',route=>{const body=route.request().postDataJSON();runs.push(body);return route.fulfill({json:{job:body.name}});});
 await page.route('**/api/securityresult?*',route=>{const disk=new URL(route.request().url()).searchParams.get('job')==='disk-space-local';return route.fulfill({json:{status:'done',result:disk?{ok:true,exit_code:0,seconds:.1,target:'Этот сервер',disks:[{device:'C:',mount:'C:\\',free_gb:20,total_gb:100,used_pct:80}],output:'C: free 20 GB'}:{ok:false,exit_code:1,seconds:.2,target:'OFFICE-PC-01',output:'Access denied'}}});});
 await page.goto(base+'/#park');await page.locator('#login-token').fill('ci-admin');await Promise.all([page.waitForEvent('load'),page.getByRole('button',{name:'Войти',exact:true}).click()]);
 await page.locator('[data-runbook="0"]').waitFor();assert.equal(runs.length,0);
 await page.locator('[data-runbook="0"]').click();
 await page.locator('#sa-table-runbook-disks').waitFor();assert((await page.locator('#rb-output').innerText()).includes('20'));
 assert.equal(runs.length,1);assert.deepEqual(runs[0],{name:'disk-space-local',params:{}});
 await page.waitForFunction(()=>!Runbooks.busy);
 await page.locator('[data-runbook="1"]').click();assert.equal(runs.length,1);
 await page.locator('#rb-form input[name=host]').fill('bad;command');
 await page.locator('#rb-form input[type=checkbox]').check();await page.locator('#rb-form button[type=submit]').click();assert.equal(runs.length,1);
 await page.locator('#rb-form input[name=host]').fill('OFFICE-PC-01');
 await page.locator('#rb-form input[type=checkbox]').uncheck();await page.locator('#rb-form button[type=submit]').click();assert.equal(runs.length,1);
 await page.locator('#rb-form input[type=checkbox]').check();await page.locator('#rb-form button[type=submit]').click();
 await page.waitForFunction(()=>document.querySelector('#rb-output').textContent.includes('Access denied'));
 assert.deepEqual(runs[1],{name:'restart-spooler',params:{host:'OFFICE-PC-01'}});
 assert((await page.locator('#rb-output').innerText()).includes('Не выполнено'));
 assert(!(await page.locator('#rb-output').innerText()).includes('undefined'));
 await page.setViewportSize({width:390,height:844});assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+2));
 assert.deepEqual(errors,[]);
 console.log('Runbook browser checks passed: structured disks, explicit target, confirmation, validation, job failure, mobile; remote execution mocked');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
