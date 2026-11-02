const {chromium}=require('playwright');
const assert=require('node:assert/strict');
const fs=require('node:fs/promises');
const base=process.env.NP_TEST_URL||'http://127.0.0.1:8796';
(async()=>{
 const browser=await chromium.launch({headless:true,...(process.env.NP_BROWSER_CHANNEL?{channel:process.env.NP_BROWSER_CHANNEL}:{})});
 try {
 const page=await browser.newPage({viewport:{width:1440,height:1000}}), errors=[],posts=[];
 page.on('pageerror',e=>errors.push(e.message));page.on('request',r=>{if(r.method()==='POST')posts.push(new URL(r.url()).pathname);});
 const responses={
  sla:{devices:[{name:'Fixture-PC',ip:'192.0.2.2',online:false,sla_pct:0,coverage_pct:100,down_seconds:86400,offline_events:1,online_events:0}]},
  ramforecast:{ok:true,last_pct:0,slope_pct_pt:0,n_points:60,span_seconds:120,horizon_seconds:600,seconds_to_95:null},
  l2map:{status:{scanning:false},ports:[{mac:'00:11:22:33:44:55',if_name:'ether2',if_index:2,switch_ip:'192.0.2.10'}]},
  geomap:{countries:[['Example country',3],['?',2]],total_ips:5,uniq:4},
  proxmox:{enabled:true,configured:true,ok:true,verify_tls:true,checked:'2026-11-02T12:00:00',nodes:[{node:'lab-pve',status:'online',cpu:0,mem:1,maxmem:2,uptime:0}],vms:[{vmid:100,name:'Test-VM',type:'vm',node:'lab-pve',status:'running',cpu:0,mem:.5,maxmem:1}]},
  mtrhistory:{entries:[{ts:'2026-11-02T12:00:00',target:'192.0.2.1',hop:2,ip:'192.0.2.3',loss_pct:0,avg_ms:0}]},
  cvestatus:{enabled:true,nvd_key:false,found:2,last:'2026-11-02',last_result:{complete:false,products:2,found:[],error:'Fixture incomplete'}},
  audit:{entries:[{timestamp:'2026-11-02',user:'fixture-user',ip:'127.0.0.1',action:'settings',status:200,details:'token=***'}]},
 };
 for(const [endpoint,json]of Object.entries(responses))await page.route('**/api/'+endpoint+'{,?*}',r=>r.fulfill({json}));
 // Match by pathname to include all query variants, independently of glob engines.
 await page.route('**/api/**',r=>{const endpoint=new URL(r.request().url()).pathname.split('/').pop();return responses[endpoint]?r.fulfill({json:responses[endpoint]}):r.fallback();});
 await page.route('**/api/cvescan',r=>r.fulfill({json:{job:'fixture-cve'}}));
 await page.route('**/api/proxmoxpoll',r=>r.fulfill({json:{job:'fixture-pve'}}));
 await page.route('**/api/securityresult?*',r=>r.fulfill({json:{status:'done',result:{complete:false,found:[],products:2,error:'Fixture incomplete'}}}));
 await page.goto(base+'/#sysadmin');await page.locator('#login-token').fill('ci-admin');await Promise.all([page.waitForEvent('load'),page.getByRole('button',{name:'Войти',exact:true}).click()]);
 await page.locator('#sa-table-audit tbody tr').waitFor();
 assert.equal(await page.locator('.sa-card').count(),8);
 assert((await page.locator('#sla-box').innerText()).includes('0%'));
 assert((await page.locator('#ram-box').innerText()).includes('0%'));
 assert((await page.locator('#l2-box').innerText()).includes('ether2'));
 assert((await page.locator('#geo-box').innerText()).includes('Example country'));
 assert((await page.locator('#pxm-box').innerText()).includes('1 / 2'));
 assert((await page.locator('#pxm-box').innerText()).includes('Test-VM'));
 assert((await page.locator('#mtrhist-box').innerText()).includes('192.0.2.3'));
 assert((await page.locator('#audit-box').innerText()).includes('fixture-user'));
 assert((await page.locator('#audit-box').innerText()).includes('settings'));
 assert((await page.locator('#cve-box').innerText()).includes('Fixture incomplete'));
 assert.deepEqual(posts.filter(p=>p!=='/api/login'),[],'Opening sysadmin does not trigger remote jobs');
 await page.locator('#sa-cve-run').click();assert(await page.locator('#sa-cve-run').isDisabled());
 await page.waitForFunction(()=>document.querySelector('#cve-box').textContent.includes('Fixture incomplete'));
 assert(!(await page.locator('#cve-box').innerText()).includes('Уязвимостей не найдено'));
 assert.equal(posts.filter(p=>p==='/api/cvescan').length,1);
 await page.locator('#sa-pxm-poll').click();await page.waitForFunction(()=>document.querySelector('#sa-table-pve-vms'));
 assert.equal(posts.filter(p=>p==='/api/proxmoxpoll').length,1);
 await page.route('**/api/geomap?*',r=>r.fulfill({status:503,json:{error:'Fixture unavailable'}}));
 await page.locator('#sa-card-geo button[data-refresh]').click();await page.waitForFunction(()=>document.querySelector('#sa-card-geo .sa-state').dataset.state==='error');
 assert((await page.locator('#geo-box').innerText()).includes('HTTP 503'));
 assert(await page.locator('#sa-table-audit').isVisible());
 await fs.mkdir('test-results/sysadmin',{recursive:true});
 await page.screenshot({path:'test-results/sysadmin/desktop.png',fullPage:true});
 await page.setViewportSize({width:390,height:844});assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+2));
 await page.screenshot({path:'test-results/sysadmin/mobile.png',fullPage:true});
 await page.setViewportSize({width:1440,height:1000});
 await page.evaluate(()=>UI.switchView('infra'));await page.waitForTimeout(200);
 const map={gateway:'192.0.2.1',nodes:[{name:'Collector',ip:'192.0.2.2',kind:'master',online:true},{name:'Gateway',ip:'192.0.2.1',kind:'router',online:null},...Array.from({length:25},(_,i)=>({name:'Device-'+i,ip:'192.0.2.'+(i+10),kind:i%3?'host':'switch',online:i%4?true:false,vendor:'Fixture'}))]};
 await page.evaluate(map=>{window.__lastMap=map;UI.renderMap(map);},map);
 assert.equal(await page.locator('#infra-map [data-node-index]').count(),27,'All devices are represented without a nine-node cut-off');
 assert((await page.locator('#infra-map').innerText()).includes('Gateway'));
 assert((await page.locator('#infra-map').innerText()).includes('Не проверено'));
 await page.locator('#topology-search').fill('Device-24');assert.equal(await page.locator('#infra-map [data-node-index]').count(),1);
 await page.locator('#infra-map [data-node-index]').focus();await page.keyboard.press('Enter');
 assert((await page.locator('#topology-detail').innerText()).includes('Device-24'));
 await page.locator('#topology-search').fill('');await page.locator('#topology-filter').selectOption('unknown');
 assert.equal(await page.locator('#infra-map [data-node-index]').count(),1);
 await page.locator('#topology-filter').selectOption('all');
 await page.getByRole('button',{name:'Увеличить топологию',exact:true}).click();assert.equal(await page.locator('#topology-scale').innerText(),'125%');
 const downloaded=page.waitForEvent('download');await page.evaluate(()=>UI.exportMap('png'));const png=await downloaded;
 const bytes=await fs.readFile(await png.path());assert.equal(bytes.subarray(1,4).toString(),'PNG');
 const dims=await page.locator('#infra-map svg').evaluate(svg=>({width:svg.viewBox.baseVal.width,height:svg.viewBox.baseVal.height}));
 assert.equal(bytes.readUInt32BE(16),dims.width*2);assert.equal(bytes.readUInt32BE(20),dims.height*2);
 await page.evaluate(()=>Topology.reset());
 await page.screenshot({path:'test-results/sysadmin/topology-desktop.png',fullPage:true});
 await page.setViewportSize({width:390,height:844});await page.waitForTimeout(200);
 assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+2));
 assert.equal(await page.locator('#infra-map [data-node-index]').count(),27);
 await page.screenshot({path:'test-results/sysadmin/topology-mobile.png',fullPage:true});
 assert.deepEqual(errors,[]);
 console.log('Sysadmin/topology browser checks passed: 8 blocks, units, zero values, partial CVE, background jobs, errors, 27 topology nodes, filters, keyboard details, PNG dimensions, mobile');
 } finally {await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
