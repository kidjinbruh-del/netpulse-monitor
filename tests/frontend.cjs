// Browser-independent regression checks for auth transport and private SW boundaries.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
(async () => {
  const source = fs.readFileSync(path.join(__dirname,'../netpulse/web/app.js'),'utf8').split('/* ================= графики')[0];
  const requests=[];
  const context={window:{addEventListener(){}},document:{getElementById(){}},console,AbortController,setTimeout,clearTimeout,
    localStorage:{getItem(){throw Error('disabled');},setItem(){throw Error('disabled');}},
    fetch:async(url,opts)=>{requests.push([url,opts]);return {ok:true,status:200,json:async()=>({ok:true})};}};
  vm.createContext(context);vm.runInContext(source+'\nthis.transport={Auth,apiGet,apiPost,timedFetch,UnauthorizedError};',context);
  const t=context.transport;t.Auth.set('private-token');
  assert.equal(t.Auth.get(),'private-token');assert.equal(t.Auth.suffix('/export?x=1'),'');
  await t.apiGet('state');await t.apiPost('journaladd',{text:'test'});
  assert.equal(requests[0][0],'/api/state');assert.equal(requests[0][1].headers['X-Auth'],'private-token');
  assert(!requests.some(([url])=>url.includes('private-token')));
  context.fetch=async()=>({status:401,ok:false});await assert.rejects(t.apiGet('state'),t.UnauthorizedError);
  context.fetch=async()=>{const e=new Error('aborted');e.name='AbortError';throw e;};
  await assert.rejects(t.timedFetch('/api/state'),/15/);
  const listeners={};const worker={URL,Response,fetch:async()=>new Response('ok'),caches:{},self:{location:{origin:'https://netpulse.test'},addEventListener:(type,fn)=>listeners[type]=fn}};
  vm.createContext(worker);vm.runInContext(fs.readFileSync(path.join(__dirname,'../netpulse/web/sw.js'),'utf8'),worker);
  for(const endpoint of ['/api/state','/metrics','/report.txt','/journal.csv','/app.js?token=secret','https://other.test/app.js']){
    let handled=false;listeners.fetch({request:{method:'GET',url:new URL(endpoint,'https://netpulse.test').href},respondWith(){handled=true;}});assert.equal(handled,false,endpoint);
  }
  console.log('Frontend regression checks passed: credentials, blocked storage, HTTP auth, timeout, SW private routes');
})().catch(error=>{console.error(error);process.exitCode=1;});
