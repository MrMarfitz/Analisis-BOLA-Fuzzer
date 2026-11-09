const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const defaults = {baseUrl:'http://127.0.0.1:8888',loginEndpoint:'/login',tokenPath:'token',usernameField:'username',userAEmail:'A',userAPassword:'fixture',userBEmail:'B',userBPassword:'fixture',sourceEndpoint:'/objects',sourceIdPath:'$[0].id',targetEndpoint:'/objects/{id}',objectParameter:'id',accessPolicy:'private',identityPaths:'$.id',privatePaths:'$.private_note',sessionEndpoint:'/me',sessionIdPath:'$.id',openApiSpec:'',groundTruth:''};
function setup() {
  const elements = new Map();
  function element(selector) {
    if(!elements.has(selector)) elements.set(selector,{value:defaults[selector.slice(1)]||'',checked:false,textContent:selector,innerHTML:'',className:'',disabled:false,hidden:false,dataset:{},attrs:{},classList:{toggle(){}},setAttribute(k,v){this.attrs[k]=v;},removeAttribute(k){delete this.attrs[k];},focus(){},scrollIntoView(){},closest(){return null;},insertAdjacentElement(){},addEventListener(){},querySelectorAll(){return [];}});
    return elements.get(selector);
  }
  const calls=[];
  const ctx=vm.createContext({URL,Date,window:{scrollTo(){}},document:{querySelector:element,querySelectorAll(){return [];},createElement(){return element('new-error');}},fetch:async (url,options)=>{
    calls.push({url,options});
    if(url==='/api/health')return {ok:true,json:async()=>({ok:true,service:'bola-fuzzer'})};
    return {ok:true,json:async()=>({ok:true,findings:[]})};
  }});
  vm.runInContext(fs.readFileSync('web/app.js','utf8'),ctx);
  return {ctx,element,calls,run:code=>vm.runInContext(code,ctx)};
}
(async()=>{
  let t=setup();
  t.element('#groundTruth').value='{invalid';
  await t.run('runConfiguredScan({preventDefault(){}})');
  assert.equal(t.calls.filter(c=>c.url==='/api/scan').length,0,'invalid JSON must not scan');
  assert.match(t.element('#scanLog').textContent,/Ground Truth/);
  t=setup();t.element('#openApiSpec').value='[]';
  assert.throws(()=>t.run('collectConfig()'),/OpenAPI/);
  t=setup();t.element('#autoDiscover').checked=true;
  assert.throws(()=>t.run('collectConfig()'),/OpenAPI/);
  t=setup();t.element('#groundTruth').value='{"case":"false"}';
  assert.throws(()=>t.run('collectConfig()'),/Ground Truth/);
  t=setup();
  t.run('applyApiResult({findings:[{status:"No BOLA",severity:"Info"},{status:"Inconclusive",severity:"Info"}]})');
  assert.equal(t.element('#findingCount').textContent,0);
  assert.equal(t.element('#totalTests').textContent,2);
  t.element('#groundTruth').value='{broken';
  await t.run('runConfiguredScan({preventDefault(){}})');
  assert.equal(t.run('findings.length'),0,'old results must not survive a failed new scan');
  t=setup();
  let complete;
  t.ctx.fetch=(url)=>url==='/api/scan'?new Promise(resolve=>{complete=resolve;}):Promise.resolve({ok:true,json:async()=>({ok:true})});
  const pending=t.run('runConfiguredScan({preventDefault(){}})');
  assert.equal(t.element('#runButton').disabled,true);
  await t.run('runConfiguredScan({preventDefault(){}})');
  t.run('clearResults()');
  assert.equal(t.run('scanRunning'),true,'clear cannot race an active scan');
  complete({ok:true,json:async()=>({ok:true,findings:[]})});await pending;
  assert.equal(t.element('#runButton').disabled,false);
  assert.equal(t.run('formatScore(null)'),'Tidak terdefinisi');
  t=setup();t.element('#baseUrl').value='not-a-url';t.run('navigateStep(2)');
  assert.equal(t.run('currentStep'),1);assert.equal(t.element('#baseUrl').attrs['aria-invalid'],'true');
  t=setup();t.element('#userBEmail').value='A';assert.throws(()=>t.run('collectConfig()'),/berbeda/);
  t=setup();t.run('showStep(4)');assert.ok(!t.element('#reviewSummary').innerHTML.includes('fixture'),'password absent from review');
  t=setup();t.run('switchTab("evaluation")');assert.equal(t.element('#panel-config').hidden,true);assert.equal(t.element('#panel-evaluation').hidden,false);
  t.element('#userAEmail').value='changed';t.run('switchTab("config")');assert.equal(t.element('#userAEmail').value,'changed','tab switch preserves configuration');
  t=setup();t.element('#labPreset').value='public';t.element('#groundTruth').value='{"old":true}';t.run('loadPreset()');
  assert.equal(t.element('#usernameField').value,'username');assert.equal(t.element('#groundTruth').value,'','preset change clears incompatible labels');
  t=setup();t.run('applyApiResult({findings:[{status:"Potential BOLA",endpoint:"<script>alert(1)</script>",evidence:{}}]})');assert.ok(!t.element('#findingTable').innerHTML.includes('<script>'),'HTML injection escaped');
  console.log('Dashboard regression scenarios passed: invalid JSON/shape, typed labels, counters, stale results, active scan guard, undefined metrics.');
})().catch(error=>{console.error(error);process.exitCode=1;});
