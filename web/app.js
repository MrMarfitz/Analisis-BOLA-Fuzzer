let findings = [], reportPaths = {}, metrics = null, discoveredCandidates = [];
let scanRunning = false, currentStep = 1, currentTab = 'config', selectedFinding = 0;
let lastConfig = null, lastRunStarted = '', lastRunContext = '';
const $ = selector => document.querySelector(selector);
const $$ = selector => Array.from(document.querySelectorAll(selector));
function escapeHtml(value) { return String(value ?? '').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;').replaceAll("'",'&#039;'); }
const LAB_PRESETS = {
  vehicle: {baseUrl:'http://127.0.0.1:8890',loginEndpoint:'/identity/api/auth/login',tokenPath:'token',usernameField:'email',userAEmail:'user-a@example.com',userAPassword:'password',userBEmail:'user-b@example.com',userBPassword:'password',sourceEndpoint:'/workshop/api/vehicles',sourceIdPath:'$[0].id',targetEndpoint:'/workshop/api/vehicles/{id}',objectParameter:'id',accessPolicy:'private',identityPaths:'$.id',privatePaths:'$.vin',sessionEndpoint:'/workshop/api/vehicles',sessionIdPath:'$[0].owner'},
  public: {baseUrl:'http://127.0.0.1:8899',loginEndpoint:'/login',tokenPath:'token',usernameField:'username',userAEmail:'A',userAPassword:'control-only-password',userBEmail:'B',userBPassword:'control-only-password',sourceEndpoint:'/cases/public/objects',sourceIdPath:'$[0].id',targetEndpoint:'/cases/public/objects/{id}',objectParameter:'id',accessPolicy:'public',identityPaths:'$.id',privatePaths:'',sessionEndpoint:'/me',sessionIdPath:'$.id'},
  error200: {baseUrl:'http://127.0.0.1:8899',loginEndpoint:'/login',tokenPath:'token',usernameField:'username',userAEmail:'A',userAPassword:'control-only-password',userBEmail:'B',userBPassword:'control-only-password',sourceEndpoint:'/cases/error200/objects',sourceIdPath:'$[0].id',targetEndpoint:'/cases/error200/objects/{id}',objectParameter:'id',accessPolicy:'private',identityPaths:'$.id',privatePaths:'$.private_note',sessionEndpoint:'/me',sessionIdPath:'$.id'}
};
const presetNames = {vehicle:'Lab kendaraan privat · data sintetis',public:'Kontrol objek publik · data sintetis',error200:'Kontrol HTTP 200 berisi penolakan · data sintetis'};
function switchTab(tab, focus=false) {
  currentTab=tab;
  for(const name of ['config','results','evaluation']) {
    $('#panel-'+name).hidden=name!==tab;
    const button=$('#tabButton-'+name);button.setAttribute('aria-selected',String(name===tab));button.tabIndex=name===tab?0:-1;
  }
  if(focus) $('#tabButton-'+tab).focus();
  if(tab==='config'&&currentStep===4)renderReview();
  window.scrollTo({top:0,behavior:'instant'});
}
function clearValidation() {
  $('#configError').hidden=true;
  $$('[aria-invalid="true"]').forEach(el=>{el.removeAttribute('aria-invalid');el.removeAttribute('aria-errormessage');});
  $$('.field-error').forEach(el=>el.remove());
}
function invalid(id,message,step) { const e=new Error(message);e.fieldId=id;e.step=step;throw e; }
function validateStep(step) {
  const required={1:['baseUrl','loginEndpoint','tokenPath'],2:['userAEmail','userAPassword','userBEmail','userBPassword'],3:['sourceEndpoint','sourceIdPath','targetEndpoint','objectParameter','identityPaths','sessionEndpoint','sessionIdPath']}[step]||[];
  for(const id of required) if(!$('#'+id).value.trim()) invalid(id,'Lengkapi '+$('label[for="'+id+'"]').textContent.toLowerCase()+'.',step);
  if(step===1) {
    let url;try{url=new URL($('#baseUrl').value.trim());}catch{invalid('baseUrl','Alamat API harus berupa URL lengkap, misalnya http://127.0.0.1:8890.',1);}
    if(!['http:','https:'].includes(url.protocol)||url.username||url.password) invalid('baseUrl','Gunakan URL HTTP atau HTTPS tanpa kredensial pada alamatnya.',1);
    if(!$('#loginEndpoint').value.startsWith('/')) invalid('loginEndpoint','Endpoint login harus diawali /.',1);
  }
  if(step===2 && $('#userAEmail').value.trim()===$('#userBEmail').value.trim()) invalid('userBEmail','Gunakan dua akun berbeda untuk memeriksa akses lintas pengguna.',2);
  if(step===3) {
    for(const id of ['sourceEndpoint','targetEndpoint','sessionEndpoint']) if(!$('#'+id).value.startsWith('/')) invalid(id,'Endpoint harus diawali /.',3);
    if(!$('#targetEndpoint').value.includes('{'+$('#objectParameter').value.trim()+'}')) invalid('targetEndpoint','Endpoint target harus memuat {'+$('#objectParameter').value.trim()+'}.',3);
    if($('#accessPolicy').value==='private' && !$('#privatePaths').value.trim()) invalid('privatePaths','Tentukan atribut privat sebagai bukti, misalnya $.vin.',3);
    try{parseOpenApiSpec(true);}catch(e){e.fieldId='openApiSpec';e.step=3;throw e;}
  }
}
function validateAllSteps(){for(let step=1;step<=3;step++) validateStep(step);}
function displayError(error) {
  if(error.step) {showStep(error.step);switchTab('config');}
  else if(error.fieldId==='groundTruth'){switchTab('evaluation');}
  else switchTab('config');
  const banner=$('#configError');banner.textContent=error.message;banner.hidden=false;
  if(error.fieldId){const field=$('#'+error.fieldId);field.setAttribute('aria-invalid','true');const details=field.closest('details');if(details)details.open=true;
    const note=document.createElement('p');note.className='field-error';note.textContent=error.message;note.id=error.fieldId+'Error';field.insertAdjacentElement('afterend',note);field.setAttribute('aria-errormessage',note.id);field.focus();}
}
function showStep(step) {
  currentStep=step;
  for(let n=1;n<=4;n++) {$('#step-'+n).hidden=n!==step;const b=$('[data-step="'+n+'"]');if(n===step)b.setAttribute('aria-current','page');else b.removeAttribute('aria-current');}
  if(step===4) renderReview();
}
function navigateStep(next) {
  if(scanRunning)return;clearValidation();
  try {if(next>currentStep)for(let n=1;n<next;n++)validateStep(n);showStep(next);$('#step-'+next).scrollIntoView({block:'start',behavior:'instant'});}catch(e){displayError(e);}
}
function loadPreset() {
  if(scanRunning)return;const choice=$('#labPreset').value;if(choice==='custom'){$('#presetNote').textContent='Isi konfigurasi API laboratorium sendiri. Konfigurasi yang ada tetap dipertahankan.';return;}
  for(const [key,value] of Object.entries(LAB_PRESETS[choice]))$('#'+key).value=value;
  $('#autoDiscover').checked=false;$('#openApiSpec').value='';$('#groundTruth').value='';discoveredCandidates=[];$('#candidateBox').textContent='Belum ada kandidat.';
  $('#presetNote').textContent=presetNames[choice]+'. Konfigurasi dimuat; belum ada permintaan scan yang dikirim. Ground truth opsional dikosongkan agar tidak memakai label kasus sebelumnya.';
  clearValidation();showStep(1);switchTab('config');
}
function renderReview() {
  const policy={private:'Privat — B tidak berhak',public:'Publik — akses diizinkan',shared:'Dibagikan — B berhak',unknown:'Belum diverifikasi; keputusan dapat tidak konklusif'}[$('#accessPolicy').value];
  const rows=[['Target API',$('#baseUrl').value],['Pemilik A',$('#userAEmail').value],['Penguji B',$('#userBEmail').value],['Sumber objek',$('#sourceEndpoint').value],['Pembacaan objek','GET '+$('#targetEndpoint').value],['Kebijakan',policy],['Bukti privat',$('#privatePaths').value||'Tidak ditetapkan'],['Label evaluasi',$('#groundTruth').value.trim()?'Disertakan pada scan ini':'Tidak disertakan']];
  $('#reviewSummary').innerHTML=rows.map(([k,v])=>`<div><dt>${escapeHtml(k)}</dt><dd>${escapeHtml(v)}</dd></div>`).join('');
}
function collectConfig() {
  validateAllSteps();
  const openapiSpec = parseOpenApiSpec(true);
  const groundTruth = parseGroundTruth(true);
  if ($("#autoDiscover").checked && !openapiSpec) {
    throw new Error("Isi OpenAPI JSON sebelum mengaktifkan pembuatan kasus otomatis.");
  }
  return {
    target: {
      name: "Dashboard target",
      base_url: $("#baseUrl").value.trim(),
      timeout_seconds: 10
    },
    auth: {
      login_endpoint: $("#loginEndpoint").value.trim(),
      method: "POST",
      username_field: $("#usernameField").value,
      password_field: "password",
      token_path: $("#tokenPath").value.trim(),
      token_prefix: "Bearer"
    },
    users: {
      user_a: {
        username: $("#userAEmail").value.trim(),
        password: $("#userAPassword").value
      },
      user_b: {
        username: $("#userBEmail").value.trim(),
        password: $("#userBPassword").value
      }
    },
    tests: [
      {
        name: "Configured dual-token BOLA test",
        method: "GET",
        source_endpoint: $("#sourceEndpoint").value.trim(),
        source_id_path: $("#sourceIdPath").value.trim(),
        target_endpoint: $("#targetEndpoint").value.trim(),
        object_parameter: $("#objectParameter").value.trim(),
        access_policy: $("#accessPolicy").value,
        identity_paths: $("#identityPaths").value.split(",").map(s => s.trim()).filter(Boolean),
        private_paths: $("#privatePaths").value.split(",").map(s => s.trim()).filter(Boolean),
        session_endpoint: $("#sessionEndpoint").value.trim(),
        session_id_path: $("#sessionIdPath").value.trim(),
        expected_owner_markers: [$("#userAEmail").value.trim()],
        sensitive_fields: ["email", "phone", "address", "vehicle", "vin", "user_id", "owner_id"]
      }
    ],
    auto_discover: $("#autoDiscover").checked,
    openapi_spec: openapiSpec,
    ground_truth: groundTruth
  };
}

function parseOpenApiSpec(throwOnError = true) {
  const raw = $("#openApiSpec").value.trim();
  if (!raw) return null;
  try {
    const spec = JSON.parse(raw);
    if (!spec || Array.isArray(spec) || typeof spec !== "object" || !spec.paths || Array.isArray(spec.paths) || typeof spec.paths !== "object") {
      throw new Error("Invalid OpenAPI structure");
    }
    return spec;
  } catch (error) {
    if (throwOnError) throw new Error("OpenAPI harus berupa objek JSON valid dengan bagian paths.");
    return null;
  }
}

function parseGroundTruth(throwOnError = true) {
  const raw = $("#groundTruth").value.trim();
  if (!raw) return {};
  try {
    const truth = JSON.parse(raw);
    if (!truth || Array.isArray(truth) || typeof truth !== "object" || Object.values(truth).some(value => typeof value !== "boolean")) {
      throw new Error("Invalid ground truth structure");
    }
    return truth;
  } catch (error) {
    if (throwOnError) throw new Error("Ground Truth harus berupa objek JSON valid dengan label true atau false.");
    return {};
  }
}


function normalizeFinding(f) {
  return {status:f.status||'Inconclusive',severity:f.severity||'Info',method:'GET',endpoint:f.endpoint||'-',objectId:f.object_id||'-',reason:f.reason||'Bukti belum tersedia.',confidence:f.confidence||'-',pocCurl:f.poc_curl||'-',ownerStatus:f.owner_status_code||0,attackerStatus:f.attacker_status_code||0,ownerPreview:f.owner_response_preview||'',attackerPreview:f.attacker_response_preview||'',evidence:f.evidence||{}};
}
function statusLabel(f){return f.status==='Potential BOLA'?'Indikasi BOLA':f.status==='No BOLA'?'Tidak terindikasi pada kasus ini':'Belum dapat disimpulkan';}
function statusType(f){return f.status==='Potential BOLA'?'danger':f.status==='No BOLA'?'good':'warning';}
function updateSummary(){
  $('#totalTests').textContent=findings.length;$('#findingCount').textContent=findings.filter(f=>f.status==='Potential BOLA').length;$('#unresolvedCount').textContent=findings.filter(f=>!['Potential BOLA','No BOLA'].includes(f.status)).length;
  $('#resultBadge').hidden=!findings.length;$('#resultBadge').textContent=findings.length;
  $('#scanEmpty').hidden=Boolean(findings.length);$('#resultsLayout').hidden=!findings.length;
}
function renderFindings(){
  $('#findingTable').innerHTML=findings.map((f,i)=>`<div class="finding-row"><button type="button" class="endpoint-title" data-index="${i}" aria-pressed="${i===selectedFinding}"><span class="status-pill ${statusType(f)}">${escapeHtml(statusLabel(f))}</span><strong>GET ${escapeHtml(f.endpoint)}</strong><span class="case-reason">Objek ${escapeHtml(f.objectId)}</span></button></div>`).join('');
  $('#findingTable').querySelectorAll('button[data-index]').forEach(b=>b.addEventListener('click',()=>{selectedFinding=Number(b.dataset.index);renderFindings();}));
  updateSummary();if(findings.length)showFindingDetail(selectedFinding);
}
function valueAt(body,path){try{let result=body;const keys=path.replace(/^\$/, '').replace(/\[(\d+)\]/g,'.$1').split('.').filter(Boolean);for(const k of keys)result=result[k];return result;}catch{return undefined;}}
function responsePanel(f,role,label,status,preview){
  const record=f.evidence[role]?.response;let body=record?.body;
  if(body===undefined)try{body=JSON.parse(preview);}catch{body=undefined;}
  const paths=[...(f.evidence.identity_paths||[]),...(f.evidence.private_paths||[])];
  const summary=paths.slice(0,5).map(p=>{const v=valueAt(body,p);return `<div><dt>${escapeHtml(p)}</dt><dd>${escapeHtml(v===undefined?'Tidak tersedia':JSON.stringify(v).slice(0,110))}</dd></div>`;}).join('');
  const json=body===undefined?(preview||'Tidak ada respons yang diterima.'):JSON.stringify(body,null,2);
  return `<div class="response-card"><h3>${label}</h3><span class="status-pill">${status?'HTTP '+escapeHtml(status):'Tidak ada respons'}</span><dl class="evidence-summary">${summary}</dl><details><summary>Lihat respons JSON</summary><pre>${escapeHtml(json)}</pre></details></div>`;
}
function showFindingDetail(i){
  const f=findings[i];if(!f)return;
  $('#detailSeverity').textContent=f.status==='Potential BOLA'?'Perlu ditinjau':f.status==='No BOLA'?'Kasus selesai':'Bukti belum cukup';$('#detailSeverity').className='status-pill '+statusType(f);
  let explanation=f.status==='Potential BOLA'?'Pengguna lain menerima identitas objek dan atribut privat yang cocok dengan respons pemilik. Tinjau kembali dasar kepemilikan dan izin akses.':f.status==='No BOLA'?'Engine tidak menemukan pelanggaran pada akses objek dalam kasus ini. Hasil ini tidak menyatakan seluruh aplikasi aman.':'Engine belum dapat mengambil keputusan. Periksa alasan teknis di bawah, kesiapan target, akun, dan pemetaan objek.';
  const p=f.evidence.policy||lastConfig?.tests?.[0]?.access_policy||'Tidak tersedia';
  $('#findingDetail').innerHTML=`<h3>${escapeHtml(statusLabel(f))}</h3><p class="detail-reason">${explanation}</p><details class="advanced"><summary>Alasan teknis dari engine</summary><p class="proof-note">${escapeHtml(f.reason)}</p></details><dl class="detail-list"><div><dt>Objek target</dt><dd>${escapeHtml(f.objectId)}</dd></div><div><dt>Kebijakan terkonfigurasi</dt><dd>${escapeHtml(p)}</dd></div><div><dt>Identitas sesi berbeda</dt><dd>${f.evidence.sessions_valid===true?'Terverifikasi':f.evidence.sessions_valid===false?'Tidak terverifikasi':'Bukti tidak tersedia'}</dd></div><div><dt>Metode</dt><dd>GET · Pembacaan objek</dd></div></dl><h3>Bukti kedua respons</h3><p class="proof-note">Field yang diperiksa ditampilkan dahulu. Buka JSON untuk melihat respons yang tersedia.</p><div class="responses">${responsePanel(f,'owner','A · Pemilik objek',f.ownerStatus,f.ownerPreview)}${responsePanel(f,'cross_user','B · Pengguna penguji',f.attackerStatus,f.attackerPreview)}</div><details class="advanced"><summary>Permintaan reproduksi curl</summary><p class="proof-note">Isi variabel TOKEN_OTHER dengan token baru akun penguji. Jalankan hanya pada target lab yang sama. Perintah dari engine memakai format shell POSIX.</p><pre class="poc-box">${escapeHtml(f.pocCurl)}</pre></details>`;
}
function formatScore(v){return v==null?'Tidak terdefinisi':escapeHtml(v);}
function renderMetrics(){
  const box=$('#metricsBox');
  if(!metrics){box.innerHTML='<h2>Belum ada metrik evaluasi.</h2><p class="muted">Siapkan label acuan sebelum scan untuk menghitung metrik dari hasil engine. Scan tanpa label tetap menghasilkan bukti deteksi.</p>';return;}
  const m=metrics;const chip=(n,v)=>`<div class="metric-chip"><strong>${formatScore(v)}</strong><span>${n}</span></div>`;
  const completed=m.completed_cases||0,planned=m.planned_cases||0;
  box.innerHTML=`<h2>Evaluasi pengujian terakhir</h2><p class="caption">${escapeHtml(lastRunStarted)} · ${escapeHtml(lastRunContext)}</p><table class="matrix"><caption>Confusion matrix pada kasus konklusif</caption><thead><tr><th scope="col">Label acuan</th><th scope="col">Prediksi positif</th><th scope="col">Prediksi negatif</th></tr></thead><tbody><tr><th scope="row">Rentan</th><td>TP ${escapeHtml(m.true_positive)}</td><td>FN ${escapeHtml(m.false_negative)}</td></tr><tr><th scope="row">Tidak rentan</th><td>FP ${escapeHtml(m.false_positive)}</td><td>TN ${escapeHtml(m.true_negative)}</td></tr></tbody></table><div class="metric-grid">${chip('Precision',m.precision)}${chip('Recall konklusif',m.recall)}${chip('F1',m.f1_score)}${chip('Kasus konklusif / direncanakan',completed+' / '+planned)}${chip('Tidak konklusif / belum diuji',m.unresolved_cases?.length||0)}${chip('Recall operasional',m.operational_recall)}</div><p class="proof-note">Cakupan keputusan konklusif: ${planned?Math.round(completed/planned*100)+'%':'Tidak terdefinisi'}. Kasus tidak konklusif tidak dipetakan menjadi negatif pada matriks. Ini bukan cakupan seluruh endpoint API.</p><p class="proof-note">Label dan metrik melekat pada scan terakhir. Mengubah formulir label tidak menghitung ulang hasil ini.</p>`;
}
function setScanState(text,type=''){$('#scanState').textContent=text;$('#scanState').className='status-pill '+type;}
function appendLog(line){$('#scanLog').textContent+=line+'\n';}
function resetLog(line){$('#scanLog').textContent=line+'\n';}
function applyApiResult(data){
  findings=(data.findings||[]).map(normalizeFinding);reportPaths=data.reports||{};metrics=data.metrics||null;selectedFinding=0;renderFindings();renderMetrics();
  $('#reportSection').hidden=!Object.keys(reportPaths).length;$('#reportLocations').innerHTML=Object.entries(reportPaths).map(([k,v])=>`<p>${escapeHtml(k)}<code>${escapeHtml(v)}</code></p>`).join('');
  appendLog(`[hasil] ${findings.length} kasus; ${findings.filter(f=>f.status==='Potential BOLA').length} indikasi BOLA.`);
}
async function discoverCandidates(){
  const box=$('#candidateBox');$('#discoverButton').disabled=true;box.textContent='Memeriksa spesifikasi...';
  try{const spec=parseOpenApiSpec(true);if(!spec)throw new Error('Isi OpenAPI JSON terlebih dahulu.');const res=await fetch('/api/openapi/discover',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({openapi_spec:spec})});const data=await res.json();if(!res.ok||!data.ok)throw new Error(data.error||'Penemuan kandidat gagal.');discoveredCandidates=data.candidates||[];box.innerHTML=discoveredCandidates.length?`<p>${discoveredCandidates.length} kandidat ditemukan. Maksimal 8 ditampilkan.</p>`+discoveredCandidates.slice(0,8).map(c=>`<div class="candidate-item"><strong>${escapeHtml(c.method)} ${escapeHtml(c.path)}</strong><span>${escapeHtml(c.risk_hint)}</span></div>`).join(''):'Tidak ada kandidat endpoint berparameter objek.';}catch(e){box.textContent=e.message;}finally{$('#discoverButton').disabled=scanRunning;}
}
function setBusy(busy){
  scanRunning=busy;$$('#scanForm input, #scanForm select, #scanForm textarea, #scanForm button, .config-nav button').forEach(e=>e.disabled=busy);
  for(const id of ['runButton','clearButton','loadPreset','labPreset','groundTruth','discoverButton'])$('#'+id).disabled=busy;
  $('#runningNotice').hidden=!busy;$('#runButton').textContent=busy?'Sedang menguji…':'Jalankan pengujian';
  $('#scanEmpty').hidden=busy||Boolean(findings.length);
}
function resetResultState(){findings=[];reportPaths={};metrics=null;selectedFinding=0;renderFindings();renderMetrics();$('#findingDetail').innerHTML='<p class="muted">Pilih kasus untuk melihat bukti.</p>';$('#reportSection').hidden=true;$('#reportLocations').innerHTML='';$('#resultBanner').hidden=true;}
async function runConfiguredScan(event){
  event.preventDefault();if(scanRunning)return;clearValidation();resetResultState();resetLog('[scan] Memeriksa konfigurasi.');
  let config;
  try{config=collectConfig();}catch(e){if(e.message.includes('Ground Truth'))e.fieldId='groundTruth';displayError(e);appendLog('[error] '+e.message);setScanState('Konfigurasi perlu diperiksa','warning');return;}
  lastConfig=config;lastRunStarted=new Date().toLocaleString('id-ID');lastRunContext='API terkonfigurasi';
  for(const [key,values] of Object.entries(LAB_PRESETS))if(Object.entries(values).every(([k,v])=>$('#'+k).value===v))lastRunContext=presetNames[key];
  $('#resultContext').textContent=lastRunContext+' · '+config.target.base_url+' · '+lastRunStarted;
  setBusy(true);setScanState('Sedang menguji');switchTab('results');const banner=$('#resultBanner');banner.textContent='Engine memproses HTTP ke target. Tunggu respons; jangan tutup halaman.';banner.className='notice progress';banner.hidden=false;
  appendLog('[scan] Konfigurasi dikirim ke backend lokal. Menunggu respons akhir.');
  try{const response=await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(config)});const data=await response.json();if(!response.ok||!data.ok)throw new Error(data.error||'Permintaan scan gagal.');applyApiResult(data);setScanState('Selesai','good');banner.textContent=findings.some(f=>f.status==='Inconclusive')?'Permintaan selesai, tetapi ada kasus yang belum dapat disimpulkan. Periksa alasan teknis.':'Pengujian selesai. Pilih kasus untuk meninjau bukti dan izin aksesnya.';banner.className='notice '+(findings.some(f=>f.status==='Inconclusive')?'warning':'success');banner.hidden=false;appendLog('[selesai] Respons akhir diterima.');}
  catch(e){appendLog('[error] '+e.message);banner.textContent='Pengujian gagal: '+e.message+'. Periksa target, kredensial, dan konfigurasi. Tidak ada hasil lama yang digunakan.';banner.className='notice error';banner.hidden=false;setScanState('Gagal','danger');}
  finally{setBusy(false);checkBackend();}
}
function clearResults(){if(scanRunning)return;resetResultState();resetLog('Hasil dibersihkan. Konfigurasi tetap tersedia.');setScanState('Siap');$('#resultContext').textContent='Belum ada hasil pengujian aktif.';}
async function checkBackend(){const el=$('#backendState');try{const res=await fetch('/api/health',{cache:'no-store'});const data=await res.json();if(!res.ok||data.ok!==true||data.service!=='bola-fuzzer')throw new Error();el.textContent='Engine terhubung';el.className='status-pill good';}catch{el.textContent='Engine tidak terhubung';el.className='status-pill danger';}}
$('#scanForm').addEventListener('submit',runConfiguredScan);
$('#clearButton').addEventListener('click',clearResults);$('#discoverButton').addEventListener('click',discoverCandidates);
$$('[data-tab]').forEach(b=>{b.addEventListener('click',()=>switchTab(b.dataset.tab));b.addEventListener('keydown',e=>{const tabs=['config','results','evaluation'];if(['ArrowLeft','ArrowRight','Home','End'].includes(e.key)){e.preventDefault();const i=tabs.indexOf(currentTab);switchTab(e.key==='Home'?tabs[0]:e.key==='End'?tabs[2]:tabs[(i+(e.key==='ArrowRight'?1:2))%3],true);}});});
$$('[data-step]').forEach(b=>b.addEventListener('click',()=>navigateStep(Number(b.dataset.step))));
$('#loadPreset').addEventListener('click',loadPreset);
for(const id of ['editConfigButton','emptyConfigureButton','evaluationConfigButton'])$('#'+id).addEventListener('click',()=>switchTab('config'));
$('#scanForm').addEventListener('keydown',e=>{if(e.key==='Enter'&&e.target.tagName==='INPUT')e.preventDefault();});
renderFindings();renderMetrics();showStep(1);checkBackend();
