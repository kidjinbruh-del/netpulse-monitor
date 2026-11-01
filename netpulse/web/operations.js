/* Persistent operations UI. Credentials are references, not browser-held passwords. */
'use strict';
const Ops = {
 role: 'viewer', currentDevice: null, currentIncident: null, config: [], timer: null,
 date(value) { return value ? new Date(typeof value === 'number' ? value*1000 : value).toLocaleString('ru-RU') : '—'; },
 async load() {
  try {
   const state = await apiGet('operations?search='+encodeURIComponent($('ops-search').value));
   this.role=state.role;
   $('ops-summary').textContent=`Открыто: ${state.summary.open} · Принято в работу: ${state.summary.acknowledged} · Закрыто: ${state.summary.resolved} (последние 500)`;
   $('ops-health').textContent='Состояние NetPulse: '+state.health.status+' · '+state.health.checks.map(c=>c.name+': '+(c.ok?'OK':'требует внимания')).join(' · ');
   $('ops-devices').innerHTML=state.devices.map(d=>`<tr><td><button class="ops-table-button" data-device-id="${esc(d.id)}">${esc(d.name)}</button></td><td>${esc(d.address)}</td><td>${d.online===null?'Нет данных':d.online?'В сети':'Нет связи'}${d.maintenance?' · техработы':''}</td><td>${esc(d.site||'—')} / ${esc(d.owner||'—')}</td></tr>`).join('')||'<tr><td colspan="4">Пока нет устройств. Добавьте MikroTik ниже или выполните инвентаризацию парка.</td></tr>';
   $('ops-incidents').innerHTML=state.incidents.map(i=>`<tr><td><button class="ops-table-button" data-incident-id="${esc(i.id)}">${esc(i.title)}</button></td><td>${esc(i.status)}</td><td>${esc(i.owner||'—')}</td><td>${esc(this.date(i.updated))}</td></tr>`).join('')||'<tr><td colspan="4">Инцидентов пока нет.</td></tr>';
   $('ops-deliveries').innerHTML=state.deliveries.map(d=>`<tr><td>${esc(d.channel)}</td><td>${esc(d.title)}</td><td>${esc(d.status)}${d.error?' · '+esc(d.error):''}</td><td>${d.attempts}</td></tr>`).join('')||'<tr><td colspan="4">Отправок ещё не было. Уведомления отправляются только в настроенные включённые каналы.</td></tr>';
   $('ops-admin').hidden=this.role!=='admin';$('ops-test-notifications').hidden=this.role!=='admin';
   if(this.role==='admin') {
    const cfg=await apiGet('deviceconfig');this.config=cfg.devices;
    $('ops-configured').innerHTML=cfg.devices.map((d,i)=>`<button class="ops-table-button" type="button" data-edit-device="${i}">${esc(d.name||d.id)} · ${d.credential_available?'переменная пароля доступна':'пароль в окружении не найден'}</button><br>`).join('');
   }
  } catch(e) { $('ops-summary').textContent=e.message; }
 },
 async device(id) {
  try {
   const d=await apiGet('device?id='+encodeURIComponent(id));this.currentDevice=d;
   const panel=$('ops-device-detail');panel.hidden=false;
   panel.innerHTML=`<div class="ops-detail"><h3>${esc(d.name)}</h3><p>${esc(d.id)} · ${esc(d.address)}</p><p>Проверено: ${esc(this.date(d.checked_at))}</p><p>${esc(d.error||'')}</p>`+
    (this.role!=='viewer'?`<form id="ops-context-form"><div class="ops-grid"><label>Площадка<input name="site" maxlength="160" value="${esc(d.site)}"></label><label>Ответственный<input name="owner" maxlength="160" value="${esc(d.owner)}"></label><label>Теги через запятую<input name="tags" value="${esc(d.tags.join(', '))}"></label><label>Техническое окно<select name="maintenance"><option value="keep">Сохранить текущее</option><option value="0">Закончить</option><option value="3600">На час</option><option value="14400">На 4 часа</option><option value="86400">На сутки</option></select></label></div><p>До: ${esc(this.date(d.maintenance_until))}</p><button type="submit" class="btn accent">Сохранить контекст</button><button type="button" class="btn ghost" id="ops-create-incident">Создать инцидент</button></form>`:'')+
    '<details><summary>Показатели и дополнительные таблицы</summary><pre>'+esc(JSON.stringify(d.data||d.inventory||{},null,2).slice(0,24000))+'</pre></details></div>';
   $('ops-context-form')?.addEventListener('submit',event=>this.saveContext(event));
   $('ops-create-incident')?.addEventListener('click',()=>this.createIncident());
  } catch(e) { toast(e.message,true); }
 },
 async saveContext(event) {
  event.preventDefault();const f=new FormData(event.target),d=this.currentDevice;
  const duration=f.get('maintenance');const until=duration==='keep'?d.maintenance_until: +duration?Date.now()/1000+(+duration):0;
  try { await apiPost('devicemeta',{id:d.id,site:f.get('site'),owner:f.get('owner'),tags:f.get('tags').split(',').map(v=>v.trim()).filter(Boolean),maintenance_until:until});await this.load();await this.device(d.id);toast('Контекст сохранён'); } catch(e) {toast(e.message,true);}
 },
 async createIncident() {
  const title=prompt('Опишите проблему устройства');if(!title?.trim())return;
  try {const result=await apiPost('incidentcreate',{device_id:this.currentDevice.id,title,severity:'warning'});await this.load();await this.incident(result.id);} catch(e){toast(e.message,true);}
 },
 async incident(id) {
  try {
   const i=await apiGet('incident?id='+encodeURIComponent(id));this.currentIncident=i;
   const panel=$('ops-incident-detail');panel.hidden=false;
   panel.innerHTML=`<div class="ops-detail"><h3>${esc(i.title)}</h3><p>${esc(i.status)} · ${esc(i.severity)} · ${esc(i.owner||'без ответственного')}</p><p>Открыт: ${esc(this.date(i.opened))} · Повторений: ${i.occurrences}</p>`+
    (this.role!=='viewer'?`<form id="ops-incident-form"><label>Ответственный<input name="owner" maxlength="160" value="${esc(i.owner)}"></label><label>Комментарий<textarea name="message" maxlength="2000"></textarea></label><div class="ops-actions"><button class="btn ghost" name="action" value="assign">Назначить</button><button class="btn ghost" name="action" value="comment">Комментарий</button>${i.status==='open'?'<button class="btn accent" name="action" value="acknowledge">Принять в работу</button>':''}${i.status!=='resolved'?'<button class="btn ghost" name="action" value="resolve">Закрыть</button>':''}</div></form>`:'')+
    '<ul>'+i.timeline.map(t=>`<li>${esc(this.date(t.ts))} · ${esc(t.actor)} · ${esc(t.action)} ${esc(t.message)}</li>`).join('')+'</ul></div>';
   $('ops-incident-form')?.addEventListener('submit',event=>this.changeIncident(event));
  }catch(e){toast(e.message,true);}
 },
 async changeIncident(event) {
  event.preventDefault();const f=new FormData(event.target),id=this.currentIncident.id;
  try {await apiPost('incidentchange',{id,action:event.submitter.value,owner:f.get('owner'),message:f.get('message')});await this.load();await this.incident(id);}catch(e){toast(e.message,true);}
 },
 setupBody() {
  const form=$('ops-setup-form');if(!form.reportValidity())return null;
  const f=new FormData(form);return {id:f.get('id'),name:f.get('name'),url:f.get('url'),transport:f.get('transport'),username:f.get('username'),password_env:f.get('password_env'),ca_file:f.get('ca_file'),timeout_sec:+f.get('timeout_sec'),legacy_login:f.has('legacy_login'),tables:f.getAll('tables')};
 },
 async save(event) {
  event.preventDefault();const body=this.setupBody();if(!body)return;
  try {const r=await apiPost('devicesave',body);$('ops-setup-status').textContent=r.credential_available?'Устройство сохранено. Следующий опрос использует настройки.':'Настройки сохранены. Задайте переменную пароля у процесса NetPulse и повторите проверку.';await this.load();}catch(e){$('ops-setup-status').textContent=e.message;}
 },
 async probe() {
  const body=this.setupBody();if(!body)return;const button=$('ops-probe');button.disabled=true;
  try {
   $('ops-setup-status').textContent='Проверяем TLS, права и ответы устройства…';
   const result=await apiPost('deviceprobe',body);
   for(let n=0;n<90;n++){
    await new Promise(resolve=>setTimeout(resolve,1500));const job=await apiGet('securityresult?job='+encodeURIComponent(result.job));
    if(job.status==='error')throw new Error('Проверка не выполнена');
    if(job.status==='done'){$('ops-setup-status').textContent=job.result.ok?'Связь подтверждена. RouterOS '+job.result.data.version:job.result.error;return;}
   }
   $('ops-setup-status').textContent='Проверка ещё работает в фоне. Повторите обновление позже.';
  }catch(e){$('ops-setup-status').textContent=e.message;}finally{button.disabled=false;}
 },
 edit(index) {
  const device=this.config[index],form=$('ops-setup-form');form.reset();
  for(const [key,value] of Object.entries(device)) {const field=form.elements.namedItem(key);if(field&&key!=='tables'){if(field.type==='checkbox')field.checked=!!value;else field.value=value??'';}}
  form.querySelectorAll('[name=tables]').forEach(input=>input.checked=(device.tables||[]).includes(input.value));
  form.scrollIntoView({behavior:'auto',block:'start'});
 },
 async testNotifications() {
  try {const result=await apiPost('notificationtest');toast(result.queued?'Уведомления поставлены в очередь: '+result.queued:'Включённых каналов нет');await this.load();}catch(e){toast(e.message,true);}
 }
};
document.getElementById('ops-setup-form').addEventListener('submit',event=>Ops.save(event));
document.getElementById('ops-probe').addEventListener('click',()=>Ops.probe());
document.getElementById('ops-search').addEventListener('input',()=>{clearTimeout(Ops.timer);Ops.timer=setTimeout(()=>Ops.load(),250);});
document.getElementById('view-operations').addEventListener('click',event=>{
 const d=event.target.closest('[data-device-id]');if(d)Ops.device(d.dataset.deviceId);
 const i=event.target.closest('[data-incident-id]');if(i)Ops.incident(i.dataset.incidentId);
 const edit=event.target.closest('[data-edit-device]');if(edit)Ops.edit(+edit.dataset.editDevice);
});
