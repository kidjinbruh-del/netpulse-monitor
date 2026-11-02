/* Read-only summaries, explicit remote jobs, honest missing-data states. */
'use strict';
window.Sysadmin = {
  active:new Set(), jobs:{},
  number(value,digits=1) { return value==null || !Number.isFinite(+value) ? '—' : (+value).toLocaleString('ru-RU',{maximumFractionDigits:digits}); },
  duration(value) { if(value==null)return '—'; const s=Math.max(0,Math.round(+value));return s>=86400?this.number(s/86400)+' дн.':s>=3600?this.number(s/3600)+' ч':s>=60?this.number(s/60)+' мин':s+' с'; },
  empty(text) { return `<div class="sa-empty">${esc(text)}</div>`; },
  table(id,headers,rows) { return `<table class="tbl" id="sa-table-${id}"><thead><tr>${headers.map(h=>`<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${rows.map(row=>`<tr>${row.map(cell=>`<td>${cell}</td>`).join('')}</tr>`).join('')}</tbody></table>`; },
  note(text) { return `<p class="sa-note">${esc(text)}</p>`; },
  badge(text) { return `<span class="sa-badge">${esc(text)}</span>`; },
  async read(id,endpoint,render) {
    if(this.active.has(id))return;
    this.active.add(id);
    const box=$(id+'-box'), card=box.closest('.card');box.setAttribute('aria-busy','true');
    card.querySelectorAll('button[data-refresh]').forEach(b=>b.disabled=true);
    const state=card.querySelector('.sa-state'); state.textContent='Загрузка…';state.dataset.state='loading';
    try {
      const response=await apiGet(endpoint);box.innerHTML=render(response);
      state.textContent='Ответ: '+new Date().toLocaleTimeString('ru-RU');state.dataset.state='ready';
    } catch(error) {
      box.innerHTML=this.empty(error.message+' · Обновите этот блок после устранения причины.');
      state.textContent='Не удалось загрузить';state.dataset.state='error';
    } finally {this.active.delete(id);box.setAttribute('aria-busy','false');card.querySelectorAll('button[data-refresh]').forEach(b=>b.disabled=false);}
  },
  load() {return Promise.allSettled([this.sla(),this.ram(),this.l2(),this.geo(),this.proxmox(),this.mtr(),this.cve(),this.audit()]);},
  sla() { const days=$('sa-sla-days').value;return this.read('sla','sla?days='+days,r=>{
    const rows=r.devices||[];
    return this.note('Оценка по переходам ONLINE/OFFLINE, не договорный SLA. До 95% покрытия процент периода не выводится; время до первого известного состояния считается неизвестным.')+
      (rows.length?this.table('sla',['Узел / IP','Сейчас','Доступность периода','Покрытие','Время offline','События offline / online'],rows.map(d=>[
        `<b>${esc(d.name)}</b><br><span class="muted">${esc(d.ip)}</span>`,this.badge(d.online==null?'Нет данных':d.online?'В сети':'Нет связи'),
        d.sla_pct==null?'Недостаточно наблюдений':this.number(d.sla_pct,3)+'%',this.number(d.coverage_pct)+'%',this.duration(d.down_seconds),this.number(d.offline_events,0)+' / '+this.number(d.online_events,0)
      ])):this.empty('Нет данных агентов. Подключите парк ПК и накопите события доступности.'));
  });},
  ram() {return this.read('ram','ramforecast',r=>{
    if(!r.ok)return this.empty(r.note||'Недостаточно истории ОЗУ');
    return `<div class="sa-kpis"><div><small>ОЗУ сейчас</small><strong>${this.number(r.last_pct)}%</strong></div><div><small>Изменение за минуту</small><strong>${this.number(r.slope_pct_pt,3)} п.п.</strong></div></div>`+
      this.note(r.seconds_to_95!=null?'До 95% по текущему тренду: '+this.duration(r.seconds_to_95):'Достижение 95% не прогнозируется в допустимом горизонте. Это не гарантия отсутствия будущей нагрузки.')+
      this.note(`Измерений: ${r.n_points||0} · окно: ${this.duration(r.span_seconds)} · горизонт: ${this.duration(r.horizon_seconds)}. ${r.note||''}`);
  });},
  l2() {return this.read('l2','l2map',r=>{
    const ports=r.ports||[];
    return this.note('Сохранённый снимок FDB. MAC за портом может находиться через другой коммутатор; это не доказательство прямого кабеля. Обновление блока не запускает SNMP-опрос.')+
      (ports.length?this.table('l2',['MAC','Порт / ifIndex','Коммутатор'],ports.slice(0,500).map(p=>[esc(p.mac),esc(p.if_name||p.port||'—')+' / '+esc(p.if_index??'—'),esc(p.switch_ip||'—')])):this.empty(r.status?.scanning?'Сбор L2-карты выполняется. Обновите снимок позднее.':'L2-карта пока пуста. Проверьте настроенные коммутаторы и доступ SNMP.'));
  });},
  geo() {return this.read('geo','geomap?limit=150',r=>{
    const countries=(r.countries||[]).map(c=>Array.isArray(c)?{country:c[0],n:c[1]}:c);
    const max=Math.max(1,...countries.map(c=>+c.n||0));
    return this.note(r.note||'Приблизительная офлайн-география упоминаний IP. Адрес может относиться к источнику или назначению; страна адреса не доказывает происхождение атаки.')+
      `<div class="sa-kpis"><div><small>Упоминаний IP</small><strong>${this.number(r.total_ips,0)}</strong></div><div><small>Уникальных адресов</small><strong>${this.number(r.uniq,0)}</strong></div></div>`+
      (countries.length?countries.map(c=>`<div class="sa-country"><span>${esc(c.country==='?'?'Страна не определена':c.country)}</span><meter min="0" max="${max}" value="${Math.max(0,+c.n||0)}" aria-label="Количество упоминаний"></meter><b>${this.number(c.n,0)}</b></div>`).join(''):this.empty('Нет IP для географической сводки. Это не подтверждает отсутствие атак.'));
  });},
  proxmox() {return this.read('pxm','proxmox',r=>{
    $('sa-pxm-poll').disabled=!r.enabled||!r.configured||this.jobs.pxm;
    if(!r.enabled)return this.empty('Proxmox VE отключён. Настройте секцию proxmox: HTTPS-хост, API token ID и токен через NP_PROXMOX_TOKEN.');
    if(!r.configured)return this.empty('Proxmox VE включён, но не хватает адреса или учётных данных. Токен не нужно вставлять в браузер.');
    const nodes=r.nodes||[],vms=r.vms||[];
    return this.note((r.error?r.error+'. ':'')+(r.stale?'Показан старый успешный снимок. ':'')+'Последний снимок: '+(r.checked||'ещё не получен')+(r.verify_tls===false?' · Проверка TLS отключена в конфигурации.':''))+
      `<div class="sa-kpis"><div><small>Узлов в снимке</small><strong>${nodes.length}</strong></div><div><small>VM / LXC</small><strong>${vms.length}</strong></div></div>`+
      (nodes.length?this.table('pve-nodes',['Узел','Статус','CPU %','RAM GB / всего','Uptime'],nodes.map(n=>[esc(n.node),this.badge(n.status||'Неизвестно'),this.number(n.cpu),this.number(n.mem)+' / '+this.number(n.maxmem),this.duration(n.uptime)])):this.empty('Нет снимка узлов. Нажмите «Опросить PVE», чтобы выполнить явный запрос.'))+
      (vms.length?this.table('pve-vms',['VMID','Имя','Тип','Узел','Статус','CPU %','RAM GB / всего'],vms.map(v=>[esc(v.vmid),esc(v.name),esc(v.type),esc(v.node),this.badge(v.status),this.number(v.cpu),this.number(v.mem)+' / '+this.number(v.maxmem)])):'');
  });},
  mtr() {return this.read('mtrhist','mtrhistory?hours='+$('sa-mtr-hours').value,r=>{
    const entries=r.entries||[];
    return this.note('Каждая строка — измерение одного хопа. Потери промежуточного ICMP-ответа не равны потерям прикладного трафика. Новая трассировка запускается в «Диагностике».')+
      (entries.length?this.table('mtr',['Время','Цель','Хоп','IP','Потери %','Средний ms'],entries.slice(-200).reverse().map(x=>[esc(x.ts),esc(x.target),esc(x.hop??'—'),esc(x.ip||'—'),this.number(x.loss_pct),this.number(x.avg_ms)])):this.empty('За выбранный период нет сохранённых MTR-измерений.'));
  });},
  resultCve(result) {
    const found=result.found||[];
    return this.note(`Проверено продуктов (с учётом кэша): ${result.products??'—'} · ${result.checked_at||''}`)+
      (result.complete===false?this.empty(result.error||'Проверка неполная: часть продуктов не проверена.'):this.note(found.length?'Найдены кандидаты. Проверьте версии и применимость CVE.':'Совпадений в обработанном наборе не найдено. Это не подтверждение отсутствия уязвимостей.'))+
      (found.length?this.table('cve',['Продукт / версия','CVE','Severity','Описание'],found.map(f=>[
        esc(f.product)+' '+esc(f.version||''),/^CVE-\d{4}-\d+$/i.test(f.cve)?`<a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(f.cve)}" target="_blank" rel="noopener noreferrer">${esc(f.cve)}</a>`:esc(f.cve),esc(f.severity||'—'),esc(f.summary||'')])):'');
  },
  cve() {return this.read('cve','cvestatus',r=>{
    $('sa-cve-run').disabled=!r.enabled||!!this.jobs.cve;
    return this.note('NVD: поиск по имени/версии. Это кандидаты для проверки, а не подтверждённые уязвимости. Отправка названий ПО во внешний NVD выполняется только при явном запуске.')+
      `<div class="sa-kpis"><div><small>Кандидатов в кэше</small><strong>${this.number(r.found,0)}</strong></div><div><small>Онлайн-проверка</small><strong>${r.enabled?'Включена':'Отключена'}</strong></div></div>`+
      this.note('Кэш обновлён: '+(r.last||'ещё не создан')+(r.nvd_key?' · ключ NVD задан':' · без ключа NVD, возможны ограничения запросов'))+
      (r.error?this.empty(r.error):'')+(r.last_result?this.resultCve(r.last_result):this.empty('Результата запуска в этой сессии ещё нет.'));
  });},
  audit() {return this.read('audit','audit?limit='+$('sa-audit-limit').value,r=>{
    const rows=r.entries||[];
    return this.note('Аудит HTTP-действий: кто, откуда и что изменял. Не заменяет системный журнал ОС.')+
      (rows.length?this.table('audit',['Время','Пользователь','IP','Действие','HTTP','Подробности'],rows.map(x=>[esc(x.timestamp),esc(x.user),esc(x.ip),esc(x.action),esc(x.status??'—'),esc(String(x.details||'').slice(0,500))])):this.empty('Изменения ещё не зарегистрированы.'));
  });},
  async run(kind) {
    if(this.jobs[kind])return;
    const id=kind==='cve'?'cve':'pxm', button=$(kind==='cve'?'sa-cve-run':'sa-pxm-poll');button.disabled=true;
    try {
      const response=await apiPost(kind==='cve'?'cvescan':'proxmoxpoll');this.jobs[kind]=response.job;
      for(let n=0;n<900;n++){
        $(id+'-box').textContent='Фоновая задача выполняется. Можно перейти в другой раздел. Идентификатор: '+response.job;
        await new Promise(resolve=>setTimeout(resolve,1500));
        const job=await apiGet('securityresult?job='+encodeURIComponent(response.job));
        if(job.status==='error')throw new Error(job.error||'Задача не выполнена');
        if(job.status==='done'){delete this.jobs[kind];if(kind==='cve'){$(id+'-box').innerHTML=this.resultCve(job.result);}else await this.proxmox();return;}
      }
      throw new Error('Задача остаётся в фоне. Идентификатор: '+response.job+'. Обновите состояние позднее.');
    }catch(error){$(id+'-box').textContent=error.message;}
    finally{delete this.jobs[kind];button.disabled=false;}
  },
};
