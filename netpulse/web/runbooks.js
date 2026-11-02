'use strict';
window.Runbooks = {
  definitions:[], busy:false,
  render(data) {
    this.definitions=data.runbooks||[];
    const box=$('rb-list');box.classList.remove('muted');
    box.innerHTML=this.definitions.map((rb,index)=>`<article class="rb-card"><div><h3>${esc(rb.name)}</h3><p>${esc(rb.description||'')}</p><div class="rb-tags"><span>${rb.scope==='remote'?'Удалённый компьютер':'Этот сервер'}</span><span>${rb.changes_state===false?'Только чтение':'Изменяет состояние'}</span>${rb.supported===false?'<span>Требуется Windows</span>':''}</div></div><button class="btn ${rb.changes_state===false?'accent':'ghost'}" data-runbook="${index}" ${this.busy||data.enabled===false||rb.supported===false?'disabled':''}>${rb.changes_state===false?'Проверить':'Подготовить запуск'}</button></article>`).join('')||'<p class="sa-empty">Сценарии не найдены.</p>';
    box.querySelectorAll('[data-runbook]').forEach(button=>button.onclick=()=>this.prepare(+button.dataset.runbook));
    const history=$('rb-history');
    history.innerHTML=(data.log||[]).length?Sysadmin.table('runbook-log',['Время','Сценарий','Кто','Цель','Код'],data.log.map(row=>[esc(row.timestamp),esc(row.runbook),esc(row.actor),esc(row.target),esc(row.exit_code??'—')])):'<p class="sa-note">Запусков ещё не было.</p>';
  },
  prepare(index) {
    if(this.busy)return;
    const rb=this.definitions[index], form=$('rb-form');form.replaceChildren();
    if(rb.changes_state===false && !rb.params?.length){this.execute(rb,{});return;}
    const title=document.createElement('h3');title.textContent=rb.name;form.append(title);
    const note=document.createElement('p');note.className='sa-note';note.textContent='Сценарий изменит состояние '+(rb.scope==='remote'?'указанного компьютера. Для перезапуска Spooler могут потребоваться WinRM и права администратора.':'этого сервера.');form.append(note);
    const fields=rb.fields||rb.params?.map(name=>({name,required:true}))||[];
    fields.forEach(field=>{
      const label=document.createElement('label');label.textContent=field.name==='host'?'Имя или IPv4 целевого компьютера':field.name;
      const input=document.createElement('input');input.className='inp';input.name=field.name;input.required=field.required!==false;
      input.pattern='[A-Za-z0-9._\\-]{1,64}';input.maxLength=64;input.placeholder=field.name==='host'?'Например, OFFICE-PC-01':'';label.append(input);form.append(label);
    });
    const confirm=document.createElement('label');confirm.className='rb-confirm';const check=document.createElement('input');check.type='checkbox';check.required=true;
    confirm.append(check,document.createTextNode('Подтверждаю выполнение на указанной цели. Пользователь предупреждён о возможном прерывании работы.'));form.append(confirm);
    const submit=document.createElement('button');submit.type='submit';submit.className='btn danger';submit.textContent='Выполнить сценарий';
    const cancel=document.createElement('button');cancel.type='button';cancel.className='btn ghost';cancel.textContent='Отмена';cancel.onclick=()=>form.hidden=true;form.append(submit,cancel);
    form.onsubmit=event=>{event.preventDefault();if(!form.reportValidity())return;const params={};fields.forEach(field=>params[field.name]=form.elements.namedItem(field.name).value.trim());this.execute(rb,params);};
    form.hidden=false;form.querySelector('input')?.focus();
  },
  async execute(rb,params) {
    if(this.busy)return;this.busy=true;$('rb-form').hidden=true;
    const out=$('rb-output');out.classList.remove('hidden');out.setAttribute('aria-busy','true');
    document.querySelectorAll('[data-runbook]').forEach(b=>b.disabled=true);
    try {
      const started=await apiPost('runbookexec',{name:rb.id,params});
      for(let n=0;n<150;n++){
        out.textContent='Выполняется: '+rb.name+' · цель: '+(params.host||'этот сервер')+' · задача '+started.job;
        await new Promise(resolve=>setTimeout(resolve,1000));
        const job=await apiGet('securityresult?job='+encodeURIComponent(started.job));
        if(job.status==='error')throw new Error(job.error||'Ошибка выполнения');
        if(job.status==='done'){
          const result=job.result;
          out.innerHTML=`<div class="rb-result-title">${result.ok?'Выполнено':'Не выполнено'} · ${esc(result.target||params.host||'этот сервер')} · код ${esc(result.exit_code??'—')} · ${esc(result.seconds??'—')} с</div>`;
          if(result.disks?.length)out.innerHTML+=Sysadmin.table('runbook-disks',['Диск','Точка монтирования','Свободно GB','Всего GB','Занято %'],result.disks.map(d=>[esc(d.device),esc(d.mount),esc(d.free_gb),esc(d.total_gb),esc(d.used_pct??'—')]));
          const raw=document.createElement('details');const summary=document.createElement('summary');summary.textContent='Текстовый вывод';const pre=document.createElement('pre');pre.textContent=result.output||result.error||'Вывод отсутствует';raw.append(summary,pre);raw.open=!result.disks?.length;out.append(raw);
          return;
        }
      }
      throw new Error('Задача ещё выполняется. Проверьте журнал запусков перед повтором.');
    }catch(error){out.textContent=error.message;}
    finally{this.busy=false;out.setAttribute('aria-busy','false');try{this.render(await apiGet('runbooks'));}catch(_){} }
  },
};
