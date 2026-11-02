'use strict';
window.Topology = {
  data:null, zoom:1,
  label(n) {return n.alias||n.hostname&&n.hostname!=='-'&&n.hostname||n.name||n.ip||'Без имени';},
  color(n) {return n.online===false?'#fb7185':n.online===true?'#34d399':'#94a3b8';},
  status(n) {return n.online===false?'Нет связи':n.online===true?'В сети':'Не проверено';},
  render(data) {
    this.data=data||{nodes:[]};
    const box=$('infra-map'), query=$('topology-search').value.trim().toLocaleLowerCase('ru'), mode=$('topology-filter').value;
    const all=this.data.nodes||[];
    const nodes=all.filter(n=>(this.label(n)+' '+(n.ip||'')+' '+(n.vendor||'')).toLocaleLowerCase('ru').includes(query) && (mode==='all'||mode==='online'&&n.online===true||mode==='offline'&&n.online===false||mode==='unknown'&&n.online==null));
    $('topology-summary').textContent=`Показано: ${nodes.length} из ${all.length} · шлюз: ${this.data.gateway||'не определён'}. Цвет показывает последнее известное состояние, а не качество канала.`;
    const W=Math.max(310,Math.round(box.clientWidth||900)), gap=14, margin=16;
    const columns=Math.max(1,Math.min(4,Math.floor((W-2*margin+gap)/250))), cardW=(W-margin*2-gap*(columns-1))/columns;
    const groups=[['Узел наблюдения и маршрут',nodes.filter(n=>n.kind==='master'||n.ip===this.data.gateway)],['Сетевое оборудование',nodes.filter(n=>n.kind!=='master'&&n.ip!==this.data.gateway&&['router','switch'].includes(n.kind))],['Серверы и сервисы',nodes.filter(n=>n.kind!=='master'&&n.ip!==this.data.gateway&&['server','infra'].includes(n.kind))],['Хосты и другие устройства',nodes.filter(n=>n.kind!=='master'&&n.ip!==this.data.gateway&&!['router','switch','server','infra'].includes(n.kind))]].filter(g=>g[1].length);
    let y=65, content='';
    const types={master:'NetPulse',router:'Маршрутизатор',switch:'Коммутатор',server:'Сервер',infra:'Инфраструктура',pc:'Компьютер',host:'Хост'};
    for(const [name,list]of groups){
      content+=`<text x="16" y="${y}" fill="#94a3b8" font-size="11" font-weight="600">${esc(name)} · ${list.length}</text>`; y+=16;
      list.forEach((node,index)=>{
        const x=margin+(index%columns)*(cardW+gap), top=y+Math.floor(index/columns)*118;
        const original=all.indexOf(node), color=this.color(node), title=String(this.label(node)), short=title.length>31?title.slice(0,29)+'…':title;
        content+=`<g role="button" tabindex="0" data-node-index="${original}" aria-label="${esc(title+' · '+this.status(node))}" class="topology-node"><title>${esc(title+'\n'+(node.ip||'Нет IP')+'\n'+this.status(node))}</title><rect x="${x}" y="${top}" width="${cardW}" height="104" rx="10" fill="#111c2d" stroke="#334155"/><rect x="${x}" y="${top+12}" width="3" height="80" rx="2" fill="${color}"/><text x="${x+15}" y="${top+22}" fill="#94a3b8" font-size="10">${esc(types[node.kind]||'Устройство')}</text><text x="${x+15}" y="${top+44}" fill="#edf2fa" font-size="13" font-weight="600">${esc(short)}</text><text x="${x+15}" y="${top+65}" fill="#94a3b8" font-size="12">${esc(node.ip||'IP не определён')}</text><circle cx="${x+19}" cy="${top+85}" r="3" fill="${color}"/><text x="${x+29}" y="${top+89}" fill="${color}" font-size="11">${this.status(node)}</text></g>`;
      });
      y+=Math.ceil(list.length/columns)*118+22;
    }
    if(!nodes.length){content+='<text x="16" y="96" fill="#94a3b8" font-size="13">Нет устройств, соответствующих фильтру.</text>';y=140;}
    const H=Math.max(y+10,180);
    box.innerHTML=`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" role="group" aria-label="Логическая карта устройств" style="font-family:system-ui,sans-serif"><rect width="100%" height="100%" fill="#0b1320" rx="10"/><text x="16" y="27" fill="#edf2fa" font-size="15" font-weight="600">Логическая карта устройств</text><text x="16" y="47" fill="#94a3b8" font-size="10">Кабельные связи не установлены · выберите устройство для подробностей</text>${content}</svg>`;
    box.querySelectorAll('[data-node-index]').forEach(group=>{
      const select=()=>this.select(all[+group.dataset.nodeIndex]);
      group.addEventListener('click',select);group.addEventListener('keydown',event=>{if(event.key==='Enter'||event.key===' '){event.preventDefault();select();}});
    });
    this.scale();
  },
  select(node) {
    const details=$('topology-detail');details.hidden=false;details.replaceChildren();
    const title=document.createElement('h3');title.textContent=this.label(node);details.append(title);
    const list=document.createElement('dl');
    const pairs=[['IP',node.ip||'Не определён'],['Тип',node.kind||'Не определён'],['Последнее состояние',this.status(node)],['Имя SNMP',node.sys_name||'Нет данных'],['Производитель',node.vendor||'Нет данных'],['ОС',node.os||'Нет данных'],['Время работы',node.uptime_h==null?'Нет данных':node.uptime_h+' ч'],['SNMP',node.snmp?'Есть сохранённые данные':'Нет сохранённых данных']];
    for(const [name,value]of pairs){const dt=document.createElement('dt'),dd=document.createElement('dd');dt.textContent=name;dd.textContent=value;list.append(dt,dd);}
    details.append(list);
    if(node.kind==='master'&&this.data.gateway){const p=document.createElement('p');p.textContent='Шлюз маршрута по умолчанию: '+this.data.gateway+'. Это логический маршрут, а не подтверждённый прямой кабель.';details.append(p);}
    const close=document.createElement('button');close.className='btn ghost';close.textContent='Закрыть подробности';close.onclick=()=>{details.hidden=true;};details.append(close);
  },
  scale(delta=0) {this.zoom=Math.max(.75,Math.min(2,this.zoom+delta));const svg=$('infra-map').querySelector('svg');if(svg){svg.style.width=svg.viewBox.baseVal.width*this.zoom+'px';svg.style.height='auto';} $('topology-scale').textContent=Math.round(this.zoom*100)+'%';},
  reset() {this.zoom=1;this.scale();},
};
window.addEventListener('resize',()=>{clearTimeout(Topology.resizeTimer);Topology.resizeTimer=setTimeout(()=>{if(Topology.data&&document.getElementById('view-infra').classList.contains('active'))Topology.render(Topology.data);},120);});
