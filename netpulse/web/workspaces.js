/* Task-oriented workspaces. No background scans or configuration changes. */
"use strict";
window.Workspaces = {
  definitions: {
    dashboard: {group:"Обзор", icon:"dash", desc:"Трафик, качество связи и состояние этой машины в одном месте.", hint:"Начните с операционного центра, если ищете проблему на конкретном устройстве.", links:[["Инциденты","operations"],["Проверить связь","diag"]]},
    operations: {group:"Обзор", icon:"shield", desc:"Устройства, ответственные, инциденты и доставка уведомлений.", hint:"Выберите устройство или инцидент, чтобы увидеть контекст и историю действий.", refresh:["Ops.load"], links:[["Инфраструктура","infra"]]},
    journal: {group:"Работа отдела", icon:"doc", desc:"Фиксируйте выполненные работы, затраченное время и плановые задачи.", hint:"Запись описывает выполненную работу. Для технических событий используйте историю и алерты.", refresh:["loadJournal"], links:[["Состояние парка","park"]]},
    apps: {group:"Сеть", icon:"apps", desc:"Какие процессы открывают соединения и используют сеть этой машины.", hint:"I/O процесса может включать дисковые операции: это не точное измерение сетевого трафика приложения.", refresh:["loadApps","loadNewConns"], links:[["Все соединения","traffic"]]},
    traffic: {group:"Сеть", icon:"globe", desc:"Сетевые интерфейсы и текущие подключения с адресами и состояниями.", hint:"Закрытый порт или отсутствие соединения сами по себе не указывают на неисправность.", refresh:["refreshInterfaces","refreshConns"], links:[["Проверить маршрут","diag"]]},
    diag: {group:"Сеть", icon:"route", desc:"Проверяйте доступность, маршрут, DNS и пропускную способность по отдельности.", hint:"Пинг, MTR, трассировка и замер канала запускаются вручную. Замер скорости расходует трафик.", links:[["Локальная сеть","lan"],["Соединения","traffic"]]},
    lan: {group:"Сеть", icon:"lan", desc:"Обнаруженные IP и MAC, имена устройств и ваши обозначения.", hint:"Выберите физический интерфейс перед сканированием. ARP-запись может быть старой и не подтверждает доступность сейчас.", refresh:["lanDevices"], links:[["Инфраструктура","infra"]]},
    park: {group:"Работа отдела", icon:"monitor", desc:"Компьютеры, события, свободное место на дисках и установленное ПО.", hint:"Данные парка поступают от подключённых агентов. Пустой список не означает, что в сети нет компьютеров.", refresh:["loadPark"], links:[["Журнал работ","journal"],["Сисадмин","sysadmin"]]},
    infra: {group:"Сеть", icon:"server", desc:"Управляемое оборудование, RouterOS, топология и пользовательские проверки.", hint:"Опрос оборудования и сканирование выполняйте осознанно. Доступные метрики зависят от протокола и прав учётной записи.", refresh:["loadInfra","loadCustomChecks","loadRouters"], links:[["Операционный центр","operations"],["Локальная сеть","lan"]]},
    mesh: {group:"Инструменты", icon:"mesh", desc:"Узлы P2P, доступные сервисы, топология и диагностика взаимодействия.", hint:"Статус моста и статус удалённого сервиса — разные вещи. RPC-команды могут менять состояние узлов.", refresh:["loadMesh"], links:[["Парк ПК","park"]]},
    capture: {group:"Инструменты", icon:"capture", desc:"Пакеты, протоколы и адреса для разбора конкретного сетевого эпизода.", hint:"Захват запускается только кнопкой «Старт». Возможности зависят от ОС и прав процесса; не собирайте чужие данные без разрешения.", links:[["Соединения","traffic"],["Диагностика","diag"]]},
    security: {group:"Защита и события", icon:"shield", desc:"Системные проверки, события IDS, открытые порты и правила блокировки.", hint:"Срабатывание детектора — повод проверить событие, а не доказательство атаки. Блокировки могут нарушить рабочие подключения.", refresh:["loadIds","fwList"], links:[["Алерты","alerts"]]},
    ai: {group:"Инструменты", icon:"chip", desc:"Модель аномалий, накопленные наблюдения и прогноз нагрузки.", hint:"Прогноз зависит от объёма истории. Аномалия не устанавливает причину проблемы и не заменяет диагностику.", refresh:["loadAI"], links:[["История измерений","history"],["Диагностика","diag"]]},
    alerts: {group:"Защита и события", icon:"bell", desc:"Проверяйте новые уведомления и отмечайте те, которые взяли в работу.", hint:"«Принять» отмечает просмотр уведомления. Это не подтверждение восстановления устройства.", refresh:["loadAlerts"], links:[["Инциденты","operations"],["Безопасность","security"]]},
    history: {group:"Защита и события", icon:"history", desc:"Сравнивайте трафик, задержку, джиттер и потери за выбранный период.", hint:"Отсутствующие измерения не равны нулю. Для истории действий администратора откройте «Сисадмин».", refresh:["loadHistory"], links:[["Журнал работ","journal"]]},
    sysadmin: {group:"Работа отдела", icon:"terminal", desc:"SLA, ресурсы, L2-порты, Proxmox, CVE и аудит изменений.", hint:"Доступность блоков зависит от настроенных источников. CVE-совпадения требуют проверки версии и применимости.", refresh:["loadSysadmin"], links:[["Парк ПК","park"],["Настройки","settings"]]},
    settings: {group:"Управление", icon:"gear", desc:"Параметры мониторинга, права доступа, уведомления и резервные копии.", hint:"Изменения применяются кнопкой сохранения. Обновление страницы с несохранёнными полями может их потерять.", links:[["Операционный центр","operations"],["Журнал работ","journal"]]},
  },
  states: new Map(), tables: new WeakSet(),
  init(ui) {
    this.ui = ui;
    const nav = document.getElementById("nav");
    nav.setAttribute("aria-label", "Разделы NetPulse");
    const buttons = [...nav.querySelectorAll(".nav-btn")];
    for (const group of ["Обзор","Сеть","Работа отдела","Защита и события","Инструменты","Управление"]) {
      const block = document.createElement("div"); block.className = "nav-group";
      const title = document.createElement("div"); title.className = "nav-group-title"; title.textContent = group;
      block.append(title);
      for (const button of buttons.filter(b => this.definitions[b.dataset.view]?.group === group)) {
        const def = this.definitions[button.dataset.view];
        button.title = def.desc;
        button.setAttribute("aria-controls", "view-" + button.dataset.view);
        const svg = button.querySelector("svg");
        svg.setAttribute("aria-hidden", "true"); svg.setAttribute("viewBox", "0 0 24 24");
        svg.querySelector("use").setAttribute("href", "#i-" + def.icon);
        block.append(button);
      }
      nav.append(block);
    }
    const search = document.getElementById("nav-search");
    search.addEventListener("input", () => {
      const query = search.value.trim().toLocaleLowerCase("ru"); let count = 0;
      buttons.forEach(button => {
        const def = this.definitions[button.dataset.view];
        const match = (button.textContent + " " + def.desc + " " + def.group).toLocaleLowerCase("ru").includes(query);
        button.hidden = !match; if (match) count++;
      });
      nav.querySelectorAll(".nav-group").forEach(g => g.hidden = ![...g.querySelectorAll(".nav-btn")].some(b => !b.hidden));
      document.getElementById("nav-empty").hidden = count > 0;
    });
    search.addEventListener("keydown", event => {
      if (event.key === "Enter") { const first = buttons.find(b => !b.hidden); if(first) first.click(); }
      if (event.key === "Escape") { search.value = ""; search.dispatchEvent(new Event("input")); search.blur(); }
    });
    document.addEventListener("keydown", event => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault(); this.menu(true); search.focus();
      }
      if (event.key === "Escape") this.menu(false);
    });
    document.getElementById("menu-shade").addEventListener("click", () => this.menu(false));
    this.observer = new MutationObserver(() => this.enhanceTables());
    this.observer.observe(document.querySelector("main"), {childList:true, subtree:true});
    this.enhanceTables();
    this.labelControls();
    document.getElementById("alerts-search").addEventListener("input", () => this.filterAlerts());
    document.getElementById("alerts-filter").addEventListener("change", () => this.filterAlerts());
    const settings = document.getElementById("view-settings");
    const warning = document.createElement("p"); warning.className="settings-dirty"; warning.hidden=true;
    warning.textContent="Есть несохранённые изменения. Примените настройки перед закрытием или обновлением страницы.";
    settings.prepend(warning);
    settings.addEventListener("input", event => {
      if (event.target.matches("input[id^=set-],select[id^=set-],textarea[id^=set-]")) {
        this.dirtySettings=true; warning.hidden=false;
      }
    });
    window.addEventListener("beforeunload", event => {
      if (this.dirtySettings) { event.preventDefault(); event.returnValue=""; }
    });
  },
  menu(open) {
    document.getElementById("sidebar").classList.toggle("open", open);
    document.getElementById("menu-shade").hidden = !open;
    document.querySelector(".burger").setAttribute("aria-expanded", String(open));
  },
  show(view) {
    this.menu(false);
    document.querySelectorAll(".nav-btn").forEach(b => {
      if (b.dataset.view === view) b.setAttribute("aria-current", "page"); else b.removeAttribute("aria-current");
    });
    const section = document.getElementById("view-" + view), def = this.definitions[view];
    if (!section.querySelector(".workspace-head")) {
      const header = document.createElement("div"); header.className = "workspace-head";
      const copy = document.createElement("div");
      const eyebrow = document.createElement("div"); eyebrow.className = "workspace-eyebrow"; eyebrow.textContent = def.group;
      const desc = document.createElement("h2"); desc.textContent = def.desc;
      const help = document.createElement("details"); help.className = "workspace-help";
      const summary = document.createElement("summary"); summary.textContent = "Как работать с разделом";
      const text = document.createElement("p"); text.textContent = def.hint; help.append(summary,text);
      copy.append(eyebrow,desc,help);
      const actions = document.createElement("div"); actions.className = "workspace-links";
      if (def.refresh) {
        const refresh = document.createElement("button"); refresh.className = "btn accent workspace-refresh";
        refresh.textContent = "Обновить данные"; refresh.onclick = () => this.refresh(view); actions.append(refresh);
      }
      def.links.forEach(([label,target]) => {
        const link = document.createElement("a"); link.className = "btn ghost"; link.href = "#"+target; link.textContent = label; actions.append(link);
      });
      header.append(copy,actions);
      const status = document.createElement("div"); status.className = "workspace-status"; status.setAttribute("role","status");
      section.prepend(header,status);
    }
    this.renderStatus(view); this.enhanceTables();
  },
  settingsSaved() {
    this.dirtySettings=false;
    document.querySelector(".settings-dirty").hidden=true;
  },
  filterAlerts() {
    const query=document.getElementById("alerts-search").value.trim().toLocaleLowerCase("ru");
    const filter=document.getElementById("alerts-filter").value;
    const items=[...document.querySelectorAll("#alerts-feed .feed-item")]; let shown=0;
    items.forEach(item=>{
      const unread=item.classList.contains("unread");
      const matches=item.textContent.toLocaleLowerCase("ru").includes(query) && (filter==="all" || (filter==="unread" ? unread : !unread));
      item.hidden=!matches; if(matches) shown++;
    });
    document.getElementById("alerts-count").textContent=shown+" из "+items.length;
    document.getElementById("alerts-empty").hidden=!items.length || shown>0;
  },
  async refresh(view) {
    for (const method of this.definitions[view].refresh || []) {
      if (method === "Ops.load") await Ops.load(); else await this.ui[method]();
    }
  },
  begin(path) {
    if (!this.ui) return null;
    const view = this.ui.currentView;
    // Global telemetry must not label the currently opened settings form as refreshed.
    if (["state","whoami","dashplatform"].includes(path.split("?")[0])) return null;
    const state = this.states.get(view) || {pending:0, failed:[],at:0};
    if (!state.pending) state.failed = [];
    state.pending++; this.states.set(view,state); this.renderStatus(view);
    return {view};
  },
  finish(ticket,error) {
    if (!ticket) return;
    const state = this.states.get(ticket.view); state.pending = Math.max(0,state.pending-1);
    if (error) state.failed.push(error.message || "Ошибка запроса"); else state.at = Date.now();
    this.renderStatus(ticket.view);
  },
  renderStatus(view) {
    const section = document.getElementById("view-"+view), box = section?.querySelector(".workspace-status");
    if (!box) return;
    const state = this.states.get(view);
    section.setAttribute("aria-busy", String(!!state?.pending));
    const refresh = section.querySelector(".workspace-refresh"); if(refresh) refresh.disabled = !!state?.pending;
    box.dataset.state = state?.pending ? "loading" : state?.failed.length ? "error" : state?.at ? "ready" : "idle";
    box.textContent = state?.pending ? "Получаем данные…" : state?.failed.length
      ? "Часть данных недоступна. " + [...new Set(state.failed)].slice(0,3).join(" · ") + ". Ранее загруженные данные могут быть устаревшими."
      : state?.at ? "Ответ сервера получен в " + new Date(state.at).toLocaleTimeString("ru-RU") + ". Время измерений указано в самих данных."
      : "Выберите действие в разделе. Активные проверки автоматически не запускаются.";
  },
  labelControls() {
    document.querySelectorAll("button").forEach(button => {
      if (!button.textContent.trim() && !button.getAttribute("aria-label")) {
        button.setAttribute("aria-label", button.title || "Обновить данные");
      }
    });
    document.querySelectorAll("input[id],select[id],textarea[id]").forEach(input => {
      if (input.labels?.length || input.hasAttribute("aria-label")) return;
      input.setAttribute("aria-label", input.placeholder || input.title || input.id.replace(/[-_]/g," "));
    });
  },
  enhanceTables() {
    document.querySelectorAll(".view table.tbl").forEach(table => {
      if (this.tables.has(table) || !table.tHead || !table.tBodies.length) return;
      this.tables.add(table); this.tableTools(table);
    });
  },
  tableTools(table) {
    const title = table.closest(".card")?.querySelector(".card-title")?.childNodes[0]?.textContent?.trim() || "Таблица";
    const toolbar = document.createElement("div"); toolbar.className = "table-tools";
    const search = document.createElement("input"); search.type="search"; search.className="inp";
    search.placeholder = "Поиск по таблице…"; search.setAttribute("aria-label", "Поиск: "+title);
    const count = document.createElement("span"); count.className="table-count"; count.setAttribute("role","status");
    const clear = document.createElement("button"); clear.className="btn ghost"; clear.textContent="Сбросить";
    const download = document.createElement("button"); download.className="btn ghost"; download.textContent="CSV"; download.setAttribute("aria-label","Экспорт CSV: "+title);
    toolbar.append(search,count,clear,download);
    const viewport = document.createElement("div"); viewport.className="table-viewport";
    viewport.tabIndex=0; viewport.setAttribute("role","region"); viewport.setAttribute("aria-label",title);
    table.before(toolbar,viewport); viewport.append(table);
    const empty = document.createElement("p"); empty.className="table-no-match"; empty.textContent="Совпадений нет. Измените запрос или сбросьте поиск."; empty.hidden=true; viewport.after(empty);
    let column=-1, direction=1;
    const body = table.tBodies[0];
    const rows = () => [...body.rows].filter(row=>row.cells.length===table.tHead.rows[0].cells.length && ![...row.cells].some(cell=>cell.colSpan>1));
    const cellText = cell => [...cell?.querySelectorAll("input,select,textarea") || []].map(el=>el.type === "password" ? "" : el.value).join(" ") || cell?.textContent.trim() || "";
    const observer = new MutationObserver(()=>apply());
    const observe = () => observer.observe(body,{childList:true,subtree:true,characterData:true});
    const apply = () => {
      observer.disconnect();
      const all = rows(), query=search.value.trim().toLocaleLowerCase("ru"); let shown=0;
      if (column>=0) all.sort((a,b)=>direction*cellText(a.cells[column]).localeCompare(cellText(b.cells[column]),"ru",{numeric:true,sensitivity:"base"})).forEach(row=>body.append(row));
      all.forEach(row=>{const match=[...row.cells].map(cellText).join(" ").toLocaleLowerCase("ru").includes(query); row.hidden=!match; if(match) shown++;});
      count.textContent = all.length ? shown+" из "+all.length : "Нет записей";
      empty.textContent = all.length ? "Совпадений нет. Измените запрос или сбросьте поиск." : "Записей пока нет. Обновите данные или настройте источник для этого раздела.";
      empty.hidden = all.length ? shown>0 : body.rows.length>0;
      download.disabled = !shown;
      observe();
    };
    [...table.tHead.rows[0].cells].forEach((th,index)=>{
      if (!th.textContent.trim()) return;
      const button = document.createElement("button"); button.className="table-sort"; button.textContent=th.textContent;
      button.title="Сортировать: "+th.textContent;
      button.onclick=()=>{
        direction=column===index ? -direction : 1; column=index;
        [...table.tHead.rows[0].cells].forEach(cell=>cell.removeAttribute("aria-sort"));
        th.setAttribute("aria-sort",direction===1?"ascending":"descending"); apply();
      };
      th.textContent=""; th.append(button);
    });
    search.oninput=apply; clear.onclick=()=>{search.value=""; column=-1; [...table.tHead.rows[0].cells].forEach(cell=>cell.removeAttribute("aria-sort")); apply(); search.focus();};
    download.onclick=()=>{
      const quote=value=>'"'+String(value).replace(/^[\s]*[=+@-]/,"'$&").replace(/"/g,'""')+'"';
      const lines=[[...table.tHead.rows[0].cells].map(c=>c.textContent),...rows().filter(row=>!row.hidden).map(row=>[...row.cells].map(cellText))];
      const blob=new Blob(["\uFEFF"+lines.map(line=>line.map(quote).join(";")).join("\r\n")],{type:"text/csv;charset=utf-8"});
      const url=URL.createObjectURL(blob), link=document.createElement("a"); link.href=url; link.download="netpulse-"+(table.id || "table")+".csv"; link.click(); setTimeout(()=>URL.revokeObjectURL(url),1000);
    };
    apply();
  },
};
