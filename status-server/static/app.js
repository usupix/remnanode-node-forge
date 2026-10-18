'use strict';
const $ = (id) => document.getElementById(id);
const labels = {up:'Работает', degraded:'Частичный сбой', down:'Недоступен', unknown:'Нет свежих данных', maintenance:'Плановые работы'};
const fullDate = new Intl.DateTimeFormat('ru-RU',{timeZone:'Europe/Moscow',day:'numeric',month:'long',year:'numeric'});
const dateTime = new Intl.DateTimeFormat('ru-RU',{timeZone:'Europe/Moscow',day:'numeric',month:'short',hour:'2-digit',minute:'2-digit'});
const clock = new Intl.DateTimeFormat('ru-RU',{timeZone:'Europe/Moscow',hour:'2-digit',minute:'2-digit'});
const allowedPeriods = new Set(['3h','6h','12h','7d','30d','90d']);
const flagCodes = new Set(['DE','EE','SE','LV','NL','FI','TR','KZ','US','RU','FR','PL','LT','UA','CH','GB']);
let period = '12h', loading = false, lastData = null, selectedNode = null;
try { const saved = localStorage.getItem('meltun-status-period'); if (allowedPeriods.has(saved)) period = saved; } catch (_) {}

function element(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}
function flag(code) {
  const svg = document.createElementNS('http://www.w3.org/2000/svg','svg');
  svg.setAttribute('class','country'); svg.setAttribute('viewBox','0 0 30 20'); svg.setAttribute('aria-hidden','true');
  const use = document.createElementNS('http://www.w3.org/2000/svg','use');
  use.setAttribute('href','/flags.svg#'+(flagCodes.has(code) ? code : 'ZZ'));
  svg.append(use); return svg;
}
function percentage(value) { return value === null ? '—' : value.toLocaleString('ru-RU',{minimumFractionDigits:2,maximumFractionDigits:2})+'%'; }
function duration(seconds) {
  if (seconds < 60) return 'меньше минуты';
  if (seconds < 3600) return Math.round(seconds/60)+' мин';
  if (seconds < 86400) return (seconds/3600).toLocaleString('ru-RU',{maximumFractionDigits:1})+' ч';
  return (seconds/86400).toLocaleString('ru-RU',{maximumFractionDigits:1})+' дн';
}
function bucketFill(parts) {
  const svg = document.createElementNS('http://www.w3.org/2000/svg','svg');
  svg.setAttribute('class','bucket-parts'); svg.setAttribute('viewBox','0 0 100 26');
  svg.setAttribute('preserveAspectRatio','none'); svg.setAttribute('aria-hidden','true');
  let x = 0;
  for (const part of parts) {
    const rect = document.createElementNS('http://www.w3.org/2000/svg','rect');
    rect.setAttribute('class','bucket-part '+part.state); rect.setAttribute('x',String(x)); rect.setAttribute('y','0');
    rect.setAttribute('width',String(part.share*100)); rect.setAttribute('height','26'); svg.append(rect); x += part.share*100;
  }
  return svg;
}
function bucketText(bucket, hourly) {
  const date = fullDate.format(new Date(bucket.start*1000));
  const range = hourly ? '\n'+clock.format(new Date(bucket.start*1000))+'–'+clock.format(new Date(bucket.end*1000))+' МСК' : '';
  let text = date+range+(bucket.uptime === null ? '\nНет данных за это время' : '\nДоступность: '+percentage(bucket.uptime));
  if (bucket.outage_seconds) text += '\nНедоступен: '+duration(bucket.outage_seconds);
  if (bucket.degraded_seconds) text += '\nЧастичный сбой: '+duration(bucket.degraded_seconds);
  if (bucket.maintenance_seconds) text += '\nПлановые работы: '+duration(bucket.maintenance_seconds);
  return text;
}
function showTooltip(button, text) {
  const t = $('tooltip'); t.textContent = text; t.hidden = false;
  const box = button.getBoundingClientRect(), width = t.offsetWidth;
  t.style.left = Math.max(10,Math.min(window.innerWidth-width-10,box.left-width/2+box.width/2))+'px';
  t.style.top = Math.max(10,box.top-t.offsetHeight-10)+'px';
}
function historyBlock(node, data) {
  const wrapper = element('div','history-block');
  const history = element('div','history'); history.setAttribute('role','group');
  history.setAttribute('aria-label','История: '+node.name);
  let selected = node.history.length-1;
  node.history.forEach((bucket,index) => {
    const parts = historyParts(bucket);
    const b = element('button','day '+(parts.length === 1 ? parts[0].state : 'mixed')+(bucket.maintenance_seconds ? ' planned' : '')); b.type = 'button'; b.tabIndex = index === selected ? 0 : -1;
    if (parts.length > 1) b.append(bucketFill(parts));
    const text = bucketText(bucket,Boolean(data.hours)); b.setAttribute('aria-label',text.replaceAll('\n','. '));
    const display = () => showTooltip(b,text);
    b.addEventListener('mouseenter',display); b.addEventListener('mouseleave',() => $('tooltip').hidden = true);
    b.addEventListener('focus',display); b.addEventListener('blur',() => $('tooltip').hidden = true);
    b.addEventListener('click',() => { b.focus(); display(); });
    b.addEventListener('keydown',(event) => {
      if (!['ArrowLeft','ArrowRight','Home','End'].includes(event.key)) return;
      event.preventDefault(); history.children[selected].tabIndex = -1;
      selected = event.key === 'Home' ? 0 : event.key === 'End' ? node.history.length-1 : Math.max(0,Math.min(node.history.length-1,selected+(event.key === 'ArrowLeft' ? -1 : 1)));
      history.children[selected].tabIndex = 0; history.children[selected].focus();
    });
    history.append(b);
  });
  wrapper.append(history);
  const dates = element('div','history-dates');
  const ago = data.hours ? data.hours+(data.hours === 3 ? ' часа назад' : ' часов назад') : data.days+' дней назад';
  dates.append(element('span','',ago),element('span','',data.hours ? 'сейчас' : 'сегодня')); wrapper.append(dates);
  return wrapper;
}
function renderNode(node, data) {
  const row = element('article','server'), top = element('div','server-top');
  const name = element('button','server-name server-link',node.name);
  name.type = 'button'; name.dataset.node = node.id; name.setAttribute('aria-haspopup','dialog');
  name.setAttribute('aria-label','Подробности: '+node.name); name.addEventListener('click',() => openDetails(node.id));
  top.append(flag(node.country),name);
  const state = element('span','server-state');
  state.append(element('i',node.state),document.createTextNode(labels[node.state]));
  top.append(state,element('span','percent',percentage(node.uptime))); row.append(top,historyBlock(node,data));
  return row;
}
const workLabels = {scheduled:'Запланированы',active:'Идут работы',completed:'Завершены',cancelled:'Отменены'};
function workCard(work) {
  const card = element('article','work-card '+work.status), head = element('div','work-head');
  head.append(element('h3','',work.title),element('span','work-tag '+work.status,workLabels[work.status]));
  card.append(head,element('p','work-scope',work.all_servers ? 'Все серверы' : work.names.join(', ')),
    element('p','work-time',dateTime.format(new Date(work.starts_at*1000))+' — '+dateTime.format(new Date(work.ends_at*1000))+' МСК'));
  if (work.description) card.append(element('p','work-description',work.description));
  return card;
}
function longDuration(seconds) {
  const minutes = Math.max(0,Math.floor(seconds/60)), hours = Math.floor(minutes/60), days = Math.floor(hours/24);
  return days ? days+' дн '+hours%24+' ч' : hours ? hours+' ч '+minutes%60+' мин' : minutes ? minutes+' мин' : 'Меньше минуты';
}
function renderDetails(id) {
  if (!lastData) return;
  const node = lastData.nodes.find(n => n.id === id);
  if (!node) { $('server-dialog').close(); return; }
  $('server-dialog-title').replaceChildren(flag(node.country),document.createTextNode(node.name));
  const body = $('server-dialog-body'), state = element('p','detail-current');
  state.append(element('i','detail-dot '+node.state),document.createTextNode(labels[node.state]));
  const periodText = lastData.hours ? lastData.hours+' ч' : lastData.days+' дней';
  const metrics = element('div','detail-metrics');
  const values = [['Доступность · '+periodText,percentage(node.uptime)],['Без сбоев сейчас',node.stable_since === null ? '—' : longDuration(lastData.generated_at-node.stable_since)],
    ['Сбоев · '+periodText,String(node.incident_count)],['Недоступность · '+periodText,node.outage_seconds ? longDuration(node.outage_seconds) : node.measured_seconds ? 'Не было' : 'Нет данных']];
  for (const [label,value] of values) { const metric = element('div','detail-metric'); metric.append(element('span','',label),element('strong','',value)); metrics.append(metric); }
  body.replaceChildren(state,metrics,historyBlock(node,lastData));
  const last = element('section','detail-section'); last.append(element('h3','','Последний сбой'));
  if (node.last_incident) {
    const incident = node.last_incident;
    last.append(element('p','',dateTime.format(new Date(incident.start*1000))+' МСК · '+longDuration((incident.end || lastData.generated_at)-incident.start)),
      element('p','muted',incident.end ? 'Работа восстановлена '+dateTime.format(new Date(incident.end*1000))+' МСК' : 'Сбой продолжается'));
  } else last.append(element('p','muted','За время наблюдения сбоев не зафиксировано.'));
  body.append(last);
  if (node.incidents.length) {
    const section = element('section','detail-section'); section.append(element('h3','','Сбои за выбранный период'));
    for (const incident of node.incidents) {
      const item = element('div','detail-incident'); item.append(element('span','',dateTime.format(new Date(incident.start*1000))),element('span','',longDuration((incident.end || lastData.generated_at)-incident.start)+(incident.end ? '' : ' · продолжается'))); section.append(item);
    }
    body.append(section);
  }
  const works = lastData.maintenance.filter(work => node.maintenance.includes(work.id));
  if (works.length) { const section = element('section','detail-section'); section.append(element('h3','','Плановые работы'),...works.map(workCard)); body.append(section); }
  body.append(element('p','detail-since','Наблюдаем с '+fullDate.format(new Date(node.since*1000))));
}
function openDetails(id) {
  selectedNode = id; $('tooltip').hidden = true; renderDetails(id); $('server-dialog').append($('tooltip')); $('server-dialog').showModal();
}
function render(data) {
  lastData = data; $('overall-dot').className = 'status-orbit '+data.state;
  $('headline').textContent = {up:'Сервисы работают',degraded:'Есть перебои в работе',down:'Серверы недоступны',unknown:'Проверяем состояние сети',maintenance:'Плановые работы'}[data.state];
  const up = data.nodes.filter(n => n.state === 'up').length;
  const planned = data.nodes.filter(n => n.state === 'maintenance').length;
  $('summary').textContent = data.nodes.length ? up+' из '+data.nodes.length+' серверов работают штатно.'+(planned ? ' Плановые работы: '+planned+'.' : ' Проверка каждую минуту.') : 'Новые серверы появятся после подключения.';
  $('node-count').textContent = String(data.nodes.length);
  $('servers').replaceChildren(...(data.nodes.length ? data.nodes.map(n => renderNode(n,data)) : [element('p','loading','Серверы ещё не добавлены.')]));
  const incidents = data.incidents.map(i => {
    const row = element('article','incident'); row.append(element('div','incident-time',dateTime.format(new Date(i.start*1000))));
    const body = element('div'), title = element('h3','',i.name);
    const tag = element('span','incident-tag'+(i.end ? '' : ' open'),i.end ? 'Устранён' : 'Продолжается');
    const p = element('p'); p.append(tag,document.createTextNode((i.kind === 'down' ? 'Недоступность' : 'Частичный сбой')+' · '+duration((i.end || data.generated_at)-i.start)+(i.end ? ' · восстановлено '+dateTime.format(new Date(i.end*1000)) : '')));
    body.append(title,p); row.append(body); return row;
  });
  $('incidents').replaceChildren(...(incidents.length ? incidents : [element('p','empty','За время наблюдения сбоев не зафиксировано.')]));
  $('maintenance-list').replaceChildren(...(data.maintenance.length ? data.maintenance.map(workCard) : [element('p','empty','Плановых работ пока нет.')]));
  $('updated').textContent = data.updated_at ? 'Последняя проверка '+dateTime.format(new Date(data.updated_at*1000))+' МСК' : 'Ожидаем первую проверку';
  if (selectedNode && $('server-dialog').open) renderDetails(selectedNode);
}
async function refresh() {
  if (loading) return; loading = true;
  try {
    const query = period.endsWith('h') ? 'hours=' : 'days=';
    const response = await fetch('/api/status?'+query+parseInt(period,10),{cache:'no-store',signal:AbortSignal.timeout(12000)});
    if (!response.ok) throw new Error('unavailable');
    const data = await response.json(); $('fetch-error').hidden = true; render(data);
  } catch (_) {
    $('fetch-error').hidden = false; $('overall-dot').className = 'status-orbit unknown';
    $('headline').textContent = lastData ? 'Обновление задерживается' : 'Данные временно недоступны';
    if (!lastData) {
      $('summary').textContent = 'Повторим проверку автоматически.';
      $('servers').replaceChildren(element('p','loading','Не удалось получить состояние серверов.'));
    } else document.querySelectorAll('.server-state').forEach(state => state.replaceChildren(element('i','unknown'),document.createTextNode(labels.unknown)));
  } finally { loading = false; }
}
document.querySelectorAll('[data-period]').forEach(button => {
  button.setAttribute('aria-pressed',String(button.dataset.period === period));
  button.addEventListener('click',() => {
    if (loading) return; period = button.dataset.period;
    try { localStorage.setItem('meltun-status-period',period); } catch (_) {}
    document.querySelectorAll('[data-period]').forEach(b => b.setAttribute('aria-pressed',String(b === button)));
    $('tooltip').hidden = true; refresh();
  });
});
window.addEventListener('scroll',() => $('tooltip').hidden = true,{passive:true});
document.addEventListener('visibilitychange',() => { if (!document.hidden) refresh(); });
setInterval(() => { if (!document.hidden) refresh(); },30000); refresh();
$('server-dialog-close').addEventListener('click',() => $('server-dialog').close());
$('server-dialog').addEventListener('close',() => {
  const button = document.querySelector('button[data-node="'+CSS.escape(selectedNode || '')+'"]'); selectedNode = null; $('tooltip').hidden = true; document.body.append($('tooltip')); if (button) button.focus();
});
$('server-dialog').addEventListener('click',event => {
  if (event.target !== $('server-dialog')) return;
  const r = event.target.getBoundingClientRect(); if (event.clientX < r.left || event.clientX > r.right || event.clientY < r.top || event.clientY > r.bottom) event.target.close();
});
