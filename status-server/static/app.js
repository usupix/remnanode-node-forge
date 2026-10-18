'use strict';
const $ = (id) => document.getElementById(id);
const labels = {up:'Работает', degraded:'Частичный сбой', down:'Недоступен', unknown:'Нет свежих данных'};
const fullDate = new Intl.DateTimeFormat('ru-RU',{timeZone:'Europe/Moscow',day:'numeric',month:'long',year:'numeric'});
const dateTime = new Intl.DateTimeFormat('ru-RU',{timeZone:'Europe/Moscow',day:'numeric',month:'short',hour:'2-digit',minute:'2-digit'});
const clock = new Intl.DateTimeFormat('ru-RU',{timeZone:'Europe/Moscow',hour:'2-digit',minute:'2-digit'});
const allowedPeriods = new Set(['3h','6h','12h','7d','30d','90d']);
const flagCodes = new Set(['DE','EE','SE','LV','NL','FI','TR','KZ','US','RU','FR','PL','LT','UA','CH','GB']);
let period = '12h', loading = false, lastData = null;
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
function bucketClass(bucket) { return bucket.uptime === null ? 'unknown' : bucket.outage_seconds > 0 ? 'down' : bucket.degraded_seconds > 0 ? 'degraded' : 'up'; }
function bucketText(bucket, hourly) {
  const date = fullDate.format(new Date(bucket.start*1000));
  const range = hourly ? '\n'+clock.format(new Date(bucket.start*1000))+'–'+clock.format(new Date(bucket.end*1000))+' МСК' : '';
  if (bucket.uptime === null) return date+range+'\nНет данных за это время';
  let text = date+range+'\nДоступность: '+percentage(bucket.uptime);
  if (bucket.outage_seconds) text += '\nНедоступен: '+duration(bucket.outage_seconds);
  if (bucket.degraded_seconds) text += '\nЧастичный сбой: '+duration(bucket.degraded_seconds);
  return text;
}
function showTooltip(button, text) {
  const t = $('tooltip'); t.textContent = text; t.hidden = false;
  const box = button.getBoundingClientRect(), width = t.offsetWidth;
  t.style.left = Math.max(10,Math.min(window.innerWidth-width-10,box.left-width/2+box.width/2))+'px';
  t.style.top = Math.max(10,box.top-t.offsetHeight-10)+'px';
}
function renderNode(node, data) {
  const row = element('article','server'), top = element('div','server-top');
  top.append(flag(node.country),element('span','server-name',node.name));
  const state = element('span','server-state');
  state.append(element('i',node.state),document.createTextNode(labels[node.state]));
  top.append(state,element('span','percent',percentage(node.uptime))); row.append(top);
  const history = element('div','history'); history.setAttribute('role','group');
  history.setAttribute('aria-label','История: '+node.name);
  let selected = node.history.length-1;
  node.history.forEach((bucket,index) => {
    const b = element('button','day '+bucketClass(bucket)); b.type = 'button'; b.tabIndex = index === selected ? 0 : -1;
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
  row.append(history);
  const dates = element('div','history-dates');
  const ago = data.hours ? data.hours+(data.hours === 3 ? ' часа назад' : ' часов назад') : data.days+' дней назад';
  dates.append(element('span','',ago),element('span','',data.hours ? 'сейчас' : 'сегодня')); row.append(dates);
  return row;
}
function render(data) {
  lastData = data; $('overall-dot').className = 'status-orbit '+data.state;
  $('headline').textContent = {up:'Сервисы работают',degraded:'Есть перебои в работе',down:'Серверы недоступны',unknown:'Проверяем состояние сети'}[data.state];
  const up = data.nodes.filter(n => n.state === 'up').length;
  $('summary').textContent = data.nodes.length ? up+' из '+data.nodes.length+' серверов работают штатно. Проверка каждую минуту.' : 'Новые серверы появятся после подключения.';
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
  $('updated').textContent = data.updated_at ? 'Последняя проверка '+dateTime.format(new Date(data.updated_at*1000))+' МСК' : 'Ожидаем первую проверку';
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
