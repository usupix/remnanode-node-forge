'use strict';
const $ = (id) => document.getElementById(id);
const labels = {up:'Работает', degraded:'Частичный сбой', down:'Недоступен', unknown:'Нет свежих данных'};
const fullDate = new Intl.DateTimeFormat('ru-RU',{timeZone:'Europe/Moscow',day:'numeric',month:'long',year:'numeric'});
const dateTime = new Intl.DateTimeFormat('ru-RU',{timeZone:'Europe/Moscow',day:'numeric',month:'short',hour:'2-digit',minute:'2-digit'});
let days = 90, loading = false, lastData = null;
function element(tag, cls, text) { const e = document.createElement(tag); if(cls)e.className=cls; if(text!==undefined)e.textContent=text; return e; }
function percentage(value) { return value===null?'—':value.toLocaleString('ru-RU',{minimumFractionDigits:2,maximumFractionDigits:2})+'%'; }
function duration(seconds) { if(seconds<60)return 'меньше минуты'; if(seconds<3600)return Math.round(seconds/60)+' мин'; if(seconds<86400)return (seconds/3600).toLocaleString('ru-RU',{maximumFractionDigits:1})+' ч'; return (seconds/86400).toLocaleString('ru-RU',{maximumFractionDigits:1})+' дн'; }
function dayClass(day) { return day.uptime===null?'unknown':day.outage_seconds>0?'down':day.degraded_seconds>0?'degraded':'up'; }
function dayText(day) { const date=fullDate.format(new Date(day.date+'T12:00:00+03:00')); if(day.uptime===null)return date+'\nНет данных за этот день'; let text=date+'\nДоступность: '+percentage(day.uptime)+'\nНаблюдение: '+duration(day.measured_seconds); if(day.outage_seconds)text+='\nНедоступен: '+duration(day.outage_seconds); if(day.degraded_seconds)text+='\nЧастичный сбой: '+duration(day.degraded_seconds); return text; }
function showTooltip(button, text) { const t=$('tooltip');t.textContent=text;t.hidden=false; const box=button.getBoundingClientRect(); const width=t.offsetWidth; t.style.left=Math.max(10,Math.min(window.innerWidth-width-10,box.left-width/2+box.width/2))+'px';t.style.top=Math.max(10,box.top-t.offsetHeight-10)+'px'; }
function renderNode(node) {
  const row=element('article','server');
  const top=element('div','server-top');top.append(element('span','country',node.country||'—'),element('span','server-name',node.name));
  const state=element('span','server-state');state.append(element('i',node.state),document.createTextNode(labels[node.state]));top.append(state,element('span','percent',percentage(node.uptime)));row.append(top);
  const history=element('div','history');history.setAttribute('role','group');history.setAttribute('aria-label','История: '+node.name);let selected=node.history.length-1;
  node.history.forEach((day,index)=>{ const b=element('button','day '+dayClass(day));b.type='button';b.tabIndex=index===selected?0:-1;b.setAttribute('aria-label',dayText(day).replaceAll('\n','. '));
    const display=()=>showTooltip(b,dayText(day));b.addEventListener('mouseenter',display);b.addEventListener('mouseleave',()=>$('tooltip').hidden=true);b.addEventListener('focus',display);b.addEventListener('blur',()=>$('tooltip').hidden=true);b.addEventListener('click',()=>{b.focus();display();});
    b.addEventListener('keydown',(event)=>{if(!['ArrowLeft','ArrowRight','Home','End'].includes(event.key))return;event.preventDefault();history.children[selected].tabIndex=-1;selected=event.key==='Home'?0:event.key==='End'?node.history.length-1:Math.max(0,Math.min(node.history.length-1,selected+(event.key==='ArrowLeft'?-1:1)));history.children[selected].tabIndex=0;history.children[selected].focus();});history.append(b); });row.append(history);
  const dates=element('div','history-dates');dates.append(element('span','',days+' дней'),element('span','','сегодня'));row.append(dates);
  const start=dateTime.format(new Date(node.since*1000));const detail=element('div','server-detail','Наблюдаем с '+start+(node.latency_ms!==null?' · отклик '+Math.round(node.latency_ms)+' мс':''));row.append(detail);return row;
}
function render(data) {
  lastData=data;$('overall-dot').className='status-orbit '+data.state;
  $('headline').textContent={up:'Сервисы работают',degraded:'Есть перебои в работе',down:'Серверы недоступны',unknown:'Проверяем состояние сети'}[data.state];
  const up=data.nodes.filter(n=>n.state==='up').length;
  $('summary').textContent=data.nodes.length?up+' из '+data.nodes.length+' серверов работают штатно. Проверка каждую минуту.':'Серверы появятся после подключения нод к панели.';
  $('node-count').textContent=String(data.nodes.length);
  $('servers').replaceChildren(...(data.nodes.length?data.nodes.map(renderNode):[element('p','loading','Ноды ещё не зарегистрированы.')]));
  const incidents=data.incidents.map(i=>{const row=element('article','incident');row.append(element('div','incident-time',dateTime.format(new Date(i.start*1000))));const body=element('div');const title=element('h3','',i.name);const tag=element('span','incident-tag'+(i.end?'':' open'),i.end?'Устранён':'Продолжается');const p=element('p');p.append(tag,document.createTextNode((i.kind==='down'?'Недоступность':'Частичный сбой')+' · '+duration((i.end||data.generated_at)-i.start)+(i.end?' · восстановлено '+dateTime.format(new Date(i.end*1000)):'')));body.append(title,p);row.append(body);return row;});
  $('incidents').replaceChildren(...(incidents.length?incidents:[element('p','empty','За время наблюдения сбоев не зафиксировано.')]));
  $('updated').textContent=data.updated_at?'Последняя проверка '+dateTime.format(new Date(data.updated_at*1000))+' МСК':'Ожидаем первую проверку';
}
async function refresh() { if(loading)return;loading=true;try{ const response=await fetch('/api/status?days='+days,{cache:'no-store',signal:AbortSignal.timeout(12000)});if(!response.ok)throw new Error('unavailable');const data=await response.json();$('fetch-error').hidden=true;render(data);}catch(error){$('fetch-error').hidden=false;if(!lastData){$('headline').textContent='Данные временно недоступны';$('summary').textContent='Повторим проверку автоматически.';$('servers').replaceChildren(element('p','loading','Не удалось получить состояние серверов.'));}else{$('overall-dot').className='status-orbit unknown';$('headline').textContent='Обновление задерживается';}}finally{loading=false;} }
document.querySelectorAll('[data-days]').forEach(button=>button.addEventListener('click',()=>{if(loading)return;days=Number(button.dataset.days);document.querySelectorAll('[data-days]').forEach(b=>b.setAttribute('aria-pressed',String(b===button)));$('tooltip').hidden=true;refresh();}));
window.addEventListener('scroll',()=>$('tooltip').hidden=true,{passive:true});document.addEventListener('visibilitychange',()=>{if(!document.hidden)refresh();});
setInterval(()=>{if(!document.hidden)refresh();},30000);refresh();
