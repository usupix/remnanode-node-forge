'use strict';
const $ = id => document.getElementById(id);
const labels = {scheduled:'Запланированы',active:'Идут работы',completed:'Завершены',cancelled:'Отменены'};
const dates = new Intl.DateTimeFormat('ru-RU',{timeZone:'Europe/Moscow',day:'numeric',month:'short',hour:'2-digit',minute:'2-digit'});
let state = null, editing = null, pending = null;
function el(tag,cls,text) { const node=document.createElement(tag); if(cls)node.className=cls; if(text!==undefined)node.textContent=text; return node; }
function message(text,error=false) { $('admin-error').hidden=true; $('admin-notice').hidden=true; const node=$(error?'admin-error':'admin-notice'); node.textContent=text; node.hidden=false; }
function loginView() { $('login-panel').hidden=false; $('admin-panel').hidden=true; $('logout-button').hidden=true; state=null; }
async function post(path,value,login=false) {
  const headers={'Content-Type':'application/json'}; if(!login)headers['X-CSRF-Token']=state.csrf;
  const response=await fetch('/api/admin/'+path,{method:'POST',headers,body:JSON.stringify(value),credentials:'same-origin'});
  const data=await response.json(); if(response.status===401&&!login)loginView(); if(!response.ok)throw new Error(data.error||'Не удалось сохранить изменения.'); return data;
}
function inputTime(timestamp) { const d=new Date((timestamp+3*3600)*1000); return d.toISOString().slice(0,16); }
function updateScope() { document.querySelectorAll('[name="work-node"]').forEach(input=>input.disabled=$('all-servers').checked); }
function resetEditor() {
  editing=null; $('maintenance-form').reset(); const start=Math.ceil((Date.now()/1000+3600)/1800)*1800;
  $('work-start').value=inputTime(start); $('work-end').value=inputTime(start+3600);
  $('editor-title').textContent='Новые работы'; $('save-work').textContent='Опубликовать'; $('reset-editor').hidden=true; updateScope();
}
function edit(work) {
  editing=work; $('work-title').value=work.title; $('work-description').value=work.description;
  $('work-start').value=inputTime(work.starts_at); $('work-end').value=inputTime(work.ends_at);
  $('all-servers').checked=work.node_ids.length===0;
  document.querySelectorAll('[name="work-node"]').forEach(input=>input.checked=work.node_ids.includes(input.value)); updateScope();
  $('editor-title').textContent='Редактирование работ'; $('save-work').textContent='Сохранить изменения'; $('reset-editor').hidden=false; $('work-title').focus();
}
function confirmWork(work,action) {
  pending={work,action}; $('confirm-title').textContent=action==='finish'?'Завершить работы сейчас?':'Отменить запланированные работы?';
  $('confirm-text').textContent=work.title+(action==='finish'?' — на сайте они будут отмечены как завершённые.':' — объявление будет убрано с публичной страницы, запись сохранится в истории управления.');
  $('confirm-dialog').showModal();
}
function render() {
  const choices=state.nodes.map(node=>{const label=el('label','check-label');const input=el('input');input.type='checkbox';input.name='work-node';input.value=node.id;label.append(input,document.createTextNode(node.name));return label;}); $('admin-nodes').replaceChildren(...choices);
  const order={active:0,scheduled:1,completed:2,cancelled:3};
  const records=[...state.maintenance].sort((a,b)=>order[a.status]-order[b.status]||(a.status==='scheduled'?a.starts_at-b.starts_at:b.starts_at-a.starts_at));
  const cards=records.map(work=>{
    const card=el('article','work-card '+work.status), head=el('div','work-head');head.append(el('h3','',work.title),el('span','work-tag '+work.status,labels[work.status]));
    const names=state.nodes.filter(n=>work.node_ids.includes(n.id)).map(n=>n.name).join(', ');
    card.append(head,el('p','work-scope',work.node_ids.length?names||'Сервер больше не наблюдается':'Все серверы'),el('p','work-time',dates.format(new Date(work.starts_at*1000))+' — '+dates.format(new Date(work.ends_at*1000))+' МСК'));
    if(work.description)card.append(el('p','work-description',work.description));
    if(work.status!=='cancelled'){
      const actions=el('div','admin-actions'),button=el('button','quiet-button','Редактировать');button.type='button';button.addEventListener('click',()=>edit(work));actions.append(button);
      if(work.status==='scheduled'||work.status==='active'){const cancel=el('button','quiet-button',work.status==='active'?'Завершить сейчас':'Отменить работы');cancel.type='button';cancel.addEventListener('click',()=>confirmWork(work,work.status==='active'?'finish':'cancel'));actions.append(cancel);}card.append(actions);
    } return card;
  }); $('admin-records').replaceChildren(...(cards.length?cards:[el('p','empty','Пока нет запланированных работ.')])); updateScope();
}
async function loadState() {
  const response=await fetch('/api/admin/state',{cache:'no-store',credentials:'same-origin'});
  if(response.status===401){loginView();return false;} if(!response.ok)throw new Error('Не удалось загрузить расписание.');
  state=await response.json();$('login-panel').hidden=true;$('admin-panel').hidden=false;$('logout-button').hidden=false;render();return true;
}
$('login-form').addEventListener('submit',async event=>{
  event.preventDefault();const button=event.submitter;button.disabled=true;
  try{await post('login',{password:$('admin-password').value},true);$('admin-password').value='';if(await loadState())resetEditor();$('admin-error').hidden=true;}
  catch(error){message(error.message,true);}finally{button.disabled=false;}
});
$('maintenance-form').addEventListener('submit',async event=>{
  event.preventDefault();const button=$('save-work');button.disabled=true;
  try{
    const nodeIds=$('all-servers').checked?[]:Array.from(document.querySelectorAll('[name="work-node"]:checked')).map(input=>input.value);
    if(!$('all-servers').checked&&!nodeIds.length)throw new Error('Выбери хотя бы один сервер.');
    const value={title:$('work-title').value,description:$('work-description').value,starts_at:Date.parse($('work-start').value+'+03:00')/1000,ends_at:Date.parse($('work-end').value+'+03:00')/1000,node_ids:nodeIds};
    if(editing){value.id=editing.id;value.version=editing.version;}
    await post('maintenance',value);const changed=Boolean(editing);await loadState();resetEditor();message(changed?'Изменения сохранены.':'Работы опубликованы на статус-сайте.');
  }catch(error){message(error.message,true);}finally{button.disabled=false;}
});
$('all-servers').addEventListener('change',updateScope);$('reset-editor').addEventListener('click',resetEditor);
$('logout-button').addEventListener('click',async()=>{try{await post('logout',{});loginView();$('admin-notice').hidden=true;}catch(error){message(error.message,true);}});
$('confirm-no').addEventListener('click',()=>$('confirm-dialog').close());
$('confirm-yes').addEventListener('click',async()=>{
  if(!pending)return;const button=$('confirm-yes');button.disabled=true;
  try{await post(pending.action,{id:pending.work.id,version:pending.work.version});$('confirm-dialog').close();await loadState();resetEditor();message(pending.action==='finish'?'Работы завершены.':'Работы отменены.');pending=null;}
  catch(error){$('confirm-dialog').close();message(error.message,true);}finally{button.disabled=false;}
});
loadState().then(ready=>{if(ready)resetEditor();}).catch(error=>message(error.message,true));
