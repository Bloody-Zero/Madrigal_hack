'use strict';
const $=id=>document.getElementById(id);
const esc=x=>String(x??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const enc=encodeURIComponent;
let token='', state={}, profiles={}, selected=new Set(), current=null, view=null, activeJob=null, rule=null, saveTimer=null, saving=Promise.resolve(), resultOffset=0;
function fail(e){$('error').textContent=e.message||String(e);$('error').hidden=false;$('saveState').textContent='Ошибка';}
function clearError(){$('error').hidden=true;}
async function api(path, options={}){
  const headers={...(options.body instanceof Blob?{}:{'Content-Type':'application/json'}),'X-Lab-Token':token,...options.headers};
  const r=await fetch(path,{...options,headers});
  const data=await r.json();if(!r.ok)throw Error(data.error||JSON.stringify(data));return data;
}
function on(id,fn,event='click'){$(id).addEventListener(event,async e=>{try{clearError();await fn(e);}catch(err){fail(err);}});}
function tab(name){document.querySelectorAll('.tab').forEach(x=>x.classList.toggle('active',x.id===name));document.querySelectorAll('nav button').forEach(x=>x.classList.toggle('active',x.dataset.tab===name));if(name==='results'&&state.runs)renderResults().catch(fail);}
document.querySelectorAll('nav button').forEach(b=>b.addEventListener('click',()=>tab(b.dataset.tab)));
function sourceName(id){return state.sources?.find(x=>x.id===id)?.name||id.slice(0,10);}
function streamName(s){return `${s.session}/${s.direction} · ${s.from.join(':')} → ${s.to.join(':')} · ${s.length} Б`;}
function updateSelected(){$('selectedCount').textContent=selected.size;}
function saved(){$('saveState').textContent='Сохранено';}
async function refresh(initial=false){
  state=await api('/api/project');$('projectPath').textContent=state.project_path;$('sourceCount').textContent=state.sources.length;
  const available=new Set(state.streams.map(s=>s.id));selected=new Set([...selected].filter(x=>available.has(x)));
  $('sources').innerHTML=state.sources.map(src=>`<div class="source"><div class="source-name">${esc(src.name)}</div><div class="muted">${src.packet_count} пакетов · ${(src.size/1024).toFixed(1)} КиБ · ${src.import_seconds.toFixed(2)} с</div><button class="small secondary diagnostics" data-source="${esc(src.id)}">Диагностика (${src.diagnostic_count})</button>${state.streams.filter(s=>s.source_id===src.id).map(s=>`<div class="stream-item ${current===s.id?'current':''}"><input type="checkbox" class="corpus" data-id="${esc(s.id)}" ${selected.has(s.id)?'checked':''}><button class="stream-link" data-id="${esc(s.id)}">${esc(streamName(s))}${s.gaps.length?' ⚠ пропуски':''}${s.conflict_ranges.length?' ⚠ конфликт':''}</button></div>`).join('')}</div>`).join('')||'<p class="muted">Начните с examples/training.pcap</p>';
  document.querySelectorAll('.corpus').forEach(c=>c.addEventListener('change',()=>{c.checked?selected.add(c.dataset.id):selected.delete(c.dataset.id);updateSelected();}));
  document.querySelectorAll('.stream-link').forEach(b=>b.addEventListener('click',()=>chooseStream(b.dataset.id).catch(fail)));
  document.querySelectorAll('.diagnostics').forEach(b=>b.addEventListener('click',async()=>{try{const d=await api('/api/diagnostics/'+b.dataset.source);$('packetDetails').textContent=JSON.stringify(d,null,2);tab('exchange');}catch(e){fail(e);}}));
  const oldB=$('compareBStream').value;
  $('compareBStream').innerHTML=state.streams.filter(s=>s.length).map(s=>`<option value="${esc(s.id)}">${esc(sourceName(s.source_id)+' · '+streamName(s))}</option>`).join('');
  if(available.has(oldB))$('compareBStream').value=oldB;
  const oldRun=$('runSelect').value;
  $('runSelect').innerHTML=state.runs.map(r=>`<option value="${r.id}">${new Date(r.created*1000).toLocaleString()} · ${r.stale?'устарело':'текущие правила'} · ${esc(JSON.stringify(r.counts))}</option>`).join('');
  if(state.runs.some(r=>r.id===oldRun))$('runSelect').value=oldRun;
  renderJournal();updateSelected();
  if(initial){rule=structuredClone(state.rule);renderRule();}
  if(!current&&state.streams.some(s=>s.length))await chooseStream(state.streams.find(s=>s.length).id);
  saved();
}
async function chooseStream(id,start=0){
  current=id;$('viewOffset').value=start;
  document.querySelectorAll('.stream-item').forEach(x=>x.classList.toggle('current',x.querySelector('.stream-link')?.dataset.id===id));
  await showStream();
}
function hexdump(v, from=0){
  const hex=v.hex.match(/../g)||[], known=v.known.match(/../g)||[], conflict=v.conflicts.match(/../g)||[];
  let out='';
  const a=Number($('noteStart').value),b=Number($('noteEnd').value);
  for(let i=0;i<hex.length;i+=16){
    let bytes='',ascii='';
    for(let j=i;j<Math.min(i+16,hex.length);j++){
      const missing=known[j]!=='01', ambiguous=conflict[j]==='01', pos=from+j;
      bytes+=`<span class="byte ${missing?'missing':ambiguous?'conflict':''} ${a<=pos&&pos<b?'selected':''}" data-offset="${pos}">${missing?'??':ambiguous?'!!':hex[j]}</span>`;
      const c=parseInt(hex[j],16);ascii+=missing||ambiguous?'?':c>=32&&c<127?String.fromCharCode(c):'.';
    }
    out+=`<div class="hex-line"><span class="hex-offset">${(from+i).toString(16).padStart(8,'0')}</span><span>${bytes}</span><span class="ascii">${esc(ascii)}</span></div>`;
  }
  return out||'<span class="muted">Нет прикладных байтов</span>';
}
function renderHex(){
  if(!view)return;$('hex').classList.remove('empty');$('hex').innerHTML=hexdump(view,view.start);
  document.querySelectorAll('#hex .byte').forEach(b=>b.addEventListener('click',async e=>{
    const pos=Number(b.dataset.offset);
    if(e.shiftKey){$('noteEnd').value=Math.max(Number($('noteStart').value)+1,pos+1);}else{$('noteStart').value=pos;$('noteEnd').value=pos+1;}
    renderHex();renderRefs();
  }));
}
function renderRefs(){
  if(!view)return;const a=Number($('noteStart').value),b=Number($('noteEnd').value);
  const refs=view.references.filter(r=>r.stream_start<b&&r.stream_end>a);
  $('references').innerHTML=refs.map(r=>`<p><button class="small secondary packet-link" data-frame="${r.frame}">Пакет №${r.frame}</button> поток [${r.stream_start}, ${r.stream_end}) → пакет [${r.packet_start}, ${r.packet_end})<br><span class="muted">Время наблюдения: ${esc(r.time)}</span></p>`).join('')||'В текущем окне нет пакетов выбранного диапазона.';
  document.querySelectorAll('.packet-link').forEach(b=>b.addEventListener('click',async()=>{try{const p=await api(`/api/packet/${view.source_id}/${b.dataset.frame}`);$('packetDetails').textContent=`Пакет №${p.frame}, seq=${p.seq}, flags=0x${p.flags.toString(16)}, checksum status=${p.checksum}\nСохранено ${p.captured_length} / исходная длина ${p.wire_length}\nДанные начинаются в байте ${p.payload_offset}\n\n${(p.raw.match(/.{1,32}/g)||[]).join('\n')}`;}catch(e){fail(e);}}));
}
async function showStream(){
  if(!current)return;view=await api(`/api/stream/${enc(current)}?start=${Number($('viewOffset').value)||0}&length=256`);
  $('viewOffset').value=view.start;$('streamTitle').textContent=sourceName(view.source_id)+' · '+streamName(view)+` · база SEQ ${view.base_seq}`;
  $('compareAName').textContent=$('streamTitle').textContent;
  const warns=[];if(!view.start_seen)warns.push('Начало направления не захвачено: смещение 0 относится к доступному диапазону.');if(!view.roles_known)warns.push('Роли клиента и сервера не установлены.');if(view.gaps.length)warns.push('Пропуски байтов: '+JSON.stringify(view.gaps));if(view.conflict_ranges.length)warns.push('Конфликтующие перекрытия: '+JSON.stringify(view.conflict_ranges));if(view.error)warns.push(view.error);
  $('streamWarnings').innerHTML=warns.map(w=>`<div class="warn">${esc(w)}</div>`).join('');renderHex();renderRefs();
}
async function watchJob(id){
  activeJob=id;$('job').hidden=false;
  try{
    for(;;){const j=await api('/api/jobs/'+id);$('jobText').textContent=`${j.stage} · ${j.progress}`;
      if(j.status==='done'){await refresh();if(j.result?.id){$('runSelect').value=j.result.id;resultOffset=0;await renderResults();tab('results');}return j.result;}
      if(['error','cancelled'].includes(j.status))throw Error(j.error);
      await new Promise(r=>setTimeout(r,300));
    }
  }finally{activeJob=null;$('job').hidden=true;}
}
on('captureFile',async e=>{const f=e.target.files[0];if(!f)return;$('saveState').textContent='Импорт…';const j=await api('/api/import?name='+enc(f.name),{method:'POST',body:f});await watchJob(j.job_id);e.target.value='';},'change');
on('cancelJob',async()=>{if(activeJob)await api('/api/jobs/'+activeJob+'/cancel',{method:'POST'});});
on('selectAll',async()=>{selected=new Set(state.streams.filter(s=>s.length).map(s=>s.id));await refresh();});
on('selectNone',async()=>{selected.clear();await refresh();});
on('jump',showStream);on('prev',async()=>{$('viewOffset').value=Math.max(0,Number($('viewOffset').value)-256);await showStream();});on('next',async()=>{$('viewOffset').value=Number($('viewOffset').value)+256;await showStream();});
on('noteStart',async()=>{renderHex();renderRefs();},'input');on('noteEnd',async()=>{renderHex();renderRefs();},'input');
on('search',async()=>{if(!current)throw Error('Выберите поток');const r=await api(`/api/search/${enc(current)}?hex=${enc($('searchHex').value)}&start=${Number($('viewOffset').value)}`);if(r.offset===null)throw Error('Не найдено в доступных однозначных байтах после текущего смещения');await chooseStream(current,r.offset);});
on('addNote',async()=>{if(!current)throw Error('Выберите поток');await api('/api/notes',{method:'POST',body:JSON.stringify({stream_id:current,start:Number($('noteStart').value),end:Number($('noteEnd').value),kind:$('noteKind').value,text:$('noteText').value})});$('noteText').value='';await refresh();});
function renderJournal(){
  $('notes').innerHTML=state.notes.map(n=>`<div class="journal-entry"><span class="badge">${esc(n.kind)}</span> ${esc(sourceName(n.source_id))} · [${n.start}, ${n.end})<p>${esc(n.text)}</p><button class="small secondary note-open" data-id="${n.id}">К исходным байтам</button></div>`).join('')||'<p class="muted">Добавьте запись из раздела «Обмен».</p>';
  document.querySelectorAll('.note-open').forEach(b=>b.addEventListener('click',async()=>{const n=state.notes.find(n=>n.id===b.dataset.id);$('noteStart').value=n.start;$('noteEnd').value=n.end;tab('exchange');await chooseStream(n.stream_id,n.start);}));
  $('actions').innerHTML=state.actions.map(a=>`<div class="journal-entry">${esc(sourceName(a.source_id))} · ${esc(a.capture_time)} · <strong>${esc(a.action)}</strong> ${esc(a.value)} <button class="small secondary action-open" data-id="${a.id}">Ближайший обмен</button><div class="muted">Смещение часов: ${esc(a.clock_offset)} с</div></div>`).join('')||'<p class="muted">Журнал действий ещё не импортирован.</p>';
  document.querySelectorAll('.action-open').forEach(b=>b.addEventListener('click',async()=>{try{const r=await api('/api/actions/'+b.dataset.id+'/locate');$('noteStart').value=r.start;$('noteEnd').value=r.end;tab('exchange');await chooseStream(r.stream_id,r.start);$('packetDetails').textContent=`Ближайший по времени сегмент, разница ${r.delta_seconds.toFixed(6)} с. Это подсказка для исследования, а не доказательство связи с действием.`;}catch(e){fail(e);}}));
}
on('importActions',async()=>{const f=$('actionsFile').files[0];if(!f)throw Error('Выберите CSV');await api('/api/actions',{method:'POST',body:JSON.stringify({csv:await f.text(),clock_offset:Number($('clockOffset').value)})});await refresh();});
const fieldTypes=['uint8','uint16','uint32','int8','int16','int32','float32','bytes','utf8'];
function renderRule(){
  $('ruleName').value=rule.name||'';$('startOffset').value=rule.start_offset||0;
  const f=rule.framing;$('framingMode').value=f.mode;$('fixedSize').value=f.size||7;$('lengthOffset').value=f.offset??3;$('lengthWidth').value=f.width||2;$('lengthEndian').value=f.endian||'big';$('lengthAdd').value=f.add??5;
  $('fixedOptions').hidden=f.mode!=='fixed';$('lengthOptions').hidden=f.mode!=='length';
  // hidden must override row's display:flex.
  $('lengthOptions').style.display=f.mode==='length'?'flex':'none';
  $('fieldRows').innerHTML=rule.fields.map((f,i)=>`<tr data-index="${i}"><td><input data-key="name" value="${esc(f.name)}"></td><td><input data-key="offset" type="number" min="0" value="${f.offset}"></td><td><select data-key="type">${fieldTypes.map(t=>`<option ${t===f.type?'selected':''}>${t}</option>`).join('')}</select></td><td><input data-key="size" value="${esc(f.size??'')}" placeholder="rest"></td><td><select data-key="endian"><option value="big" ${f.endian!=='little'?'selected':''}>big</option><option value="little" ${f.endian==='little'?'selected':''}>little</option></select></td><td><input data-key="equals" value="${esc(f.equals??'')}" placeholder="не задано"></td><td><button class="secondary remove-field" data-index="${i}">×</button></td></tr>`).join('');
  document.querySelectorAll('#fieldRows input,#fieldRows select').forEach(el=>el.addEventListener('change',()=>{const i=Number(el.closest('tr').dataset.index),f=rule.fields[i],k=el.dataset.key,v=el.value;
    if(k==='equals'){if(v==='')delete f.equals;else f.equals=f.type==='bytes'||f.type==='utf8'?v:Number(v);}
    else if(k==='offset')f[k]=Number(v);else if(k==='size'){if(v)f[k]=v==='rest'?'rest':Number(v);else delete f.size;}
    else f[k]=v;
    if(k==='type'&&['bytes','utf8'].includes(v)&&!f.size)f.size='rest';
    $('ruleJson').value=JSON.stringify(rule,null,2);scheduleSave();
  }));
  document.querySelectorAll('.remove-field').forEach(b=>b.addEventListener('click',()=>{rule.fields.splice(Number(b.dataset.index),1);renderRule();scheduleSave();}));
  $('ruleJson').value=JSON.stringify(rule,null,2);
}
function scheduleSave(){clearTimeout(saveTimer);$('saveState').textContent='Изменения…';saveTimer=setTimeout(()=>saveRule().catch(fail),600);}
async function saveRule(){
  clearTimeout(saveTimer);const snapshot=structuredClone(rule);
  saving=saving.catch(()=>{}).then(()=>api('/api/rule',{method:'POST',body:JSON.stringify(snapshot)}));
  await saving;saved();
}
function framingFromForm(){
  rule.name=$('ruleName').value;rule.start_offset=Number($('startOffset').value);
  const mode=$('framingMode').value;
  rule.framing=mode==='fixed'?{mode,size:Number($('fixedSize').value)}:{...rule.framing,mode,offset:Number($('lengthOffset').value),width:Number($('lengthWidth').value),endian:$('lengthEndian').value,add:Number($('lengthAdd').value)};
  renderRule();scheduleSave();
}
for(const id of ['ruleName','startOffset','framingMode','fixedSize','lengthOffset','lengthWidth','lengthEndian','lengthAdd'])on(id,framingFromForm,'change');
on('addField',async()=>{rule.fields.push({name:'field_'+rule.fields.length,offset:5,type:'uint16',endian:'big'});renderRule();scheduleSave();});
on('loadProfile',async()=>{rule=structuredClone(profiles[$('profile').value]);renderRule();await saveRule();await refresh();});
on('applyJson',async()=>{rule=JSON.parse($('ruleJson').value);await saveRule();renderRule();await refresh();});
async function check(){if(!selected.size)throw Error('Выберите потоки галочками слева');await saveRule();const j=await api('/api/check',{method:'POST',body:JSON.stringify({stream_ids:[...selected]})});await watchJob(j.job_id);}
on('check',check);on('check2',check);
async function renderResults(){
  const id=$('runSelect').value;if(!id){$('runSummary').textContent='Проверок пока нет.';return;}
  const r=await api(`/api/runs/${id}?offset=${resultOffset}&limit=100&status=${$('statusFilter').value}`);
  $('runSummary').innerHTML=`<div class="card">${r.stale?'<div class="warn">Результат устарел: правила изменились. Запустите проверку повторно.</div>':''}<strong>${esc(JSON.stringify(r.counts))}</strong><p class="muted">${r.stream_ids.length} потоков · ${r.seconds.toFixed(3)} с · неинтерпретированных байтов ${r.unknown_bytes}<br>Корпус и фильтр: ${esc(r.stream_ids.map(x=>sourceName(x.split(':')[0])+':'+x.split(':').slice(1).join('/')).join(', '))} · ${esc($('statusFilter').value)}</p><div class="row"><a class="button secondary" target="_blank" href="/api/runs/${id}/report">HTML-отчёт</a><a class="button secondary" href="/api/runs/${id}/download">Все результаты JSON</a></div><p class="muted">Успешный разбор не подтверждает смысл полей. Диагностика потоков включена в JSON и отчёт.</p></div>`;
  $('resultRows').innerHTML=r.rows.map((row,i)=>`<tr><td><button class="secondary open-result" data-i="${i}">${esc(sourceName(row.source_id))}<br>${esc(row.stream_id.split(':').slice(1).join('/'))} · [${row.start}, ${row.end})</button></td><td>${esc(row.status)}</td><td>${row.fields.map((f,j)=>`<button class="value-link field-result" data-i="${i}" data-j="${j}">${esc(f.name)} = ${esc(String(f.value).slice(0,160))}</button>`).join('')}</td><td>${esc(row.errors.join('; '))}${row.unknown_ranges.length?'<br>Не описано: '+esc(JSON.stringify(row.unknown_ranges)):''}</td></tr>`).join('');
  const open=async(row,field)=>{$('noteStart').value=field?.start??row.start;$('noteEnd').value=field?.end??row.end;tab('exchange');await chooseStream(row.stream_id,field?.start??row.start);};
  document.querySelectorAll('.open-result').forEach(b=>b.addEventListener('click',()=>open(r.rows[Number(b.dataset.i)]).catch(fail)));
  document.querySelectorAll('.field-result').forEach(b=>b.addEventListener('click',()=>{const row=r.rows[Number(b.dataset.i)];open(row,row.fields[Number(b.dataset.j)]).catch(fail);}));
  $('resultsPage').textContent=`${r.filtered_count?resultOffset+1:0}–${Math.min(resultOffset+100,r.filtered_count)} из ${r.filtered_count}`;
  $('resultsPrev').disabled=resultOffset===0;$('resultsNext').disabled=resultOffset+100>=r.filtered_count;
}
on('runSelect',async()=>{resultOffset=0;await renderResults();},'change');on('statusFilter',async()=>{resultOffset=0;await renderResults();},'change');
on('resultsPrev',async()=>{resultOffset=Math.max(0,resultOffset-100);await renderResults();});on('resultsNext',async()=>{resultOffset+=100;await renderResults();});
on('compareGo',async()=>{
  if(!current||!$('compareBStream').value)throw Error('Выберите два потока');
  const len=Math.max(1,Math.min(512,Number($('compareLength').value)));
  const [a,b]=await Promise.all([api(`/api/stream/${enc(current)}?start=${Number($('compareAStart').value)}&length=${len}`),api(`/api/stream/${enc($('compareBStream').value)}?start=${Number($('compareBStart').value)}&length=${len}`)]);
  function cells(v){return (v.hex.match(/../g)||[]).map((h,i)=>v.known.slice(i*2,i*2+2)!=='01'?'??':v.conflicts.slice(i*2,i*2+2)==='01'?'!!':h);}
  const ac=cells(a),bc=cells(b);let diff=0;
  function render(x,y){return x.map((c,i)=>`${i%16===0?(i?'\n':'')+(i.toString(16).padStart(4,'0'))+'  ':''}<span class="${c!==y[i]?'diff':''}">${c}</span> `).join('');}
  for(let i=0;i<Math.max(ac.length,bc.length);i++)if(ac[i]!==bc[i])diff++;
  $('compareA').innerHTML=render(ac,bc);$('compareB').innerHTML=render(bc,ac);$('compareSummary').textContent=`Различающихся позиций: ${diff}. Длины диапазонов: ${ac.length} / ${bc.length} байт. Сравнение не устанавливает назначение полей.`;
});
(async()=>{try{const b=await api('/api/bootstrap');token=b.token;profiles=b.profiles;$('dependency').textContent=b.tshark;$('profile').innerHTML=Object.entries(profiles).map(([id,p])=>`<option value="${id}">${esc(p.name)}</option>`).join('');await refresh(true);await renderResults();}catch(e){fail(e);}})();
