'use strict';
const $ = s => document.querySelector(s);
const token = $('meta[name="lab-token"]').content;
let meta, history=[], activeId=null, liveId=null, detail=null, evidenceIndex=0, selected=new Set(), busy=false, pollBusy=false, demoMode=false;
let discovery=null, modelFilter='';
const statusNames={idle:'等待开始',running:'检测中',stopping:'正在停止',completed:'已完成',failed:'失败',stopped:'已停止',imported:'已导入'};
const esc = s => String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmt = n => typeof n==='number'&&Number.isFinite(n)?n.toFixed(2)+' s':'—';
const check = r => !r.complete?'<span class="status bad">不完整</span>':r.validation_pass===true?'<span class="status ok">通过</span>':r.validation_pass===false?'<span class="status bad">未通过</span>':'<span class="status neutral">人工检查</span>';
async function api(path,body,headers={}){const response=await fetch(path,{method:body?'POST':'GET',headers:{'X-Lab-Token':token,...(body?{'Content-Type':'application/json'}:{}),...headers},...(body?{body:JSON.stringify(body)}:{})});if(!response.ok){let error;try{error=(await response.json()).error;}catch{error='请求失败';}throw Error(error);}return response.json();}
function toast(message){$('#toast').textContent=message;$('#toast').hidden=false;clearTimeout(toast.timer);toast.timer=setTimeout(()=>$('#toast').hidden=true,5000);}
function page(name){document.querySelectorAll('.page').forEach(p=>p.hidden=p.id!==name+'Page');document.querySelectorAll('.nav').forEach(b=>b.classList.toggle('active',b.dataset.page===name));const titles={detect:['让模型的行为，留下证据。','从响应、参数和重复调用中，观察你的 API 实际表现。'],history:['每一次检测，都有迹可循。','浏览历史记录、核对原始响应，导出你的观察结果。'],compare:['把差异，放在同一张桌上。','对照两个端点或不同时段的行为，寻找可复核的线索。']};$('#pageTitle').textContent=titles[name][0];$('#pageSubtitle').textContent=titles[name][1];if(name!=='detect')refreshHistory().catch(e=>toast(e.message));}
function planned(){const count=selected.size*Number($('#repeats').value||0);$('#planned').textContent=count+' 次请求';if(!busy)$('#progressText').textContent='0 / '+count;}
function preset(name){selected=new Set(meta.presets[name]);document.querySelectorAll('.preset').forEach(b=>b.classList.toggle('selected',b.dataset.preset===name));renderPicker();planned();}
function renderPicker(){$('#casePicker').innerHTML=meta.cases.map(c=>`<label title="${esc(c.category)}"><input type="checkbox" value="${esc(c.id)}" ${selected.has(c.id)?'checked':''}>${esc(c.id)}</label>`).join('');}
function stats(s,target){$(target).innerHTML=[['完整响应',s.complete+' / '+s.count],['失败 / 不完整',s.failed],['总延迟中位数',fmt(s.median_s)],['TTFT 中位数',fmt(s.ttft_s)]].map(([name,value])=>`<div class="stat"><small>${esc(name)}</small><strong>${esc(value)}</strong></div>`).join('');}
function rowTable(rows,extra=false){return rows.map((r,i)=>`<tr><td>${esc(r.case_id)}</td><td>${esc(r.repeat??'—')}</td><td>${esc(r.http_status??'—')}</td><td>${check(r)}</td><td>${fmt(r.total_s)}</td><td>${esc(r.usage?.prompt_tokens??'—')}</td>${extra?`<td><button class="text-button evidence-btn" data-index="${i}">查看 →</button></td>`:''}</tr>`).join('');}
// --- Model list discovery ---------------------------------------------------
// The list is what the endpoint says about itself: it names candidates to test
// and can be diffed between runs, but it never establishes a model's identity.
function renderModels(message){
  const wrap=$('#modelPicker');
  if(!discovery){wrap.hidden=true;return;}
  wrap.hidden=false;
  const declared=$('#model').value.trim();
  const loose=discovery.models.find(m=>m===declared||m.endsWith('/'+declared));
  const listed=discovery.models.includes(declared);
  const flagged=!!declared&&!loose;
  wrap.classList.toggle('warn',flagged);
  const route=discovery.attempts?.[0];
  const tried=discovery.attempts||[];
  $('#modelSummary').textContent=(message||`自报 ${discovery.count} 个模型 ID`)+
    (route?` · ${route.url.replace(/^https?:\/\//,'')}`:'')+
    (declared?(loose?(listed?' · 已选中，在列表中':' · 已选中，去前缀匹配到 '+loose):' · 声明的模型不在列表中'):'');
  const term=modelFilter.trim().toLowerCase();
  const shown=discovery.models.filter(m=>!term||m.toLowerCase().includes(term));
  const failed=tried.filter(a=>!a.count);
  $('#modelList').innerHTML=(shown.length?shown.map(m=>{
    const isCurrent=m===declared;
    const isFlagged=flagged&&(m===declared||m.endsWith('/'+declared));
    return `<button type="button" class="pick${isFlagged?' flagged':''}" data-model="${esc(m)}" title="${esc(m)}"${isCurrent?' aria-current="true"':''}>${esc(m)}</button>`;
  }).join(''):`<span class="empty">${discovery.models.length?'没有匹配的模型 ID':'端点未返回可解析的模型 ID'}</span>`)
  + (failed.length?`<span class="empty">未取到列表的路由：${esc(failed.map(a=>a.url.replace(/^https?:\/\//,'')+' → '+a.http_status).join('、'))}</span>`:'');
}
async function fetchModels(){
  const base=$('#base').value.trim();
  if(!base){toast('请先填写 Base URL');return;}
  if(!$('#key').value){toast('获取模型列表需要 API Key');return;}
  const button=$('#fetchModels');button.disabled=true;button.textContent='获取中…';
  try{
    const r=await api('/api/models?base_url='+encodeURIComponent(base)+'&timeout=15',null,{'X-Provider-Key':$('#key').value});
    discovery=r;modelFilter='';$('#modelFilter').value='';
    renderModels();
    if(!r.count)toast('端点未返回可解析的模型 ID，已保存原始响应供核对');
  }catch(e){discovery=null;$('#modelPicker').hidden=true;toast(e.message);}
  finally{button.disabled=false;button.textContent='获取列表';}
}

async function refreshHistory(){history=await api('/api/history');refreshReferences().catch(e=>toast(e.message));$('#historyCount').textContent=history.length;$('#historyList').innerHTML=history.length?history.map(h=>`<div class="history-item ${h.run_id===activeId?'selected':''}"><div><h3>${esc(h.label)}</h3><p>${esc(h.model)} · ${esc(h.created_at)}${h.run_id.startsWith('import-')?' · 导入记录':''}</p></div><div class="history-meta"><span>${h.summary.complete} / ${h.summary.count} 完整</span><span>${esc(statusNames[h.status]||h.status)}</span><button class="secondary small open-run" data-id="${esc(h.run_id)}">打开 →</button></div></div>`).join(''):'<div class="empty">还没有检测记录。<br>开始一次检测，或导入之前保存的 results.jsonl。</div>';const oldA=$('#compareA').value,oldB=$('#compareB').value;for(const sel of ['#compareA','#compareB'])$(sel).innerHTML='<option value="">选择检测记录</option>'+history.map(h=>`<option value="${esc(h.run_id)}">${esc(h.label)} · ${esc(h.run_id)}</option>`).join('');$('#compareA').value=oldA;$('#compareB').value=oldB;}
// --- Signal panel ----------------------------------------------------------
// Everything shown here was already collected during the run. No extra request
// is made, and each line is an observation about the chain, not a verdict.
const sfmt=v=>typeof v==='number'&&Number.isFinite(v)?v+' s':'—';
const list=v=>Array.isArray(v)&&v.length?v.join('、'):'—';
function signalPanel(){
  const target=$('#signalsPanel');
  const sig=detail?.signals;
  if(!sig){target.innerHTML='';return;}
  const cards=[];
  for(const [id,label] of [['model','响应返回的 model'],['system_fingerprint','响应返回的 system_fingerprint'],['id_prefixes','响应 ID 前缀']]){
    const point=sig.agreement?.[id];if(!point)continue;
    cards.push([`${label}：${list(point.values)}`,
      (point.mixed?'本次运行内出现过变化。':'本次运行内保持一致。')+
      (id==='id_prefixes'?'ID 前缀由服务端生成，可被代理转发或改写；相同前缀只说明链路相似。':''),false]);
  }
  const dm=sig.agreement?.declared_model;
  if(dm)cards.push([`请求的模型 ID：${list(dm.values)}`,dm.note||'',!!dm.returned_differs]);
  if(sig.headers?.collected)cards.push([
    `响应头（${sig.headers.collected}/${sig.headers.total} 次记录到）`,
    `观测到：${list((sig.headers.notes||[]).map(n=>n.name))}`+
    (sig.headers.absent?.length?`\n常见但未见：${list(sig.headers.absent)}`:'')+
    (sig.headers.present?.length?`\n限流与追踪类：${list(sig.headers.present)}`:'')+
    '\n凭据类头部（cookie、authorization、session、API key）已脱敏，不进入记录。',false]);
  for(const t of sig.tokenizer||[])cards.push([`分词探针 ${t.case_id}：输入计数 ${list(t.prompt_tokens)}`,
    t.note||(t.stable?'重复之间一致。':'重复之间不一致，核对计量口径。'),!!t.note]);
  for(const l of sig.logprobs||[])cards.push([`logprobs 分词：${list(l.token_counts)} 个 token，${l.distinct_tokenizations} 种切分`,
    `样例切分：${list(l.sample)}
${l.note||''}`,l.distinct_tokenizations>1]);
  for(const st of sig.streams||[]){if(!st.gaps)continue;
    cards.push([`流式节奏 ${st.case_id} #${st.repeat}：${st.profile}`,
      `块间中位 ${sfmt(st.gap_p50)}，抖动 ${st.gap_stdev??'—'}，同批到达占比 ${st.simultaneous_ratio}，约 ${st.chars_per_s??'—'} 字符/秒`+
      '\n整段一起到达通常是缓冲或排队，不是模型生成速度。',false]);}
  if(sig.usage_keys)cards.push(['usage 字段',
    `观测到：${list(sig.usage_keys.keys)}；缓存类：${list(sig.usage_keys.cached)}；推理类：${list(sig.usage_keys.reasoning)}\n${sig.usage_keys.note}`,false]);
  if(sig.models?.count)cards.push(['端点自报的模型列表',
    `${sig.models.count} 个 ID，采集于 ${sig.models.captured_at||'—'}，来自 ${sig.models.url||'—'}\n列表由端点自报，可被改写，只用于挑选待测模型。`,false]);
  const tok=tokrefBlock();
  if(!cards.length&&!tok){target.innerHTML='';return;}
  target.innerHTML=`<div class="signals"><h3>侧信道信号 · 来自本次已保存的响应</h3>${tok}${
    cards.map(([title,body,lead])=>`<div class="signal${lead?' lead':''}"><strong>${esc(title)}</strong><p>${esc(body).replace(/\n/g,'<br>')}</p></div>`).join('')}</div>`;
}
// Differential tokenizer comparison against the reference library. A shared
// tokenizer names a family, never a model size, so no probability is shown.
const levelNames={exact:'逐 token 一致',near:'接近，非逐 token 一致',different:'不一致'};
function tokrefBlock(){
  const t=detail?.tokref;
  if(!t||!t.usable)return '';
  if(!t.matches.length)return `<div class="signal"><strong>分词参照比对</strong><p>${esc(t.references?
    '参照库里没有与本次探针文本相同的参照。':'参照库为空。')}请先用“分词与计量”方案检测一个可信的官方端点，再在那条记录上点“设为分词参照”。</p></div>`;
  const d=t.declared;
  let verdict='本次请求的模型没有对应的参照，下表只列出最接近的分词器。';
  if(d&&d.level==='different')verdict=`请求的模型 ${d.model} 与它自己的参照“${d.label}”分词不一致。`+
    (d.nearest?`最接近的是“${d.nearest.label}”（${levelNames[d.nearest.level]}）。`:'')+
    '\n也可能是中转站用本地估算代替了上游计量，请对照原始响应核实。';
  else if(d)verdict=`请求的模型 ${d.model} 与它的参照“${d.label}”${levelNames[d.level]}。`+
    (d.offset?`\n空载探针比参照多计 ${d.offset} 个输入 token：可能附带了隐藏上下文，或计费口径不同。`:'');
  const rows=t.matches.map(m=>`<tr><td>${esc(m.label)}${m.source==='builtin'?' · 内置':''}</td><td>${esc(m.family||'—')}</td><td>${esc(levelNames[m.level])}</td><td>${m.max_abs_diff}</td><td>${m.level==='exact'&&m.anchored_on_base?m.offset:'—'}</td></tr>`).join('');
  return `<div class="signal${d?.level==='different'?' lead':''}"><strong>分词参照比对</strong><p>${esc(verdict).replace(/\n/g,'<br>')}</p>`+
    `<div class="table-wrap"><table><thead><tr><th>参照</th><th>系列</th><th>结论</th><th>最大差值</th><th>输入偏移</th></tr></thead><tbody>${rows}</tbody></table></div>`+
    `<p>差分比较抵消了聊天模板和固定的隐藏系统提示。分词器相同只说明同一系列，例如 gpt-4o 与 gpt-4o-mini 共用分词器。</p></div>`;
}
async function refreshReferences(){
  const refs=await api('/api/references');
  $('#refCount').textContent=refs.length+' 条';
  $('#refList').innerHTML=refs.length?refs.map(r=>`<div class="ref-item"><div><strong>${esc(r.label)}</strong>${r.source==='builtin'?' <span class="tag">内置</span>':''}`+
    `<p>${esc(r.model||'—')} · ${esc(r.family||'未填写系列')} · ${esc(r.endpoint_host||'—')} · ${Object.keys(r.probes).length} 个探针</p></div>`+
    (r.source==='local'?`<button class="secondary small del-ref" data-id="${esc(r.id)}">删除</button>`:'')+'</div>').join('')
    :'<div class="empty">还没有参照。对可信官方端点运行“分词与计量”方案后，在记录详情里点“设为分词参照”。</div>';
}

async function openRun(id){detail=await api('/api/run?id='+encodeURIComponent(id));activeId=id;demoMode=false;renderDetail();}
function renderDetail(){$('#runDetail').hidden=false;$('#detailTitle').textContent=detail.manifest.label||detail.manifest.model||'检测记录';$('#detailMeta').textContent=(demoMode?'演示数据 · 未发生 API 调用':detail.manifest.endpoint||'导入记录 · 无原始正文文件')+' · '+(detail.manifest.run_id||'');$('#export').disabled=demoMode||['running','stopping'].includes(detail.manifest.status);$('#makeRef').disabled=demoMode||detail.manifest.status==='imported'||['running','stopping'].includes(detail.manifest.status);$('#refForm').hidden=true;stats(detail.summary,'#detailStats');$('#anomalies').innerHTML=detail.summary.anomalies.map(a=>`<div class="anomaly"><strong>${esc(a.case_id)}</strong> · ${esc(a.message)}</div>`).join('');$('#reportTab').textContent=detail.report||'尚无报告';signalPanel();filterRecords();$('#runDetail').scrollIntoView({behavior:'smooth',block:'start'});}
function filterRecords(){const mode=$('#recordFilter').value;$('#detailRows').innerHTML=rowTable(detail.rows,true);$('#detailRows').querySelectorAll('tr').forEach((tr,i)=>{const r=detail.rows[i];tr.hidden=mode==='failed'?r.complete:mode==='check'?r.validation_pass!==false:false;});}
async function showEvidence(index,raw=false){evidenceIndex=index;const r=detail.rows[index];$('#evidenceTitle').textContent=r.case_id+' · 第 '+(r.repeat??'—')+' 次';$('#evidence').showModal();if(raw){if(demoMode||!r.raw_file){$('#evidenceBody').textContent='此记录没有原始正文文件。';return;}try{const res=await fetch('/api/raw?id='+encodeURIComponent(activeId)+'&index='+index,{headers:{'X-Lab-Token':token}});if(!res.ok)throw Error('无法读取原始文件');$('#evidenceBody').textContent=await res.text();}catch(e){$('#evidenceBody').textContent=e.message;}}else $('#evidenceBody').textContent=JSON.stringify(r,null,2);}
async function poll(){if(pollBusy)return;pollBusy=true;try{const state=await api('/api/state');busy=['running','stopping'].includes(state.status);$('#start').disabled=busy;$('#stop').hidden=!busy;$('#stop').disabled=state.status==='stopping';$('.live-card').classList.toggle('running',busy);$('#runBadge').textContent=statusNames[state.status]||state.status;$('#progressBar').style.width=(state.planned?state.completed/state.planned*100:0)+'%';$('#progressText').textContent=state.completed+' / '+(state.planned||selected.size*Number($('#repeats').value));$('#liveTitle').textContent=state.current?state.current.case_id+' · 第 '+state.current.repeat+' 次':state.status==='idle'?'准备接收第一个信号':state.message;$('#liveMessage').textContent=state.current?'正在等待 API 响应；页面会自动更新。':state.status==='idle'?'填写 API 信息后即可开始。先用快速观察验证连接，再进行完整测试。':state.message;$('#elapsed').textContent=state.started_at&&busy?'已运行 '+Math.floor((Date.now()/1000-state.started_at))+' 秒':'—';if(state.run_id){liveId=state.run_id;const run=await api('/api/run?id='+encodeURIComponent(state.run_id));$('#liveResults').hidden=false;stats(run.summary,'#liveStats');$('#liveRows').innerHTML=rowTable(run.rows.slice(-12).reverse());if(poll.lastStatus&&poll.lastStatus!==state.status&&!busy)await refreshHistory();}poll.lastStatus=state.status;}catch(e){if(!poll.warned){toast('本地服务连接中断；请保持启动窗口运行。');poll.warned=true;}}finally{pollBusy=false;}}
async function compare(){const a=$('#compareA').value,b=$('#compareB').value;if(!a||!b||a===b){toast('请选择两批不同的检测记录');return;}try{const [x,y]=await Promise.all([api('/api/run?id='+encodeURIComponent(a)),api('/api/run?id='+encodeURIComponent(b))]);const comparable=x.manifest.corpus_sha256&&x.manifest.corpus_sha256===y.manifest.corpus_sha256;$('#compareWarning').textContent=comparable?'语料哈希一致；仍需核对端点默认设置、采样、负载和隐藏提示词。':'语料哈希不一致或缺失。结果只作描述性比较，不宜据此评价模型优劣。';const names=[...new Set([...x.summary.cases,...y.summary.cases].map(c=>c.case_id))];
const sigOf=r=>({prefix:(r.signals?.agreement?.id_prefixes?.values||[]).join('、'),
  model:(r.signals?.agreement?.model?.values||[]).join('、'),
  fp:(r.signals?.agreement?.system_fingerprint?.values||[]).join('、'),
  headers:(r.signals?.headers?.notes||[]).map(n=>n.name).join('、'),
  gap:fmt(r.summary.cases.find(c=>c.stream_gap_p50!=null)?.stream_gap_p50)});
const sa=sigOf(x),sb=sigOf(y);
const rows=[['响应 ID 前缀',sa.prefix,sb.prefix],['返回 model',sa.model,sb.model],
  ['system_fingerprint',sa.fp,sb.fp],['响应头字段',sa.headers,sb.headers],['流式块间中位',sa.gap,sb.gap]];
const signalBlock=`<h3 class="signals-title">侧信道对照</h3><div class="table-wrap"><table><thead><tr><th>信号</th><th>A</th><th>B</th></tr></thead><tbody>${
  rows.map(([k,a,b])=>`<tr><td>${esc(k)}</td><td class="mono">${esc(a||'—')}</td><td class="mono">${esc(b||'—')}</td></tr>`).join('')}</tbody></table></div>`;$('#compareResults').innerHTML=signalBlock+`<div class="table-wrap"><table><thead><tr><th>测试项</th><th>A 完整 / 调用</th><th>B 完整 / 调用</th><th>A / B 精确通过</th><th>A / B 延迟中位数</th><th>A / B 输入计数</th></tr></thead><tbody>${names.map(name=>{const a=x.summary.cases.find(c=>c.case_id===name),b=y.summary.cases.find(c=>c.case_id===name);return `<tr><td>${esc(name)}</td><td>${a?a.complete+'/'+a.count:'—'}</td><td>${b?b.complete+'/'+b.count:'—'}</td><td>${a?a.passed+'/'+a.checked:'—'} · ${b?b.passed+'/'+b.checked:'—'}</td><td>${fmt(a?.median_s)} · ${fmt(b?.median_s)}</td><td>${esc(a?.prompt_tokens.join(', ')||'—')} / ${esc(b?.prompt_tokens.join(', ')||'—')}</td></tr>`;}).join('')}</tbody></table></div>`;}catch(e){toast(e.message);}}
function demo(){page('history');demoMode=true;const rows=[{case_id:'baseline',category:'control',repeat:1,http_status:200,complete:true,validation_pass:true,total_s:2.3,ttft_s:null,usage:{prompt_tokens:34},text:'hello',request_sha256:'demo-baseline',output_sha256:'a'}, {case_id:'baseline',category:'control',repeat:2,http_status:200,complete:true,validation_pass:true,total_s:4.8,ttft_s:null,usage:{prompt_tokens:4414},text:'hello',request_sha256:'demo-baseline',output_sha256:'a'}, {case_id:'stop',category:'compatibility',repeat:1,http_status:200,complete:true,validation_pass:false,total_s:3.5,usage:{prompt_tokens:31},text:'ALPHA|OMEGA'}];detail={manifest:{label:'演示 · 参数与用量观察',model:'demo-model',status:'demo'},rows,summary:{count:3,complete:3,failed:0,median_s:3.5,ttft_s:null,anomalies:[{case_id:'baseline',message:'相同请求体的输入计数出现差异：34、4414。仅为演示，不代表实际服务商。'},{case_id:'stop',message:'停止符仍出现在正文中，调用链未兑现该停止条件。'}]},report:'# 演示报告\n\n这些是虚构演示数据，不会发起 API 请求。\n行为指纹不能确认底层模型身份。'};renderDetail();}
document.querySelectorAll('.nav').forEach(b=>b.onclick=()=>page(b.dataset.page));document.querySelectorAll('.preset').forEach(b=>b.onclick=()=>preset(b.dataset.preset));$('#repeats').oninput=planned;$('#toggleCases').onclick=()=>$('#casePicker').hidden=!$('#casePicker').hidden;$('#casePicker').onchange=e=>{if(e.target.checked)selected.add(e.target.value);else selected.delete(e.target.value);document.querySelectorAll('.preset').forEach(b=>b.classList.remove('selected'));planned();};$('#fetchModels').onclick=fetchModels;$('#modelFilter').oninput=e=>{modelFilter=e.target.value;renderModels();};$('#modelList').onclick=e=>{const b=e.target.closest('.pick');if(!b)return;$('#model').value=b.dataset.model;renderModels();};$('#model').oninput=()=>{if(discovery)renderModels();};$('#base').onchange=()=>{discovery=null;renderModels();};$('#showKey').onclick=()=>{const hidden=$('#key').type==='password';$('#key').type=hidden?'text':'password';$('#showKey').textContent=hidden?'隐藏':'显示';$('#showKey').setAttribute('aria-label',hidden?'隐藏密钥':'显示密钥');};
$('#runForm').onsubmit=async e=>{e.preventDefault();$('#formError').textContent='';$('#start').disabled=true;try{const config={label:$('#label').value,base_url:$('#base').value,model:$('#model').value,api_key:$('#key').value,models_ref:discovery?{ref_id:discovery.ref_id,url:discovery.attempts?.[0]?.url||'',count:discovery.count,kept:discovery.models,captured_at:discovery.captured_at}:null,cases:[...selected],repeats:Number($('#repeats').value),timeout:Number($('#timeout').value),interval:Number($('#interval').value),long_lines:Number($('#longLines').value)};const r=await api('/api/start',config);config.api_key='';$('#key').value='';$('#key').type='password';$('#showKey').textContent='显示';activeId=r.run_id;busy=true;await poll();}catch(e){$('#formError').textContent=e.message;$('#start').disabled=false;}};
$('#stop').onclick=async()=>{try{await api('/api/stop',{});await poll();}catch(e){toast(e.message);}};$('#openActive').onclick=async()=>{page('history');try{await openRun(liveId);}catch(e){toast(e.message);}};$('#historyList').onclick=async e=>{const b=e.target.closest('.open-run');if(b)try{await openRun(b.dataset.id);}catch(e){toast(e.message);}};
$('#detailRows').onclick=e=>{const b=e.target.closest('.evidence-btn');if(b)showEvidence(Number(b.dataset.index));};$('#recordFilter').onchange=filterRecords;$('#closeEvidence').onclick=()=>$('#evidence').close();$('#recordEvidence').onclick=()=>showEvidence(evidenceIndex);$('#rawEvidence').onclick=()=>showEvidence(evidenceIndex,true);document.querySelectorAll('.detail-tab').forEach(b=>b.onclick=()=>{document.querySelectorAll('.detail-tab').forEach(t=>t.classList.toggle('active',t===b));$('#recordsTab').hidden=b.dataset.tab!=='records';$('#reportTab').hidden=b.dataset.tab!=='report';});
$('#export').onclick=async()=>{try{const response=await fetch('/api/export?id='+encodeURIComponent(detail.manifest.run_id),{headers:{'X-Lab-Token':token}});if(!response.ok)throw Error((await response.json()).error);const url=URL.createObjectURL(await response.blob());const a=document.createElement('a');a.href=url;a.download=detail.manifest.run_id+'.zip';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}catch(e){toast(e.message);}};
$('#importBtn').onclick=()=>$('#importFile').click();$('#importFile').onchange=async e=>{const f=e.target.files[0];if(!f)return;try{if(f.size>20_000_000)throw Error('文件超过 20 MB');const r=await api('/api/import',{label:f.name+' · 历史导入',text:await f.text()});await refreshHistory();await openRun(r.run_id);toast('导入完成，旧版固定答案已按精确规则重新检查');}catch(e){toast(e.message);}finally{e.target.value='';}};$('#compareBtn').onclick=compare;
$('#makeRef').onclick=()=>{$('#refForm').hidden=false;$('#refLabel').value=(detail.manifest.model||'')+' · '+(detail.manifest.endpoint||'').replace(/^https?:\/\//,'').split('/')[0];$('#refLabel').focus();};
$('#refCancel').onclick=()=>$('#refForm').hidden=true;
$('#refForm').onsubmit=async e=>{e.preventDefault();try{await api('/api/reference',{run_id:activeId,label:$('#refLabel').value,family:$('#refFamily').value,note:$('#refNote').value});toast('已保存为分词参照');await refreshReferences();await openRun(activeId);}catch(err){toast(err.message);}};
$('#refList').onclick=async e=>{const b=e.target.closest('.del-ref');if(!b)return;
  // No confirm() dialog: a second click within 4 seconds deletes.
  if(b.dataset.armed!=='1'){b.dataset.armed='1';b.textContent='再点一次删除';setTimeout(()=>{b.dataset.armed='';b.textContent='删除';},4000);return;}
  try{await api('/api/reference/delete',{id:b.dataset.id});await refreshReferences();if(detail&&activeId&&!demoMode)await openRun(activeId);}catch(err){toast(err.message);}};$('#demo').onclick=demo;
function presetCounts(){const by={};for(const n of ['compatibility','full','models'])by[n]=(meta.presets[n]||[]).length;$('#fullCount').textContent=by['full']+' 项 · 覆盖全部维度';$('#modelsCount').textContent=by['models']+' 项 · 只看分词与计量';const compat=document.querySelector('[data-preset="compatibility"] small');if(compat)compat.textContent=by['compatibility']+' 项 · 检查接口兼容性';}
async function init(){try{meta=await api('/api/meta');$('#version').textContent=meta.version;presetCounts();preset('quick');await refreshHistory();await poll();setInterval(poll,2000);}catch(e){$('#formError').textContent=e.message;}}init();
