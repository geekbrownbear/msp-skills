package main

import "net/http"

func pageHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(page))
}

// The whole UI: one page, no external assets, renders from /api/catalog.
const page = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MSP Connector Setup</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--ink:#1a2330;--mut:#5b6875;--line:#dde3ea;--acc:#0b6bcb;--ok:#1a7f37;--warn:#b35c00;--err:#b42318}
*{box-sizing:border-box}body{margin:0;font:15px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--ink)}
header{padding:20px 24px;background:var(--card);border-bottom:1px solid var(--line)}
h1{margin:0;font-size:20px}header p{margin:4px 0 0;color:var(--mut);font-size:13px}
main{max-width:980px;margin:0 auto;padding:20px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:10px;margin-bottom:20px}
.chip{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 12px;cursor:pointer}
.chip:hover{border-color:var(--acc)}
.chip b{display:block;font-size:14px}.chip small{color:var(--mut)}
.chip .st{float:right;font-size:12px}.st.ok{color:var(--ok)}.st.none{color:var(--mut)}
.chip.sel{border-color:var(--acc);box-shadow:0 0 0 2px rgba(11,107,203,.15)}
form{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:20px;display:none}
form h2{margin:0 0 2px}.tag{color:var(--mut);font-size:13px;margin-bottom:14px}
.field{margin-bottom:16px}
label{font-weight:600;display:block}
label .req{color:var(--err);font-weight:400;font-size:12px;margin-left:6px}
label .opt{color:var(--mut);font-weight:400;font-size:12px;margin-left:6px}
.help{color:var(--mut);font-size:13px;margin:2px 0 6px}
input{width:100%;padding:8px 10px;border:1px solid var(--line);border-radius:8px;font:14px monospace}
input.bad{border-color:var(--err)}
.ex{color:var(--mut);font-size:12px;margin-top:3px}.ex code{background:var(--bg);padding:1px 5px;border-radius:4px}
.viol{color:var(--err);font-size:12px;margin-top:3px;display:none}
button{background:var(--acc);color:#fff;border:0;border-radius:8px;padding:10px 18px;font-size:15px;cursor:pointer}
button:disabled{opacity:.5}
.msg{margin-top:12px;font-size:14px;display:none;padding:10px 12px;border-radius:8px}
.msg.ok{display:block;background:#e6f4ea;color:var(--ok)}
.msg.err{display:block;background:#fdecea;color:var(--err)}
.enable{margin-top:10px;font-size:13px;color:var(--mut)}
.enable code{background:var(--bg);padding:2px 6px;border-radius:4px;user-select:all}
.note{background:#fff8e6;border:1px solid #f0dcae;border-radius:8px;padding:8px 12px;font-size:13px;color:var(--warn);margin-bottom:16px}
.derived{font-size:13px;margin-top:5px;color:var(--mut)}.derived code{background:#eef4fb;color:var(--acc);padding:2px 6px;border-radius:4px}
.ovr{margin-top:6px}.ovr summary{font-size:12px;color:var(--mut);cursor:pointer}
</style></head><body>
<header><h1>MSP Connector Setup</h1>
<p>Pick a connector, fill in its credentials, save. Values are written straight to the stack's secrets store on this host and never kept by this page. Running connectors reload on their own within seconds.</p></header>
<main>
<div class="note">Enter values exactly as issued &mdash; no quotes needed, ever. Fields marked required must be filled; everything else has a working default.</div>
<div class="grid" id="grid"></div>
<form id="form" onsubmit="return save(event)">
<h2 id="f-name"></h2><div class="tag" id="f-tag"></div>
<div id="fields"></div>
<button id="savebtn">Save credentials</button>
<div class="msg" id="msg"></div>
<div class="enable" id="enable"></div>
</form>
</main>
<script>
const T=new URLSearchParams(location.search).get('token')||'';
const H={'X-Setup-Token':T,'Content-Type':'application/json'};
let CAT=null,STATUS={},CUR=null;
async function boot(){
  const [c,s]=await Promise.all([
    fetch('/api/catalog',{headers:H}).then(r=>{if(!r.ok)throw new Error('token');return r.json()}),
    fetch('/api/status',{headers:H}).then(r=>r.json())]);
  CAT=c;STATUS=s;render();
}
function render(){
  const g=document.getElementById('grid');g.innerHTML='';
  const cs=[...CAT.connectors].sort((a,b)=>(b.hinted-a.hinted)||a.slug.localeCompare(b.slug));
  for(const c of cs){
    const d=document.createElement('div');d.className='chip'+(CUR===c.slug?' sel':'');
    const st=STATUS[c.slug]&&STATUS[c.slug].vars&&STATUS[c.slug].vars.length;
    d.innerHTML='<span class="st '+(st?'ok':'none')+'">'+(st?'&#10003; configured':'not set')+'</span><b>'+c.display_name+'</b><small>'+(c.category||'')+'</small>';
    d.onclick=()=>{CUR=c.slug;render();show(c)};
    g.appendChild(d);
  }
}
function show(c){
  const f=document.getElementById('form');f.style.display='block';
  document.getElementById('f-name').textContent=c.display_name;
  document.getElementById('f-tag').textContent=c.tagline||c.vendor;
  const have=(STATUS[c.slug]&&STATUS[c.slug].vars)||[];
  const box=document.getElementById('fields');box.innerHTML='';
  const fields=[...c.fields].sort((a,b)=>((b.required===true)-(a.required===true)));
  for(const fl of fields){
    const w=document.createElement('div');w.className='field';
    const req=fl.required===true?'<span class="req">required</span>':(fl.required===false?'<span class="opt">optional</span>':'<span class="req">needed</span>');
    const set=have.includes(fl.name)?' <span class="opt">(already set &mdash; saving overwrites the whole file, so re-enter everything)</span>':'';
    const d=fl.derive;
    if(d&&d.from_field){
      // derived from another field, with a custom override
      w.innerHTML='<label>'+fl.label+'<span class="opt">derived</span></label>'
        +(fl.help?'<div class="help">'+esc(fl.help)+'</div>':'')
        +'<div class="derived" id="prev-'+fl.name+'">&rarr; <code>(fill in '+esc(d.from_field)+' above)</code></div>'
        +'<details class="ovr"><summary>'+esc(d.override_label||'use a custom value instead')+'</summary>'
        +'<input name="'+fl.name+'__override" data-pattern="'+esc(d.override_pattern||'')+'" type="text" spellcheck="false">'
        +(d.override_example?'<div class="ex">example: <code>'+esc(d.override_example)+'</code></div>':'')
        +'<div class="viol">does not match the expected shape</div></details>';
    }else if(d){
      // derived from its own small input
      w.innerHTML='<label>'+esc(d.input_label||fl.label)+req+set+'</label>'
        +(d.input_help?'<div class="help">'+esc(d.input_help)+'</div>':'')
        +'<input name="'+fl.name+'__input" data-pattern="'+esc(d.input_pattern||'')+'" type="text" spellcheck="false" style="max-width:260px">'
        +(d.input_example?'<div class="ex">example: <code>'+esc(d.input_example)+'</code></div>':'')
        +'<div class="derived" id="prev-'+fl.name+'">&rarr; <code>&hellip;</code></div>'
        +'<div class="viol">does not match the expected shape shown in the example</div>';
    }else{
      w.innerHTML='<label>'+fl.label+req+set+'</label>'
        +(fl.help?'<div class="help">'+esc(fl.help)+'</div>':'')
        +'<input name="'+fl.name+'" data-pattern="'+esc(fl.pattern||'')+'" '+(fl.sensitive?'type="password" autocomplete="off"':'type="text"')+' spellcheck="false">'
        +(fl.example?'<div class="ex">example: <code>'+esc(fl.example)+'</code></div>':'')
        +'<div class="viol">does not match the expected shape shown in the example</div>';
    }
    box.appendChild(w);
  }
  box.addEventListener('input',()=>previews(c));previews(c);
  document.getElementById('msg').className='msg';
  document.getElementById('enable').innerHTML='';
  f.scrollIntoView({behavior:'smooth'});
}
function esc(s){return s.replace(/[&<>"]/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[m]))}
function deriveValue(c,fl){
  const d=fl.derive;if(!d)return null;
  const q=n=>{const el=document.querySelector('#fields input[name="'+n+'"]');return el?el.value.trim():''};
  if(d.from_field){
    const ovr=q(fl.name+'__override');
    if(ovr)return ovr;
    const src=q(d.from_field)||q(d.from_field+'__input');
    return src?d.template.replace('{value}',src):'';
  }
  let v=q(fl.name+'__input');
  if(!v)return '';
  if(d.lowercase)v=v.toLowerCase();
  if(d.strip_trailing_slash)v=v.replace(/\/+$/,'');
  return d.template.replace('{value}',v);
}
function previews(c){
  for(const fl of c.fields){
    if(!fl.derive)continue;
    const el=document.getElementById('prev-'+fl.name);if(!el)continue;
    const v=deriveValue(c,fl);
    el.innerHTML='&rarr; <code>'+(v?esc(v):'&hellip;')+'</code>'+(v?' <span class="opt">(saved as '+fl.name+')</span>':'');
  }
}
async function save(ev){
  ev.preventDefault();
  const c=CAT.connectors.find(x=>x.slug===CUR);
  const values={};let bad=false;
  for(const inp of document.querySelectorAll('#fields input')){
    const v=inp.value.trim(),pat=inp.dataset.pattern;
    inp.className='';const viol=inp.closest('.field').querySelector('.viol');viol&&(viol.style.display='none');
    if(v&&pat&&!(new RegExp(pat)).test(v)){inp.className='bad';viol&&(viol.style.display='block');bad=true}
    if(v&&!inp.name.includes('__'))values[inp.name]=v;
  }
  for(const fl of c.fields){
    if(!fl.derive)continue;
    const v=deriveValue(c,fl);
    if(v){
      if(fl.pattern&&!(new RegExp(fl.pattern)).test(v)){bad=true;const el=document.getElementById('prev-'+fl.name);el&&(el.innerHTML+=' <span style="color:var(--err)">derived value has the wrong shape</span>')}
      else values[fl.name]=v;
    }
  }
  const msg=document.getElementById('msg');
  if(bad){msg.className='msg err';msg.textContent='Fix the highlighted fields first.';return false}
  const missing=c.fields.filter(f=>f.required===true&&!values[f.name]).map(f=>(f.derive&&f.derive.input_label)||f.label);
  if(missing.length){msg.className='msg err';msg.textContent='Required: '+missing.join(', ');return false}
  const r=await fetch('/api/save',{method:'POST',headers:H,body:JSON.stringify({slug:CUR,values})});
  const j=await r.json().catch(()=>({}));
  if(!r.ok){msg.className='msg err';msg.textContent=j.error||('save failed ('+r.status+')');return false}
  msg.className='msg ok';msg.textContent='Saved '+j.vars+' value(s). A running connector reloads by itself within seconds.';
  document.getElementById('enable').innerHTML='If this connector is not running yet, enable it once from the operator machine:<br><code>docker compose -f compose.yml -f compose.secrets.yml --profile '+CUR+' up -d</code>';
  STATUS[CUR]={vars:Object.keys(values)};render();
  return false;
}
boot().catch(e=>{document.body.insertAdjacentHTML('afterbegin','<div style="background:#fdecea;color:#b42318;padding:12px 24px">Missing or wrong token. Open this page with ?token=... from the container log.</div>')});
</script></body></html>`
