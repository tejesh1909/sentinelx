// import {useEffect,useState,useCallback,ReactNode} from 'react'
// import {LayoutDashboard,Activity,ShieldAlert,Siren,Gauge,Bot,BarChart3,Plug,Settings as Cog,Search,Bell,LogOut} from 'lucide-react'
// import {ResponsiveContainer,PieChart,Pie,Cell,AreaChart,Area,BarChart,Bar,XAxis,YAxis,Tooltip,LineChart,Line,CartesianGrid} from 'recharts'

// // ---- api (tokens in localStorage: simple, but XSS-exposed; prefer httpOnly cookies for production) ----
// let tok:any=JSON.parse(localStorage.getItem('sx')||'{}')
// const save=(t:any)=>{tok=t;localStorage.setItem('sx',JSON.stringify(t))}
// async function api(path:string,opt:any={}):Promise<any>{
//   const go=()=>fetch('/api'+path,{...opt,headers:{...(opt.body&&!(opt.body instanceof FormData)?{'Content-Type':'application/json'}:{}),Authorization:`Bearer ${tok.access_token}`}})
//   let r=await go()
//   if(r.status===401&&tok.refresh_token&&!path.startsWith('/auth/')){
//     const rr=await fetch('/api/auth/refresh',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({refresh_token:tok.refresh_token})})
//     if(rr.ok){save(await rr.json());r=await go()}else{save({});location.reload()}}
//   if(!r.ok){const j=await r.json().catch(()=>({}));throw new Error(j.error?.message||r.statusText)}
//   return r.headers.get('content-type')?.includes('json')?r.json():r}
// function useApi(path:string){const[d,setD]=useState<any>(null),[e,setE]=useState(''),[l,setL]=useState(true)
//   const load=useCallback(()=>{setL(true);api(path).then(x=>{setD(x);setE('')}).catch(x=>setE(x.message)).finally(()=>setL(false))},[path]);useEffect(load,[load]);return{d,e,l,load}}

// // ---- ui kit ----
// const SEV:any={critical:'bg-red-500/20 text-red-300',high:'bg-orange-500/20 text-orange-300',medium:'bg-yellow-500/20 text-yellow-300',low:'bg-emerald-500/20 text-emerald-300'}
// const COL=['#8b5cf6','#06b6d4','#3b82f6','#f59e0b','#ef4444','#10b981']
// const Badge=({v}:any)=><span className={`px-2 py-0.5 rounded text-xs ${SEV[v]||'bg-slate-500/20 text-slate-300'}`}>{v}</span>
// const Card=({t,children,right}:any)=><section className="rounded-xl border border-white/10 bg-gradient-to-br from-white/5 to-transparent p-4"><div className="flex justify-between mb-3"><h3 className="font-medium text-slate-200">{t}</h3>{right}</div>{children}</section>
// const btn="px-3 py-1.5 rounded-lg bg-gradient-to-r from-violet-600 to-cyan-600 text-sm text-white disabled:opacity-50"
// const inp="bg-slate-900 border border-white/10 rounded-lg px-3 py-1.5 text-sm text-slate-100"
// const fmt=(s:string)=>s?new Date(s+(s.endsWith('Z')?'':'Z')).toLocaleString():''
// function Async({r,children}:{r:any,children:(d:any)=>ReactNode}){if(r.l&&!r.d)return<div className="space-y-2 animate-pulse">{[1,2,3].map(i=><div key={i} className="h-8 rounded bg-white/5"/>)}</div>;if(r.e)return<p className="text-red-400">Error: {r.e}</p>;return r.d?<>{children(r.d)}</>:null}
// function Table({cols,rows,onRow}:{cols:[string,(r:any)=>ReactNode][],rows:any[],onRow?:(r:any)=>void}){
//   if(!rows.length)return<p className="p-6 text-center text-slate-500">No data yet.</p>
//   return<div className="overflow-x-auto"><table className="w-full text-sm"><thead><tr className="text-left text-slate-400">{cols.map(c=><th key={c[0]} className="py-2 pr-3 font-normal">{c[0]}</th>)}</tr></thead>
//   <tbody>{rows.map((r,i)=><tr key={r.id||i} onClick={()=>onRow?.(r)} className={`border-t border-white/5 ${onRow?'cursor-pointer hover:bg-white/5':''}`}>{cols.map(c=><td key={c[0]} className="py-2 pr-3 align-top">{c[1](r)}</td>)}</tr>)}</tbody></table></div>}
// function Pager({d,set}:any){const last=Math.max(1,Math.ceil(d.total/d.size));return<div className="flex gap-2 items-center justify-end mt-3 text-sm text-slate-400"><button className={btn} disabled={d.page<=1} onClick={()=>set(d.page-1)}>Prev</button>Page {d.page}/{last} · {d.total} items<button className={btn} disabled={d.page>=last} onClick={()=>set(d.page+1)}>Next</button></div>}
// const Bars=({data,k='value',h=220}:any)=><ResponsiveContainer width="100%" height={h}><BarChart data={data} layout="vertical" margin={{left:30}}><XAxis type="number" stroke="#64748b"/><YAxis type="category" dataKey="name" width={140} stroke="#64748b" tick={{fontSize:11}}/><Tooltip contentStyle={{background:'#0f172a',border:'1px solid #334155'}}/><Bar dataKey={k} fill="#06b6d4"/></BarChart></ResponsiveContainer>
// const Pie_=({data}:any)=><ResponsiveContainer width="100%" height={220}><PieChart><Pie data={data} dataKey="value" nameKey="name" outerRadius={80} label>{data.map((_:any,i:number)=><Cell key={i} fill={COL[i%COL.length]}/>)}</Pie><Tooltip contentStyle={{background:'#0f172a',border:'1px solid #334155'}}/></PieChart></ResponsiveContainer>
// let pushToast:(m:string)=>void=()=>{}
// const Alert_=(m:string)=>pushToast(m)

// // ---- extras ----
// const report=async(id:string)=>{try{const b=await(await api(`/incidents/${id}/report`)).blob();window.open(URL.createObjectURL(b))}catch(e:any){Alert_(e.message)}}
// const lookup=async(ip:string)=>{try{const x=await api('/ip/'+ip);Alert_(`${ip}: ${x.geo||'no geo data'} · ${x.note}`)}catch(e:any){Alert_(e.message)}}
// function Chain({events,threats}:any){
//   const tm:any={};threats.forEach((t:any)=>(tm[t.event_id]=tm[t.event_id]||[]).push(t))
//   const nodes:any[]=[];events.forEach((e:any)=>{const k=[e.event_type,e.status,e.user,e.ip,e.resource].join('|');const l=nodes[nodes.length-1];if(l&&l.k===k&&e.status!=='success'){l.n++;l.th.push(...(tm[e.id]||[]))}else nodes.push({k,e,n:1,th:[...(tm[e.id]||[])]})})
//   const colr:any={success:'border-emerald-400',failure:'border-red-400',denied:'border-orange-400'}
//   if(!nodes.length)return<p className="text-slate-500">No events.</p>
//   return<div className="flex items-stretch overflow-x-auto pb-2">{nodes.map((x,i)=><div key={i} className="flex items-center"><div className={`w-44 shrink-0 rounded-lg border-2 ${colr[x.e.status]||'border-slate-500'} bg-slate-900 p-2 text-xs`}>
//     <div className="text-slate-500">{fmt(x.e.timestamp)}</div><div className="font-medium">{x.n>1?`${x.n}× `:''}{x.e.event_type} · {x.e.status}</div><div className="text-slate-400 truncate">{x.e.user||'-'} @ {x.e.ip||'-'}</div><div className="text-slate-400 truncate">{x.e.resource}</div>
//     {x.th.slice(0,2).map((t:any)=><div key={t.id} className="mt-1"><Badge v={t.severity}/> <span className="text-violet-300">{t.mitre?.id}</span></div>)}</div>{i<nodes.length-1&&<div className="w-6 h-0.5 shrink-0 bg-gradient-to-r from-violet-500 to-cyan-500"/>}</div>)}</div>}
// function Live({onSim}:any){const[items,setItems]=useState<any[]>([]),[on,setOn]=useState(false)
//   useEffect(()=>{const ac=new AbortController();(async()=>{try{const r=await fetch('/api/stream',{headers:{Authorization:`Bearer ${tok.access_token}`},signal:ac.signal});if(!r.ok||!r.body)return;setOn(true);const rd=r.body.getReader(),dec=new TextDecoder();let buf='';
//     for(;;){const{done,value}=await rd.read();if(done)break;buf+=dec.decode(value,{stream:true});const parts=buf.split('\n\n');buf=parts.pop()||'';for(const p of parts)if(p.startsWith('data: ')){const t=JSON.parse(p.slice(6));setItems(x=>[t,...x].slice(0,6));pushToast(`New ${t.severity} threat: ${t.category}`);onSim()}}}catch{}setOn(false)})();return()=>ac.abort()},[])
//   const sim=async()=>{try{await api('/simulate/attack',{method:'POST'});pushToast('Synthetic attack started – watch the live feed')}catch(e:any){Alert_(e.message)}}
//   return<Card t={<span><span className={`inline-block w-2 h-2 rounded-full mr-2 ${on?'bg-emerald-400':'bg-slate-600'}`}/>Live threat feed</span>} right={<button className={btn} onClick={sim}>Simulate attack</button>}>
//     {items.length?<ul className="text-sm space-y-1">{items.map(t=><li key={t.id}><Badge v={t.severity}/> {t.mitre?.id} {t.description}</li>)}</ul>:<p className="text-sm text-slate-500">Waiting for new threats… click “Simulate attack” for a synthetic demo scenario.</p>}</Card>}
// function Mitre(){const r=useApi('/mitre');return<Async r={r}>{d=><Card t="MITRE ATT&CK coverage (indicative mapping)"><div className="grid grid-cols-2 md:grid-cols-4 gap-2">{d.map((x:any)=><div key={x.rule_key} className={`rounded-lg p-3 text-xs border ${x.enabled?'border-violet-500/40':'border-white/10 opacity-50'}`} style={{background:`rgba(139,92,246,${Math.min(.5,x.detections/20)})`}}><div className="text-slate-400">{x.tactic}</div><div className="font-medium">{x.technique} {x.name}</div><div>{x.detections} detections</div></div>)}</div></Card>}</Async>}
// function Mfa({me,reload}:any){const[s,setS]=useState<any>(null),[c,setC]=useState('')
//   const setup=async()=>{try{setS(await api('/mfa/setup',{method:'POST'}))}catch(e:any){Alert_(e.message)}}
//   const act=async(p:string)=>{try{await api('/mfa/'+p,{method:'POST',body:JSON.stringify({code:c})});setS(null);setC('');reload();Alert_('MFA '+p+'d')}catch(e:any){Alert_(e.message)}}
//   return<Card t="Two-factor authentication (TOTP)">{me.mfa_enabled?<div className="flex gap-2"><input className={inp} placeholder="6-digit code" value={c} onChange={e=>setC(e.target.value)}/><button className={btn} onClick={()=>act('disable')}>Disable MFA</button></div>
//    :!s?<button className={btn} onClick={setup}>Set up MFA</button>:<div className="space-y-2 text-sm"><p>Add this secret to an authenticator app (Google Authenticator, Authy…):</p><code className="block break-all text-cyan-300">{s.secret}</code><p className="text-xs text-slate-500 break-all">{s.uri}</p><div className="flex gap-2"><input className={inp} placeholder="6-digit code" value={c} onChange={e=>setC(e.target.value)}/><button className={btn} onClick={()=>act('enable')}>Confirm & enable</button></div></div>}</Card>}

// // ---- pages ----
// function Overview(){const r=useApi('/dashboard');return<Async r={r}>{d=><div className="space-y-4"><Live onSim={r.load}/>
//   <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">{Object.entries(d.kpis).filter(([k])=>k!=='risk_level').map(([k,v]:any)=><Card key={k} t={k.replace(/_/g,' ')}><div className="text-2xl font-semibold">{v}{k==='risk_score'&&<span className="ml-2"><Badge v={d.kpis.risk_level}/></span>}</div></Card>)}</div>
//   <div className="grid lg:grid-cols-3 gap-4"><div className="lg:col-span-2"><Card t="Threat activity (14d)"><ResponsiveContainer width="100%" height={240}><AreaChart data={d.timeline}><CartesianGrid stroke="#1e293b"/><XAxis dataKey="day" stroke="#64748b" tick={{fontSize:11}}/><YAxis stroke="#64748b"/><Tooltip contentStyle={{background:'#0f172a',border:'1px solid #334155'}}/><Area dataKey="events" stroke="#8b5cf6" fill="#8b5cf633"/><Area dataKey="threats" stroke="#ef4444" fill="#ef444433"/></AreaChart></ResponsiveContainer></Card></div><Card t="Threat severity"><Pie_ data={d.severity}/></Card></div>
//   <div className="grid lg:grid-cols-3 gap-4"><Card t="Attack/event sources"><Bars data={d.sources}/></Card><Card t="Threat categories"><Bars data={d.categories}/></Card><Card t="Risk trend (avg score)"><ResponsiveContainer width="100%" height={220}><LineChart data={d.risk_trend}><CartesianGrid stroke="#1e293b"/><XAxis dataKey="day" stroke="#64748b" tick={{fontSize:11}}/><YAxis domain={[0,100]} stroke="#64748b"/><Tooltip contentStyle={{background:'#0f172a'}}/><Line dataKey="score" stroke="#06b6d4"/></LineChart></ResponsiveContainer></Card></div>
//   <div className="grid lg:grid-cols-2 gap-4"><Card t="Critical / high alerts"><Table rows={d.critical_alerts} cols={[['Severity',r=><Badge v={r.severity}/>],['Threat',r=>r.description],['Risk',r=>r.risk_score]]}/></Card><Card t="Recent events"><Table rows={d.recent_events} cols={[['Time',r=>fmt(r.timestamp)],['Type',r=>r.event_type],['User/IP',r=>r.user||r.ip],['Status',r=>r.status]]}/></Card></div></div>}</Async>}

// function Events({q0}:{q0:string}){const[f,setF]=useState<any>({q:q0,severity:'',source:'',page:1})
//   const r=useApi('/events?'+new URLSearchParams(Object.entries(f).filter(([,v])=>v) as any));const set=(k:string,v:any)=>setF({...f,[k]:v,page:k==='page'?v:1})
//   const up=async(e:any)=>{const fd=new FormData();fd.append('file',e.target.files[0]);try{const x=await api('/events/upload',{method:'POST',body:fd});Alert_(`Accepted ${x.accepted}, duplicates ${x.duplicates}, invalid ${x.invalid.length}, threats ${x.threats}`);r.load()}catch(er:any){Alert_(er.message)}e.target.value=''}
//   return<Card t="Security events" right={<label className={btn+' cursor-pointer'}>Upload JSON/CSV<input type="file" hidden accept=".json,.csv" onChange={up}/></label>}>
//   <div className="flex gap-2 mb-3 flex-wrap"><input className={inp} placeholder="Search user/IP/resource" value={f.q} onChange={e=>set('q',e.target.value)}/>
//   <select className={inp} value={f.severity} onChange={e=>set('severity',e.target.value)}><option value="">All severities</option>{['low','medium','high','critical'].map(s=><option key={s}>{s}</option>)}</select>
//   <select className={inp} value={f.source} onChange={e=>set('source',e.target.value)}><option value="">All sources</option>{['application','api_gateway','authentication','cloud','server'].map(s=><option key={s}>{s}</option>)}</select></div>
//   <Async r={r}>{d=><><Table rows={d.items} cols={[['Time',r=>fmt(r.timestamp)],['Source',r=>r.source],['Type',r=>r.event_type],['IP',r=>r.ip],['User',r=>r.user],['Resource',r=>r.resource],['Status',r=>r.status],['Sev',r=><Badge v={r.severity}/>]]}/><Pager d={d} set={(p:number)=>set('page',p)}/></>}</Async></Card>}

// function Threats(){const[p,setP]=useState(1),[sev,setSev]=useState('');const r=useApi(`/threats?page=${p}${sev?'&severity='+sev:''}`)
//   const mk=async(id:string)=>{try{await api(`/threats/${id}/incident`,{method:'POST'});r.load()}catch(e:any){Alert_(e.message)}}
//   return<Card t="Detected threats" right={<select className={inp} value={sev} onChange={e=>{setSev(e.target.value);setP(1)}}><option value="">All</option>{['low','medium','high','critical'].map(s=><option key={s}>{s}</option>)}</select>}>
//   <Async r={r}>{d=><><Table rows={d.items} cols={[['Severity',r=><Badge v={r.severity}/>],['Category',r=>r.category],['Description',r=>r.description],['MITRE',r=>r.mitre?<span title={r.mitre.name+' · '+r.mitre.tactic} className="text-violet-300">{r.mitre.id}</span>:''],['Conf.',r=>r.confidence],['Risk',r=>r.risk_score],['Detected',r=>fmt(r.detected_at)],['',r=>r.incident_id?<span className="text-cyan-400">In incident</span>:<button className={btn} onClick={()=>mk(r.id)}>Create incident</button>]]}/><Pager d={d} set={setP}/></>}</Async></Card>}

// function Incidents(){const[sel,setSel]=useState<string|null>(null),[st,setSt]=useState('');const r=useApi('/incidents?size=50'+(st?'&status='+st:''))
//   if(sel)return<IncidentView id={sel} back={()=>{setSel(null);r.load()}}/>
//   return<Card t="Incidents" right={<select className={inp} value={st} onChange={e=>setSt(e.target.value)}><option value="">All statuses</option>{['new','investigating','in_progress','resolved','closed'].map(s=><option key={s}>{s}</option>)}</select>}>
//   <Async r={r}>{d=><Table rows={d.items} onRow={x=>setSel(x.id)} cols={[['Risk',r=><><Badge v={r.risk_level}/> {r.risk_score}</>],['Title',r=>r.title],['Status',r=>r.status],['Priority',r=>r.priority],['Created',r=>fmt(r.created_at)]]}/>}</Async></Card>}
// function IncidentView({id,back}:any){const r=useApi('/incidents/'+id),u=useApi('/users-lite'),[note,setNote]=useState(''),[kind,setKind]=useState('note'),[ai,setAi]=useState<any>(null),[busy,setBusy]=useState(false)
//   const patch=async(b:any)=>{try{await api('/incidents/'+id,{method:'PATCH',body:JSON.stringify(b)});r.load()}catch(e:any){Alert_(e.message)}}
//   const post=async()=>{try{await api(`/incidents/${id}/notes`,{method:'POST',body:JSON.stringify({body:note,kind})});setNote('');r.load()}catch(e:any){Alert_(e.message)}}
//   const sum=async()=>{setBusy(true);try{setAi(await api('/ai/analyze',{method:'POST',body:JSON.stringify({incident_id:id,save_summary:true})}));r.load()}catch(e:any){Alert_(e.message)}setBusy(false)}
//   return<Async r={r}>{d=><div className="space-y-4"><button className="text-cyan-400 text-sm" onClick={back}>← All incidents</button>
//   <Card t={d.title} right={<span><Badge v={d.risk_level}/> {d.risk_score}/100</span>}>
//    <div className="flex gap-2 flex-wrap mb-3"><select className={inp} value={d.status} onChange={e=>patch({status:e.target.value})}>{['new','investigating','in_progress','resolved','closed'].map(s=><option key={s}>{s}</option>)}</select>
//    <select className={inp} value={d.priority} onChange={e=>patch({priority:e.target.value})}>{['low','medium','high','critical'].map(s=><option key={s}>{s}</option>)}</select>
//    <select className={inp} value={d.assignee_id||''} onChange={e=>patch({assignee_id:e.target.value||null})}><option value="">Unassigned</option>{(u.d||[]).map((x:any)=><option key={x.id} value={x.id}>{x.full_name}</option>)}</select>
//    <button className={btn} disabled={busy} onClick={sum}>{busy?'Analyzing…':'AI summary'}</button><button className={btn} onClick={()=>report(d.id)}>Open report</button></div>
//    {d.summary&&<p className="text-sm text-slate-300 mb-2">Summary: {d.summary}</p>}{d.risk&&<p className="text-xs text-slate-400">Why: {d.risk.explanation}</p>}
//    {ai&&<AIOut o={ai}/>}</Card>
//   <Card t="Correlated threats"><Table rows={d.threats} cols={[['Sev',r=><Badge v={r.severity}/>],['Category',r=>r.category],['Description',r=>r.description],['Risk',r=>r.risk_score]]}/></Card>
//   <Card t="Attack chain"><Chain events={d.events} threats={d.threats}/></Card>
//   <Card t="Recommended playbook (manual steps – nothing is executed automatically)">{d.playbooks.length?d.playbooks.map((p:any)=><div key={p.category} className="mb-2"><b className="text-violet-300 text-sm">{p.category.replace(/_/g,' ')}</b><ul className="list-disc ml-5 text-sm">{p.steps.map((s:string)=><li key={s}>{s}</li>)}</ul></div>):<p className="text-slate-500">None.</p>}</Card>
//   <Card t={`Related events (${d.events.length})`}><Table rows={d.events} cols={[['Time',r=>fmt(r.timestamp)],['Type',r=>r.event_type],['User',r=>r.user],['IP',r=>r.ip],['Resource',r=>r.resource],['Status',r=>r.status]]}/></Card>
//   <Card t="Activity history"><ul className="text-sm space-y-1 mb-3">{d.history.map((h:any)=><li key={h.id}><span className="text-slate-500">{fmt(h.at)}</span> <b className="text-violet-300">{h.kind}</b> · {h.author}: {h.body}</li>)}</ul>
//    <div className="flex gap-2"><select className={inp} value={kind} onChange={e=>setKind(e.target.value)}><option value="note">Note</option><option value="remediation">Remediation</option></select><input className={inp+' flex-1'} value={note} onChange={e=>setNote(e.target.value)} placeholder="Add investigation note or remediation action"/><button className={btn} disabled={!note} onClick={post}>Add</button></div></Card></div>}</Async>}
// function AIOut({o}:any){return<div className="text-sm space-y-2 mt-3 border-t border-white/10 pt-3"><p className="text-xs text-slate-500">Source: {o.source==='llm'?'LLM':'deterministic fallback (LLM unavailable or not configured)'}</p>
//   <p><b>Threat summary:</b> {o.summary}</p><p><b>Potential impact:</b> {o.impact}</p><div><b>Supporting evidence:</b><ul className="list-disc ml-5">{o.evidence.map((e:string,i:number)=><li key={i}>{e}</li>)}</ul></div><p><b>Risk explanation:</b> {o.risk_explanation}</p><div><b>Recommended actions (not executed):</b><ul className="list-disc ml-5">{o.actions.map((e:string,i:number)=><li key={i}>{e}</li>)}</ul></div>{o.answer&&<p><b>Answer:</b> {o.answer}</p>}</div>}

// function Risk(){const r=useApi('/risk');return<Async r={r}>{d=><div className="space-y-4"><Mitre/><Card t="Scoring model (configurable via RISK_CONFIG_JSON)"><p className="text-sm text-slate-400">Levels: {Object.entries(d.levels).map(([k,v])=>`${k} ${v}`).join(' · ')}</p><pre className="text-xs text-slate-400 overflow-x-auto mt-2">{JSON.stringify(d.config,null,1)}</pre></Card>
//   <Card t="Highest risk assessments"><Table rows={d.items} cols={[['Score',r=><><Badge v={r.level}/> {r.score}</>],['Type',r=>r.kind],['Subject',r=>r.label],['Why',r=><span className="text-xs text-slate-400">{r.explanation}</span>]]}/></Card></div>}</Async>}

// function Assistant(){const inc=useApi('/incidents?size=100'),[id,setId]=useState(''),[q,setQ]=useState(''),[o,setO]=useState<any>(null),[busy,setBusy]=useState(false)
//   const ask=async()=>{setBusy(true);try{setO(await api('/ai/analyze',{method:'POST',body:JSON.stringify({incident_id:id||null,question:q||null})}))}catch(e:any){Alert_(e.message)}setBusy(false)}
//   return<Card t="AI Security Assistant (read-only: explains and recommends, never acts)"><div className="flex gap-2 flex-wrap"><select className={inp} value={id} onChange={e=>setId(e.target.value)}><option value="">All data (recent events)</option>{inc.d?.items.map((i:any)=><option key={i.id} value={i.id}>{i.title.slice(0,70)}</option>)}</select>
//   <input className={inp+' flex-1 min-w-60'} value={q} onChange={e=>setQ(e.target.value)} placeholder="e.g. Why was this incident marked critical?"/><button className={btn} disabled={busy} onClick={ask}>{busy?'Thinking…':'Ask'}</button></div>{o&&<AIOut o={o}/>}</Card>}

// function Analytics(){const[f,setF]=useState<any>({date_from:'',date_to:'',severity:'',source:''});const qs=new URLSearchParams(Object.entries(f).filter(([,v])=>v) as any).toString();const r=useApi('/analytics?'+qs)
//   const exp=async(kind:string)=>{try{const b=await(await api(`/analytics/export.csv?kind=${kind}&${qs}`)).blob();const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download=kind+'.csv';a.click()}catch(e:any){Alert_(e.message)}}
//   return<div className="space-y-4"><Card t="Filters & export"><div className="flex gap-2 flex-wrap"><input type="date" className={inp} value={f.date_from} onChange={e=>setF({...f,date_from:e.target.value})}/><input type="date" className={inp} value={f.date_to} onChange={e=>setF({...f,date_to:e.target.value})}/>
//   <select className={inp} value={f.severity} onChange={e=>setF({...f,severity:e.target.value})}><option value="">All severities</option>{['low','medium','high','critical'].map(s=><option key={s}>{s}</option>)}</select>
//   <select className={inp} value={f.source} onChange={e=>setF({...f,source:e.target.value})}><option value="">All sources</option>{['application','api_gateway','authentication','cloud','server'].map(s=><option key={s}>{s}</option>)}</select>
//   {['events','threats','incidents'].map(k=><button key={k} className={btn} onClick={()=>exp(k)}>Export {k} CSV</button>)}</div></Card>
//   <Async r={r}>{d=><div className="grid lg:grid-cols-2 gap-4"><Card t="Daily event volume"><ResponsiveContainer width="100%" height={220}><BarChart data={d.daily}><XAxis dataKey="day" stroke="#64748b" tick={{fontSize:11}}/><YAxis stroke="#64748b"/><Tooltip contentStyle={{background:'#0f172a'}}/><Bar dataKey="events" fill="#8b5cf6"/></BarChart></ResponsiveContainer></Card>
//   <Card t="Severity distribution"><Pie_ data={d.severity}/></Card><Card t="Top suspicious IPs"><Bars data={d.top_ips}/><Table rows={d.top_ips} cols={[['IP',r=>r.name],['Hits',r=>r.value],['',r=><button className={btn} onClick={()=>lookup(r.name)}>Lookup</button>]]}/></Card><Card t="Most affected resources"><Bars data={d.resources}/></Card><Card t="Threat categories"><Bars data={d.categories}/></Card>
//   <Card t="Incident resolution"><Bars data={d.incident_status} h={150}/><p className="text-sm text-slate-400">Resolved: {d.resolution.resolved_count} · avg time to resolve: {d.resolution.avg_hours??'n/a'} h</p></Card></div>}</Async></div>}

// function Integrations(){const r=useApi('/integrations');const sim=async()=>{try{const x=await api('/integrations/cloudtrail/simulate',{method:'POST'});Alert_(`SIMULATED CloudTrail ingest: ${x.accepted} events, ${x.threats} threats`);r.load()}catch(e:any){Alert_(e.message)}}
//   return<Async r={r}>{d=><div className="grid md:grid-cols-2 gap-4">{d.map((i:any)=><Card key={i.id} t={i.name} right={<span className={`text-xs ${i.simulated?'text-yellow-300':'text-emerald-300'}`}>{i.simulated?'SIMULATED':i.status}</span>}><p className="text-sm text-slate-400 mb-3">{i.description}</p>{i.kind==='cloud'&&<button className={btn} onClick={sim}>Run simulated ingest</button>}<p className="text-xs text-slate-500 mt-2">Last sync: {i.last_sync?fmt(i.last_sync):'never'}</p></Card>)}</div>}</Async>}

// function Settings({me,reload}:any){const[n,setN]=useState(me.full_name),[cp,setCp]=useState(''),[np,setNp]=useState('')
//   const sv=async()=>{try{await api('/me',{method:'PATCH',body:JSON.stringify({full_name:n,...(np?{current_password:cp,new_password:np}:{})})});setCp('');setNp('');reload();Alert_('Saved')}catch(e:any){Alert_(e.message)}}
//   return<div className="space-y-4">{me.must_change_password&&<p className="p-3 rounded bg-yellow-500/10 text-yellow-300 text-sm">You are using a default demo password. Change it below before any production use.</p>}
//   <Card t="Profile"><div className="flex gap-2 flex-wrap"><input className={inp} value={n} onChange={e=>setN(e.target.value)}/><input type="password" className={inp} placeholder="Current password" value={cp} onChange={e=>setCp(e.target.value)}/><input type="password" className={inp} placeholder="New password (10+ chars)" value={np} onChange={e=>setNp(e.target.value)}/><button className={btn} onClick={sv}>Save</button></div><p className="text-xs text-slate-500 mt-2">{me.email} · role: {me.role}</p></Card>
//   <Mfa me={me} reload={reload}/>{me.role==='admin'&&<Admin/>}</div>}
// function Admin(){const u=useApi('/users'),ru=useApi('/rules'),au=useApi('/audit')
//   const pu=async(id:string,b:any)=>{try{await api('/users/'+id,{method:'PATCH',body:JSON.stringify(b)});u.load()}catch(e:any){Alert_(e.message)}}
//   const pr=async(id:number,b:any)=>{try{await api('/rules/'+id,{method:'PATCH',body:JSON.stringify(b)});ru.load()}catch(e:any){Alert_(e.message)}}
//   return<><Card t="Users (admin)"><Async r={u}>{d=><Table rows={d} cols={[['Name',r=>r.full_name],['Email',r=>r.email],['Role',r=><select className={inp} value={r.role} onChange={e=>pu(r.id,{role:e.target.value})}><option>admin</option><option>analyst</option></select>],['Active',r=><input type="checkbox" checked={r.is_active} onChange={e=>pu(r.id,{is_active:e.target.checked})}/>]]}/>}</Async></Card>
//   <Card t="Detection rules (admin)"><Async r={ru}>{d=><Table rows={d} cols={[['On',r=><input type="checkbox" checked={r.enabled} onChange={e=>pr(r.id,{enabled:e.target.checked})}/>],['Rule',r=><><b>{r.name}</b><div className="text-xs text-slate-500">{r.description}</div></>],['Params',r=><RuleParams r={r} save={(p:any)=>pr(r.id,{params:p})}/>]]}/>}</Async></Card>
//   <Card t="Audit log"><Async r={au}>{d=><Table rows={d} cols={[['At',r=>fmt(r.at)],['Action',r=>r.action],['Target',r=>r.target],['IP',r=>r.ip]]}/>}</Async></Card></>}
// function RuleParams({r,save}:any){const[t,setT]=useState(JSON.stringify(r.params));return<div className="flex gap-1"><input className={inp+' w-72 font-mono text-xs'} value={t} onChange={e=>setT(e.target.value)}/><button className={btn} onClick={()=>{try{save(JSON.parse(t))}catch{Alert_('Invalid JSON')}}}>Save</button></div>}

// // ---- shell ----
// const NAV:[string,any][]=[['Overview',LayoutDashboard],['Security Events',Activity],['Threat Detection',ShieldAlert],['Incidents',Siren],['Risk Analysis',Gauge],['AI Security Assistant',Bot],['Analytics & Reports',BarChart3],['Integrations',Plug],['Settings',Cog]]
// function Auth({done}:any){const[reg,setReg]=useState(false),[f,setF]=useState({email:'',password:'',full_name:'',otp:''}),[e,setE]=useState(''),[needOtp,setNeed]=useState(false)
//   const go=async()=>{try{if(reg)await api('/auth/register',{method:'POST',body:JSON.stringify(f)});const t=await api('/auth/login',{method:'POST',body:JSON.stringify({email:f.email,password:f.password,otp:f.otp||null})});save(t);done()}catch(x:any){if(x.message==='MFA code required')setNeed(true);setE(x.message)}}
//   return<div className="min-h-screen grid place-items-center"><div className="w-80 space-y-3 rounded-xl border border-white/10 p-6 bg-slate-900/60 shadow-[0_0_60px_#8b5cf633]"><h1 className="text-2xl font-bold bg-gradient-to-r from-violet-400 to-cyan-400 bg-clip-text text-transparent">SentinelX</h1><p className="text-xs text-slate-400">Unified Security Intelligence Platform</p>
//   {reg&&<input className={inp+' w-full'} placeholder="Full name" value={f.full_name} onChange={x=>setF({...f,full_name:x.target.value})}/>}<input className={inp+' w-full'} placeholder="Email" value={f.email} onChange={x=>setF({...f,email:x.target.value})}/><input type="password" className={inp+' w-full'} placeholder="Password" value={f.password} onChange={x=>setF({...f,password:x.target.value})} onKeyDown={x=>x.key==='Enter'&&go()}/>
//   {needOtp&&<input className={inp+' w-full'} placeholder="Authenticator code" value={f.otp} onChange={x=>setF({...f,otp:x.target.value})}/>}{e&&<p className="text-red-400 text-sm">{e}</p>}<button className={btn+' w-full'} onClick={go}>{reg?'Create account':'Sign in'}</button><button className="text-xs text-slate-400" onClick={()=>setReg(!reg)}>{reg?'Have an account? Sign in':'Create analyst account'}</button></div></div>}
// export default function App(){const[auth,setAuth]=useState(!!tok.access_token),[page,setPage]=useState(0),[toasts,setToasts]=useState<string[]>([]),[light,setLight]=useState(localStorage.getItem('sxl')==='1'),[q,setQ]=useState(''),[gs,setGs]=useState(''),[bell,setBell]=useState(false),me=useApi('/me'),al=useApi('/threats?size=5&min_severity=high')
//   useEffect(()=>{if(auth)me.load()},[auth])
//   useEffect(()=>{pushToast=(m:string)=>{setToasts(t=>[...t,m]);setTimeout(()=>setToasts(t=>t.slice(1)),5000)}},[])
//   useEffect(()=>{document.documentElement.classList.toggle('light',light);localStorage.setItem('sxl',light?'1':'0')},[light])
//   useEffect(()=>{const k=(e:KeyboardEvent)=>{const el=e.target as HTMLElement;if(['INPUT','SELECT','TEXTAREA'].includes(el.tagName))return;if(e.key==='/'){e.preventDefault();document.getElementById('gsearch')?.focus()}else if(/^[1-9]$/.test(e.key))setPage(+e.key-1)};window.addEventListener('keydown',k);return()=>window.removeEventListener('keydown',k)},[])
//   if(!auth)return<Auth done={()=>setAuth(true)}/>
//   const out=async()=>{await api('/auth/logout',{method:'POST',body:JSON.stringify({refresh_token:tok.refresh_token})}).catch(()=>{});save({});setAuth(false)}
//   const P=[<Overview/>,<Events key={q} q0={q}/>,<Threats/>,<Incidents/>,<Risk/>,<Assistant/>,<Analytics/>,<Integrations/>,me.d&&<Settings me={me.d} reload={me.load}/>]
//   return<div className="min-h-screen flex"><aside className="w-56 shrink-0 border-r border-white/10 p-3 hidden md:block bg-[#0a0e1c]"><div className="text-xl font-bold mb-5 px-2 bg-gradient-to-r from-violet-400 to-cyan-400 bg-clip-text text-transparent">SentinelX</div>
//    {NAV.map(([n,I],i)=><button key={n} onClick={()=>setPage(i)} className={`w-full flex items-center gap-2 px-3 py-2 rounded-lg text-sm mb-1 ${page===i?'bg-violet-600/30 text-white':'text-slate-400 hover:bg-white/5'}`}><I size={16}/>{n}</button>)}</aside>
//   <main className="flex-1 min-w-0"><header className="flex items-center gap-3 p-3 border-b border-white/10"><select className={inp+' md:hidden'} value={page} onChange={e=>setPage(+e.target.value)}>{NAV.map(([n],i)=><option key={n} value={i}>{n}</option>)}</select>
//    <form className="flex-1 max-w-md relative" onSubmit={e=>{e.preventDefault();setQ(gs);setPage(1)}}><Search size={14} className="absolute left-3 top-2.5 text-slate-500"/><input id="gsearch" className={inp+' w-full pl-8'} placeholder="Search events (user, IP, resource)…" value={gs} onChange={e=>setGs(e.target.value)}/></form>
//    <div className="relative"><button onClick={()=>{setBell(!bell);al.load()}} className="p-2 rounded hover:bg-white/5"><Bell size={18}/></button>{bell&&<div className="absolute right-0 mt-2 w-80 z-10 rounded-xl border border-white/10 bg-slate-900 p-3 text-sm space-y-2">{al.d?.items.length?al.d.items.map((t:any)=><div key={t.id}><Badge v={t.severity}/> {t.description}</div>):<p className="text-slate-500">No high-severity alerts.</p>}</div>}</div>
//    <span className="text-sm text-slate-400 hidden sm:block">{me.d?.full_name} · {me.d?.role}</span><button onClick={()=>setLight(!light)} title="Toggle theme" className="p-2 rounded hover:bg-white/5 text-sm">{light?'🌙':'☀️'}</button><button onClick={out} title="Sign out" className="p-2 rounded hover:bg-white/5"><LogOut size={18}/></button></header>
//    <div className="p-4">{P[page]}</div></main><div className="fixed bottom-4 right-4 space-y-2 z-50">{toasts.map((t,i)=><div key={i} className="rounded-lg border border-cyan-500/30 bg-slate-900 px-4 py-2 text-sm shadow-lg max-w-sm">{t}</div>)}</div></div>}
import {useEffect,useState,useCallback,ReactNode} from 'react'
import {LayoutDashboard,Activity,ShieldAlert,Siren,Gauge,Bot,BarChart3,Plug,Settings as Cog,Search,Bell,LogOut} from 'lucide-react'
import {ResponsiveContainer,PieChart,Pie,Cell,AreaChart,Area,BarChart,Bar,XAxis,YAxis,Tooltip,LineChart,Line,CartesianGrid} from 'recharts'

// ---- api (tokens in localStorage: simple, but XSS-exposed; prefer httpOnly cookies for production) ----
const API_BASE = ((import.meta as any).env?.VITE_API_URL || '').replace(/\/$/, '')
let tok:any=JSON.parse(localStorage.getItem('sx')||'{}')
const save=(t:any)=>{tok=t;localStorage.setItem('sx',JSON.stringify(t))}
async function api(path:string,opt:any={}):Promise<any>{
  const go=()=>fetch(`${API_BASE}/api${path}`,{...opt,headers:{...(opt.body&&!(opt.body instanceof FormData)?{'Content-Type':'application/json'}:{}),Authorization:`Bearer ${tok.access_token}`}})
  let r=await go()
  if(r.status===401&&tok.refresh_token&&!path.startsWith('/auth/')){
    const rr=await fetch(`${API_BASE}/api/auth/refresh`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({refresh_token:tok.refresh_token})})
    if(rr.ok){save(await rr.json());r=await go()}else{save({});location.reload()}}
  if(!r.ok){const j=await r.json().catch(()=>({}));throw new Error(j.error?.message||r.statusText)}
  return r.headers.get('content-type')?.includes('json')?r.json():r}
function useApi(path:string){const[d,setD]=useState<any>(null),[e,setE]=useState(''),[l,setL]=useState(true)
  const load=useCallback(()=>{setL(true);api(path).then(x=>{setD(x);setE('')}).catch(x=>setE(x.message)).finally(()=>setL(false))},[path]);useEffect(load,[load]);return{d,e,l,load}}

// ---- ui kit ----
const SEV:any={critical:'bg-red-500/20 text-red-300',high:'bg-orange-500/20 text-orange-300',medium:'bg-yellow-500/20 text-yellow-300',low:'bg-emerald-500/20 text-emerald-300'}
const COL=['#8b5cf6','#06b6d4','#3b82f6','#f59e0b','#ef4444','#10b981']
const Badge=({v}:any)=><span className={`px-2 py-0.5 rounded text-xs ${SEV[v]||'bg-slate-500/20 text-slate-300'}`}>{v}</span>
const Card=({t,children,right}:any)=><section className="rounded-xl border border-white/10 bg-gradient-to-br from-white/5 to-transparent p-4"><div className="flex justify-between mb-3"><h3 className="font-medium text-slate-200">{t}</h3>{right}</div>{children}</section>
const btn="px-3 py-1.5 rounded-lg bg-gradient-to-r from-violet-600 to-cyan-600 text-sm text-white disabled:opacity-50"
const inp="bg-slate-900 border border-white/10 rounded-lg px-3 py-1.5 text-sm text-slate-100"
const fmt=(s:string)=>s?new Date(s+(s.endsWith('Z')?'':'Z')).toLocaleString():''
function Async({r,children}:{r:any,children:(d:any)=>ReactNode}){if(r.l&&!r.d)return<div className="space-y-2 animate-pulse">{[1,2,3].map(i=><div key={i} className="h-8 rounded bg-white/5"/>)}</div>;if(r.e)return<p className="text-red-400">Error: {r.e}</p>;return r.d?<>{children(r.d)}</>:null}
function Table({cols,rows,onRow}:{cols:[string,(r:any)=>ReactNode][],rows:any[],onRow?:(r:any)=>void}){
  if(!rows.length)return<p className="p-6 text-center text-slate-500">No data yet.</p>
  return<div className="overflow-x-auto"><table className="w-full text-sm"><thead><tr className="text-left text-slate-400">{cols.map(c=><th key={c[0]} className="py-2 pr-3 font-normal">{c[0]}</th>)}</tr></thead>
  <tbody>{rows.map((r,i)=><tr key={r.id||i} onClick={()=>onRow?.(r)} className={`border-t border-white/5 ${onRow?'cursor-pointer hover:bg-white/5':''}`}>{cols.map(c=><td key={c[0]} className="py-2 pr-3 align-top">{c[1](r)}</td>)}</tr>)}</tbody></table></div>}
function Pager({d,set}:any){const last=Math.max(1,Math.ceil(d.total/d.size));return<div className="flex gap-2 items-center justify-end mt-3 text-sm text-slate-400"><button className={btn} disabled={d.page<=1} onClick={()=>set(d.page-1)}>Prev</button>Page {d.page}/{last} · {d.total} items<button className={btn} disabled={d.page>=last} onClick={()=>set(d.page+1)}>Next</button></div>}
const Bars=({data,k='value',h=220}:any)=><ResponsiveContainer width="100%" height={h}><BarChart data={data} layout="vertical" margin={{left:30}}><XAxis type="number" stroke="#64748b"/><YAxis type="category" dataKey="name" width={140} stroke="#64748b" tick={{fontSize:11}}/><Tooltip contentStyle={{background:'#0f172a',border:'1px solid #334155'}}/><Bar dataKey={k} fill="#06b6d4"/></BarChart></ResponsiveContainer>
const Pie_=({data}:any)=><ResponsiveContainer width="100%" height={220}><PieChart><Pie data={data} dataKey="value" nameKey="name" outerRadius={80} label>{data.map((_:any,i:number)=><Cell key={i} fill={COL[i%COL.length]}/>)}</Pie><Tooltip contentStyle={{background:'#0f172a',border:'1px solid #334155'}}/></PieChart></ResponsiveContainer>
let pushToast:(m:string)=>void=()=>{}
const Alert_=(m:string)=>pushToast(m)

// ---- extras ----
const report=async(id:string)=>{try{const b=await(await api(`/incidents/${id}/report`)).blob();window.open(URL.createObjectURL(b))}catch(e:any){Alert_(e.message)}}
const lookup=async(ip:string)=>{try{const x=await api('/ip/'+ip);Alert_(`${ip}: ${x.geo||'no geo data'} · ${x.note}`)}catch(e:any){Alert_(e.message)}}
function Chain({events,threats}:any){
  const tm:any={};threats.forEach((t:any)=>(tm[t.event_id]=tm[t.event_id]||[]).push(t))
  const nodes:any[]=[];events.forEach((e:any)=>{const k=[e.event_type,e.status,e.user,e.ip,e.resource].join('|');const l=nodes[nodes.length-1];if(l&&l.k===k&&e.status!=='success'){l.n++;l.th.push(...(tm[e.id]||[]))}else nodes.push({k,e,n:1,th:[...(tm[e.id]||[])]})})
  const colr:any={success:'border-emerald-400',failure:'border-red-400',denied:'border-orange-400'}
  if(!nodes.length)return<p className="text-slate-500">No events.</p>
  return<div className="flex items-stretch overflow-x-auto pb-2">{nodes.map((x,i)=><div key={i} className="flex items-center"><div className={`w-44 shrink-0 rounded-lg border-2 ${colr[x.e.status]||'border-slate-500'} bg-slate-900 p-2 text-xs`}>
    <div className="text-slate-500">{fmt(x.e.timestamp)}</div><div className="font-medium">{x.n>1?`${x.n}× `:''}{x.e.event_type} · {x.e.status}</div><div className="text-slate-400 truncate">{x.e.user||'-'} @ {x.e.ip||'-'}</div><div className="text-slate-400 truncate">{x.e.resource}</div>
    {x.th.slice(0,2).map((t:any)=><div key={t.id} className="mt-1"><Badge v={t.severity}/> <span className="text-violet-300">{t.mitre?.id}</span></div>)}</div>{i<nodes.length-1&&<div className="w-6 h-0.5 shrink-0 bg-gradient-to-r from-violet-500 to-cyan-500"/>}</div>)}</div>}
function Live({onSim}:any){const[items,setItems]=useState<any[]>([]),[on,setOn]=useState(false)
  useEffect(()=>{const ac=new AbortController();(async()=>{try{const r=await fetch(`${API_BASE}/api/stream`,{headers:{Authorization:`Bearer ${tok.access_token}`},signal:ac.signal});if(!r.ok||!r.body)return;setOn(true);const rd=r.body.getReader(),dec=new TextDecoder();let buf='';
    for(;;){const{done,value}=await rd.read();if(done)break;buf+=dec.decode(value,{stream:true});const parts=buf.split('\n\n');buf=parts.pop()||'';for(const p of parts)if(p.startsWith('data: ')){const t=JSON.parse(p.slice(6));setItems(x=>[t,...x].slice(0,6));pushToast(`New ${t.severity} threat: ${t.category}`);onSim()}}}catch{}setOn(false)})();return()=>ac.abort()},[])
  const sim=async()=>{try{await api('/simulate/attack',{method:'POST'});pushToast('Synthetic attack started – watch the live feed')}catch(e:any){Alert_(e.message)}}
  return<Card t={<span><span className={`inline-block w-2 h-2 rounded-full mr-2 ${on?'bg-emerald-400':'bg-slate-600'}`}/>Live threat feed</span>} right={<button className={btn} onClick={sim}>Simulate attack</button>}>
    {items.length?<ul className="text-sm space-y-1">{items.map(t=><li key={t.id}><Badge v={t.severity}/> {t.mitre?.id} {t.description}</li>)}</ul>:<p className="text-sm text-slate-500">Waiting for new threats… click “Simulate attack” for a synthetic demo scenario.</p>}</Card>}
function Mitre(){const r=useApi('/mitre');return<Async r={r}>{d=><Card t="MITRE ATT&CK coverage (indicative mapping)"><div className="grid grid-cols-2 md:grid-cols-4 gap-2">{d.map((x:any)=><div key={x.rule_key} className={`rounded-lg p-3 text-xs border ${x.enabled?'border-violet-500/40':'border-white/10 opacity-50'}`} style={{background:`rgba(139,92,246,${Math.min(.5,x.detections/20)})`}}><div className="text-slate-400">{x.tactic}</div><div className="font-medium">{x.technique} {x.name}</div><div>{x.detections} detections</div></div>)}</div></Card>}</Async>}
function Mfa({me,reload}:any){const[s,setS]=useState<any>(null),[c,setC]=useState('')
  const setup=async()=>{try{setS(await api('/mfa/setup',{method:'POST'}))}catch(e:any){Alert_(e.message)}}
  const act=async(p:string)=>{try{await api('/mfa/'+p,{method:'POST',body:JSON.stringify({code:c})});setS(null);setC('');reload();Alert_('MFA '+p+'d')}catch(e:any){Alert_(e.message)}}
  return<Card t="Two-factor authentication (TOTP)">{me.mfa_enabled?<div className="flex gap-2"><input className={inp} placeholder="6-digit code" value={c} onChange={e=>setC(e.target.value)}/><button className={btn} onClick={()=>act('disable')}>Disable MFA</button></div>
   :!s?<button className={btn} onClick={setup}>Set up MFA</button>:<div className="space-y-2 text-sm"><p>Add this secret to an authenticator app (Google Authenticator, Authy…):</p><code className="block break-all text-cyan-300">{s.secret}</code><p className="text-xs text-slate-500 break-all">{s.uri}</p><div className="flex gap-2"><input className={inp} placeholder="6-digit code" value={c} onChange={e=>setC(e.target.value)}/><button className={btn} onClick={()=>act('enable')}>Confirm & enable</button></div></div>}</Card>}

// ---- pages ----
function Overview(){const r=useApi('/dashboard');return<Async r={r}>{d=><div className="space-y-4"><Live onSim={r.load}/>
  <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">{Object.entries(d.kpis).filter(([k])=>k!=='risk_level').map(([k,v]:any)=><Card key={k} t={k.replace(/_/g,' ')}><div className="text-2xl font-semibold">{v}{k==='risk_score'&&<span className="ml-2"><Badge v={d.kpis.risk_level}/></span>}</div></Card>)}</div>
  <div className="grid lg:grid-cols-3 gap-4"><div className="lg:col-span-2"><Card t="Threat activity (14d)"><ResponsiveContainer width="100%" height={240}><AreaChart data={d.timeline}><CartesianGrid stroke="#1e293b"/><XAxis dataKey="day" stroke="#64748b" tick={{fontSize:11}}/><YAxis stroke="#64748b"/><Tooltip contentStyle={{background:'#0f172a',border:'1px solid #334155'}}/><Area dataKey="events" stroke="#8b5cf6" fill="#8b5cf633"/><Area dataKey="threats" stroke="#ef4444" fill="#ef444433"/></AreaChart></ResponsiveContainer></Card></div><Card t="Threat severity"><Pie_ data={d.severity}/></Card></div>
  <div className="grid lg:grid-cols-3 gap-4"><Card t="Attack/event sources"><Bars data={d.sources}/></Card><Card t="Threat categories"><Bars data={d.categories}/></Card><Card t="Risk trend (avg score)"><ResponsiveContainer width="100%" height={220}><LineChart data={d.risk_trend}><CartesianGrid stroke="#1e293b"/><XAxis dataKey="day" stroke="#64748b" tick={{fontSize:11}}/><YAxis domain={[0,100]} stroke="#64748b"/><Tooltip contentStyle={{background:'#0f172a'}}/><Line dataKey="score" stroke="#06b6d4"/></LineChart></ResponsiveContainer></Card></div>
  <div className="grid lg:grid-cols-2 gap-4"><Card t="Critical / high alerts"><Table rows={d.critical_alerts} cols={[['Severity',r=><Badge v={r.severity}/>],['Threat',r=>r.description],['Risk',r=>r.risk_score]]}/></Card><Card t="Recent events"><Table rows={d.recent_events} cols={[['Time',r=>fmt(r.timestamp)],['Type',r=>r.event_type],['User/IP',r=>r.user||r.ip],['Status',r=>r.status]]}/></Card></div></div>}</Async>}

function Events({q0}:{q0:string}){const[f,setF]=useState<any>({q:q0,severity:'',source:'',page:1})
  const r=useApi('/events?'+new URLSearchParams(Object.entries(f).filter(([,v])=>v) as any));const set=(k:string,v:any)=>setF({...f,[k]:v,page:k==='page'?v:1})
  const up=async(e:any)=>{const fd=new FormData();fd.append('file',e.target.files[0]);try{const x=await api('/events/upload',{method:'POST',body:fd});Alert_(`Accepted ${x.accepted}, duplicates ${x.duplicates}, invalid ${x.invalid.length}, threats ${x.threats}`);r.load()}catch(er:any){Alert_(er.message)}e.target.value=''}
  return<Card t="Security events" right={<label className={btn+' cursor-pointer'}>Upload JSON/CSV<input type="file" hidden accept=".json,.csv" onChange={up}/></label>}>
  <div className="flex gap-2 mb-3 flex-wrap"><input className={inp} placeholder="Search user/IP/resource" value={f.q} onChange={e=>set('q',e.target.value)}/>
  <select className={inp} value={f.severity} onChange={e=>set('severity',e.target.value)}><option value="">All severities</option>{['low','medium','high','critical'].map(s=><option key={s}>{s}</option>)}</select>
  <select className={inp} value={f.source} onChange={e=>set('source',e.target.value)}><option value="">All sources</option>{['application','api_gateway','authentication','cloud','server'].map(s=><option key={s}>{s}</option>)}</select></div>
  <Async r={r}>{d=><><Table rows={d.items} cols={[['Time',r=>fmt(r.timestamp)],['Source',r=>r.source],['Type',r=>r.event_type],['IP',r=>r.ip],['User',r=>r.user],['Resource',r=>r.resource],['Status',r=>r.status],['Sev',r=><Badge v={r.severity}/>]]}/><Pager d={d} set={(p:number)=>set('page',p)}/></>}</Async></Card>}

function Threats(){const[p,setP]=useState(1),[sev,setSev]=useState('');const r=useApi(`/threats?page=${p}${sev?'&severity='+sev:''}`)
  const mk=async(id:string)=>{try{await api(`/threats/${id}/incident`,{method:'POST'});r.load()}catch(e:any){Alert_(e.message)}}
  return<Card t="Detected threats" right={<select className={inp} value={sev} onChange={e=>{setSev(e.target.value);setP(1)}}><option value="">All</option>{['low','medium','high','critical'].map(s=><option key={s}>{s}</option>)}</select>}>
  <Async r={r}>{d=><><Table rows={d.items} cols={[['Severity',r=><Badge v={r.severity}/>],['Category',r=>r.category],['Description',r=>r.description],['MITRE',r=>r.mitre?<span title={r.mitre.name+' · '+r.mitre.tactic} className="text-violet-300">{r.mitre.id}</span>:''],['Conf.',r=>r.confidence],['Risk',r=>r.risk_score],['Detected',r=>fmt(r.detected_at)],['',r=>r.incident_id?<span className="text-cyan-400">In incident</span>:<button className={btn} onClick={()=>mk(r.id)}>Create incident</button>]]}/><Pager d={d} set={setP}/></>}</Async></Card>}

function Incidents(){const[sel,setSel]=useState<string|null>(null),[st,setSt]=useState('');const r=useApi('/incidents?size=50'+(st?'&status='+st:''))
  if(sel)return<IncidentView id={sel} back={()=>{setSel(null);r.load()}}/>
  return<Card t="Incidents" right={<select className={inp} value={st} onChange={e=>setSt(e.target.value)}><option value="">All statuses</option>{['new','investigating','in_progress','resolved','closed'].map(s=><option key={s}>{s}</option>)}</select>}>
  <Async r={r}>{d=><Table rows={d.items} onRow={x=>setSel(x.id)} cols={[['Risk',r=><><Badge v={r.risk_level}/> {r.risk_score}</>],['Title',r=>r.title],['Status',r=>r.status],['Priority',r=>r.priority],['Created',r=>fmt(r.created_at)]]}/>}</Async></Card>}
function IncidentView({id,back}:any){const r=useApi('/incidents/'+id),u=useApi('/users-lite'),[note,setNote]=useState(''),[kind,setKind]=useState('note'),[ai,setAi]=useState<any>(null),[busy,setBusy]=useState(false)
  const patch=async(b:any)=>{try{await api('/incidents/'+id,{method:'PATCH',body:JSON.stringify(b)});r.load()}catch(e:any){Alert_(e.message)}}
  const post=async()=>{try{await api(`/incidents/${id}/notes`,{method:'POST',body:JSON.stringify({body:note,kind})});setNote('');r.load()}catch(e:any){Alert_(e.message)}}
  const sum=async()=>{setBusy(true);try{setAi(await api('/ai/analyze',{method:'POST',body:JSON.stringify({incident_id:id,save_summary:true})}));r.load()}catch(e:any){Alert_(e.message)}setBusy(false)}
  return<Async r={r}>{d=><div className="space-y-4"><button className="text-cyan-400 text-sm" onClick={back}>← All incidents</button>
  <Card t={d.title} right={<span><Badge v={d.risk_level}/> {d.risk_score}/100</span>}>
   <div className="flex gap-2 flex-wrap mb-3"><select className={inp} value={d.status} onChange={e=>patch({status:e.target.value})}>{['new','investigating','in_progress','resolved','closed'].map(s=><option key={s}>{s}</option>)}</select>
   <select className={inp} value={d.priority} onChange={e=>patch({priority:e.target.value})}>{['low','medium','high','critical'].map(s=><option key={s}>{s}</option>)}</select>
   <select className={inp} value={d.assignee_id||''} onChange={e=>patch({assignee_id:e.target.value||null})}><option value="">Unassigned</option>{(u.d||[]).map((x:any)=><option key={x.id} value={x.id}>{x.full_name}</option>)}</select>
