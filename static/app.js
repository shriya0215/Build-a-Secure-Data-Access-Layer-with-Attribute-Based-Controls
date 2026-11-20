const $=id=>document.getElementById(id);
async function refresh(){
 const o=await fetch('/api/overview').then(r=>r.json());
 $('total').textContent=o.total;$('allowed').textContent=o.allowed;$('denied').textContent=o.denied;
 const logs=await fetch('/api/audit').then(r=>r.json());
 $('audit-body').innerHTML=logs.length?logs.map(x=>`<tr><td>${x.timestamp}</td><td>${x.user_name}</td><td>${x.resource_id}</td><td>${x.action}</td><td><span class="decision-badge ${x.decision.toLowerCase()}">${x.decision}</span></td><td title="${x.reason}">${x.reason.slice(0,75)}${x.reason.length>75?'…':''}</td></tr>`).join(''):`<tr><td colspan="6" class="empty">No requests yet. Run the simulator to create an audit record.</td></tr>`;
}
$('evaluate').addEventListener('click',async()=>{
 const btn=$('evaluate');btn.disabled=true;btn.textContent='Evaluating…';
 try{
 const result=await fetch('/api/evaluate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({user_id:$('user').value,resource_id:$('resource').value,action:$('action').value,business_hours:$('business').value==='true'})}).then(r=>r.json());
 const box=$('result');box.classList.remove('hidden');
 const pass=result.reasons.map(r=>{const fail=r.includes('FAIL');const masked=r.includes('MASKED');return `<span class="reason ${fail?'fail':(r.includes('PASS')?'pass':'')}">${r}</span>`}).join('');
 const rows=result.rows.length?`<div class="data-preview"><b>Sample data ${result.masked?'(PII masked)':''}</b><table><thead><tr>${Object.keys(result.rows[0]).map(k=>`<th>${k.toUpperCase()}</th>`).join('')}</tr></thead><tbody>${result.rows.map(row=>`<tr>${Object.values(row).map(v=>`<td>${v}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`:`<p class="policy-ref">No sample data returned because this request was denied or the action is not read.</p>`;
 box.innerHTML=`<div class="decision ${result.decision.toLowerCase()}">${result.decision==='ALLOW'?'✓':'⊘'} ${result.decision} <span class="policy-ref">· PDP evaluation complete</span></div><div class="reason-list">${pass}</div><div class="policy-ref">Matched policy IDs: ${result.policy_ids.length?result.policy_ids.join(', '):'None'} · ${result.user.name} → ${result.resource.label} (${result.action})</div>${rows}`;
 await refresh();
 }catch(e){$('result').classList.remove('hidden');$('result').textContent='Evaluation error: '+e.message}
 btn.disabled=false;btn.innerHTML='Evaluate access <span>→</span>';
});
$('refresh').addEventListener('click',refresh);
refresh();