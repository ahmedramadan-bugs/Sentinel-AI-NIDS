/* =========================================================
   NIDS REAL BACKEND CONNECTOR
   ========================================================= */

let alerts = [];
let systemStatus = {};
let responseState = {};
let currentAlertId = null;
let currentPage = 'dashboard';
let trafficChart = null, attackPieChart = null, protocolPieChart = null, importanceChart = null;

function timeAgo(dateStr){
  if(!dateStr) return '—';
  const d = new Date(dateStr);
  const s = Math.floor((Date.now() - d.getTime())/1000);
  if(s < 60) return s + 's ago';
  if(s < 3600) return Math.floor(s/60) + 'm ago';
  if(s < 86400) return Math.floor(s/3600) + 'h ago';
  return Math.floor(s/86400) + 'd ago';
}

function fmtTime(dateStr){
  if(!dateStr) return '—';
  return new Date(dateStr).toLocaleString([], {month:'short', day:'2-digit', hour:'2-digit', minute:'2-digit', second:'2-digit'});
}

/* Escape untrusted data before injecting into innerHTML */
function escapeHtml(s){
  if(s == null) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function sevBadge(sev){
  const s = (sev || 'Info').toLowerCase();
  return `<span class="badge-sev badge-${s}">${escapeHtml(sev) || 'Info'}</span>`;
}

function statusBadge(st){
  const s = (st || 'UNKNOWN').toLowerCase();
  return `<span class="badge-status ${s}">${escapeHtml(st) || 'UNKNOWN'}</span>`;
}

function fireToast(msg, variant='info'){
  const icons = {critical:'bi-exclamation-octagon-fill', success:'bi-check-circle-fill', info:'bi-info-circle-fill'};
  const container = document.getElementById('toastContainer');
  if(!container) return;
  const el = document.createElement('div');
  el.className = `toast-item t-${variant}`;
  el.innerHTML = `<i class="bi ${icons[variant]||icons.info}"></i><span>${msg}</span>`;
  container.appendChild(el);
  requestAnimationFrame(()=> el.classList.add('show'));
  setTimeout(()=>{
    el.classList.remove('show');
    setTimeout(()=> el.remove(), 250);
  }, 4000);
}

/* Navigation */
document.addEventListener('click', e=>{
  const link = e.target.closest('[data-page]');
  if(link){
    e.preventDefault();
    showPage(link.dataset.page);
  }
});
const mobileToggle = document.getElementById('mobile-toggle');
if(mobileToggle){
  mobileToggle.addEventListener('click', ()=>{
    document.getElementById('sidebar').classList.toggle('open');
  });
}

function showPage(page){
  currentPage = page;
  document.querySelectorAll('#nav-links .nav-link').forEach(l=>l.classList.toggle('active', l.dataset.page===page));
  ['dashboard','alerts','alert-detail','topology','console','analytics','ai-models','response','settings'].forEach(p=>{
    const el = document.getElementById('page-'+p);
    if(el) el.style.display = (p===page) ? '' : 'none';
  });
  const sb = document.getElementById('sidebar');
  if(sb) sb.classList.remove('open');
  if(page==='dashboard') renderDashboard();
  if(page==='alerts') renderAlertsPage();
  if(page==='topology' && typeof renderTopology==='function') renderTopology();
  if(page==='console' && typeof initConsolePage==='function') initConsolePage();
  if(page==='analytics') renderAnalytics();
  if(page==='ai-models') renderAiModels();
  if(page==='response') renderResponse();
  if(page==='settings') renderSettings();
}

/* Pulse Canvas */
let pulseCtx, pulseData = [];
function initPulse(){
  const pulseCanvas = document.getElementById('pulseCanvas');
  if(!pulseCanvas) return;
  pulseCanvas.width = (pulseCanvas.clientWidth || 190) * 2;
  pulseCanvas.height = (pulseCanvas.clientHeight || 24) * 2;
  pulseCtx = pulseCanvas.getContext('2d');
  pulseData = new Array(60).fill(0).map(()=>Math.random()*0.3+0.2);
  drawPulse();
}
function drawPulse(){
  if(!pulseCtx) return;
  const pulseCanvas = document.getElementById('pulseCanvas');
  if(!pulseCanvas) return;
  pulseData.shift();
  pulseData.push(Math.random()*0.4 + (Math.random()<0.08?0.8:0.2));
  const w = pulseCanvas.width, h = pulseCanvas.height;
  pulseCtx.clearRect(0,0,w,h);
  pulseCtx.beginPath();
  pulseData.forEach((v,i)=>{
    const x = (i/(pulseData.length-1))*w;
    const y = h - v*h;
    if(i===0) pulseCtx.moveTo(x,y); else pulseCtx.lineTo(x,y);
  });
  pulseCtx.strokeStyle = '#00d9c0';
  pulseCtx.lineWidth = 2;
  pulseCtx.stroke();
  requestAnimationFrame(drawPulse);
}

function tickClock(){
  const el = document.getElementById('clock');
  if(el) el.textContent = new Date().toLocaleString([], {weekday:'short', month:'short', day:'2-digit', hour:'2-digit', minute:'2-digit', second:'2-digit'});
}

/* Real Data Fetchers */
async function fetchStatus(){
  try{
    const res = await fetch('/api/status');
    if(!res.ok) return;
    systemStatus = await res.json();
    updateHealthBar();
    updateKpis();
  }catch(e){ console.error('fetchStatus error', e); }
}

async function fetchEvents(){
  try{
    const res = await fetch('/api/events?limit=300');
    if(!res.ok) return;
    const data = await res.json();
    alerts = data.events || [];
    if(currentPage==='dashboard') renderLatestAlerts();
    if(currentPage==='alerts') applyFilters();
  }catch(e){ console.error('fetchEvents error', e); }
}

async function fetchResponseState(){
  try{
    const res = await fetch('/api/response/state');
    if(!res.ok) return;
    responseState = await res.json();
    if(currentPage==='response') updateResponseUI();
  }catch(e){ console.error('fetchResponseState error', e); }
}

function updateHealthBar(){
  const s = systemStatus;
  if(!s) return;
  const isSnifferOk = s.suricata && (s.suricata.status === 'WATCHING' || s.suricata.status === 'READY');
  const dotSniff = document.getElementById('dot-sniffer');
  const lblSniff = document.getElementById('lbl-sniffer');
  if(dotSniff) dotSniff.className = isSnifferOk ? 'dot' : 'dot warn';
  if(lblSniff) lblSniff.textContent = isSnifferOk ? 'ACTIVE' : (s.suricata?.status || 'OFFLINE');

  const isMlOk = s.ml && s.ml.status === 'HEALTHY';
  const dotAi = document.getElementById('dot-ai');
  const lblAi = document.getElementById('lbl-ai');
  if(dotAi) dotAi.className = isMlOk ? 'dot' : 'dot warn';
  if(lblAi) lblAi.textContent = isMlOk ? 'ONLINE (XGBoost)' : 'FALLBACK';

  const isFwOk = s.response && s.response.status === 'HEALTHY';
  const dotFw = document.getElementById('dot-fw');
  const lblFw = document.getElementById('lbl-fw');
  if(dotFw) dotFw.className = isFwOk ? 'dot' : 'dot warn';
  if(lblFw) lblFw.textContent = isFwOk ? (s.response.dry_run ? 'DRY-RUN' : 'CONNECTED (SSH)') : 'UNAVAILABLE';
}

function updateKpis(){
  const m = systemStatus.metrics || {};
  const elActive = document.getElementById('kpi-active');
  const elCrit = document.getElementById('kpi-critical');
  const elRes = document.getElementById('kpi-resolved');
  const elFlows = document.getElementById('kpi-flows');
  if(elActive) elActive.textContent = m.active_threats ?? m.alerts ?? 0;
  if(elCrit) elCrit.textContent = m.critical_alerts ?? 0;
  if(elRes) elRes.textContent = m.resolved_today ?? m.block_decisions ?? 0;
  if(elFlows) elFlows.textContent = (m.observed_events ?? 0).toLocaleString();
}

async function renderTrafficChart(range='24h'){
  try{
    if(typeof Chart === 'undefined') return;
    const res = await fetch(`/api/stats/traffic?range=${range}`);
    const data = await res.json();
    const ctx = document.getElementById('trafficChart');
    if(!ctx) return;
    if(trafficChart) trafficChart.destroy();
    trafficChart = new Chart(ctx, {
      type:'line',
      data:{
        labels: data.labels || [],
        datasets:[{
          label:'Flows / Packets',
          data: data.values || [],
          borderColor:'#00d9c0',
          backgroundColor:'rgba(0,217,192,.12)',
          fill:true,
          tension:.35,
          pointRadius:2,
          borderWidth:2
        }]
      },
      options:{
        responsive:true,
        plugins:{legend:{display:false}},
        scales:{
          x:{ticks:{color:'#576078', font:{family:'JetBrains Mono', size:10}}, grid:{color:'rgba(255,255,255,.04)'}},
          y:{ticks:{color:'#576078', font:{family:'JetBrains Mono', size:10}}, grid:{color:'rgba(255,255,255,.04)'}}
        }
      }
    });
  }catch(e){ console.error('renderTrafficChart error', e); }
}

async function renderAttackPie(){
  try{
    if(typeof Chart === 'undefined') return;
    const res = await fetch('/api/stats/distribution');
    const counts = await res.json();
    const labels = Object.keys(counts);
    const values = Object.values(counts);
    const palette = ['#ef4a52','#f5943a','#e8c33c','#00d9c0','#7c8cf5','#b388ff'];
    const ctx = document.getElementById('attackPie');
    if(!ctx) return;
    if(attackPieChart) attackPieChart.destroy();
    attackPieChart = new Chart(ctx, {
      type:'doughnut',
      data:{
        labels: labels.length ? labels : ['Normal Traffic'],
        datasets:[{
          data: values.length ? values : [1],
          backgroundColor: values.length ? palette.slice(0, labels.length) : ['#33c777'],
          borderColor:'#111826',
          borderWidth:2
        }]
      },
      options:{
        responsive:true,
        plugins:{legend:{position:'bottom', labels:{color:'#8b96ab', font:{size:10, family:'Inter'}, boxWidth:10, padding:10}}}
      }
    });
  }catch(e){ console.error('renderAttackPie error', e); }
}

function renderLatestAlerts(){
  const latest = alerts.slice(0, 10);
  const tbody = document.querySelector('#latest-alerts-table tbody');
  if(!tbody) return;
  tbody.innerHTML = latest.map(a=>{
    let actionBtn = '';
    if(a.attack_type !== 'Normal'){
      if(a.response_status === 'APPLIED' || a.response_status === 'ACTIVE'){
        actionBtn = `<span class="badge-status applied"><i class="bi bi-shield-check"></i> Blocked</span>`;
      } else {
        actionBtn = `<button class="btn-block-quick" data-block-ip="${escapeHtml(a.src_ip)}" data-attack="${escapeHtml(a.attack_type)}">Block</button>`;
      }
    }
    return `
    <tr class="clickable" data-id="${a.id}">
      <td class="ip-mono">${escapeHtml(a.src_ip)}</td>
      <td class="ip-mono">${escapeHtml(a.dest_ip)}:${escapeHtml(a.dest_port || 0)}</td>
      <td><b>${escapeHtml(a.attack_type)}</b></td>
      <td>${sevBadge(a.severity)}</td>
      <td class="mono">${(Number(a.confidence || 0)*100).toFixed(0)}%</td>
      <td>${statusBadge(a.response_status)}</td>
      <td class="time-dim">${timeAgo(a.timestamp)}</td>
      <td>${actionBtn}</td>
    </tr>`;
  }).join('');

  tbody.querySelectorAll('tr.clickable').forEach(tr=>{
    tr.addEventListener('click', e=>{
      if(e.target.closest('button')) return;
      openAlertDetail(+tr.dataset.id);
    });
  });
}

async function triggerBlock(ip, attack='Manual Dashboard Block', severity='High', timeout=300){
  try{
    const res = await fetch('/api/response/block', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({ip, attack, severity, timeout: Number(timeout)})
    });
    const result = await res.json();
    if(result.success){
      const durText = Number(timeout) === 0 ? 'Permanent' : timeout + 's';
      fireToast(`Successfully blocked ${ip} on Cisco switch (${durText}).`, 'success');
    } else {
      fireToast(`${ip}: ${result.message || 'Block applied / already blocked.'}`, 'info');
    }
    fetchStatus();
    fetchEvents();
    fetchResponseState();
  }catch(e){ fireToast('Block request failed: ' + e, 'critical'); }
}

async function triggerUnblock(ip){
  try{
    const res = await fetch('/api/response/unblock', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({ip})
    });
    const result = await res.json();
    if(result.success){
      fireToast(`Unblocked ${ip} from Cisco switch.`, 'success');
    } else {
      fireToast(`Unblock ${ip}: ${result.message || 'Complete'}`, 'info');
    }
    fetchStatus();
    fetchEvents();
    fetchResponseState();
  }catch(e){ fireToast('Unblock request failed: ' + e, 'critical'); }
}

/* Universal Click Delegator for reliable action buttons */
document.addEventListener('click', async (e)=>{
  const unblockBtn = e.target.closest('[data-unblock-ip]');
  if(unblockBtn){
    e.preventDefault();
    e.stopPropagation();
    const ip = unblockBtn.dataset.unblockIp;
    unblockBtn.disabled = true;
    unblockBtn.textContent = 'Unblocking...';
    await triggerUnblock(ip);
    return;
  }

  const removeWhiteBtn = e.target.closest('[data-remove-white]');
  if(removeWhiteBtn){
    e.preventDefault();
    e.stopPropagation();
    const ip = removeWhiteBtn.dataset.removeWhite;
    removeWhiteBtn.disabled = true;
    removeWhiteBtn.textContent = 'Removing...';
    try{
      await fetch('/api/response/whitelist/remove', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({ip})
      });
      fireToast(`Removed ${ip} from whitelist`, 'info');
      fetchResponseState();
    }catch(err){ fireToast('Failed to remove whitelist: ' + err, 'critical'); }
    return;
  }

  const blockQuickBtn = e.target.closest('[data-block-ip]');
  if(blockQuickBtn){
    e.preventDefault();
    e.stopPropagation();
    const ip = blockQuickBtn.dataset.blockIp;
    const attack = blockQuickBtn.dataset.attack || 'Manual Dashboard Block';
    blockQuickBtn.disabled = true;
    blockQuickBtn.textContent = 'Blocking...';
    await triggerBlock(ip, attack, 'High', 300);
    return;
  }
});

function renderDashboard(){
  fetchStatus();
  fetchEvents();
  const tr = document.getElementById('traffic-range');
  renderTrafficChart(tr ? tr.value : '24h');
  renderAttackPie();
}

const trafficRangeEl = document.getElementById('traffic-range');
if(trafficRangeEl) trafficRangeEl.addEventListener('change', e=>renderTrafficChart(e.target.value));

const btnRefreshNow = document.getElementById('btn-refresh-now');
if(btnRefreshNow){
  btnRefreshNow.addEventListener('click', ()=>{
    renderDashboard();
    fireToast('Refreshed live NIDS data.', 'info');
  });
}

/* Alerts Page Filtering */
function populateTypeFilter(){
  const sel = document.getElementById('f-type');
  if(!sel || sel.options.length > 1) return;
  const types = ['TCP SYN / Port Scan', 'Brute Force', 'Denial of Service', 'SQL Injection', 'Cross-Site Scripting', 'Local File Inclusion', 'ICMP Reconnaissance', 'Suricata Security Alert', 'Normal'];
  types.forEach(t=>{
    const o = document.createElement('option'); o.value=t; o.textContent=t; sel.appendChild(o);
  });
}

function renderAlertsPage(){
  populateTypeFilter();
  fetchEvents();
}

function applyFilters(){
  const sev = document.getElementById('f-severity')?.value;
  const type = document.getElementById('f-type')?.value;
  const fromDate = document.getElementById('f-from')?.value;
  const toDate = document.getElementById('f-to')?.value;
  const ip = document.getElementById('f-ip')?.value?.trim();
  const search = document.getElementById('f-search')?.value?.trim()?.toLowerCase();

  let list = [...alerts];
  if(sev) list = list.filter(a=>a.severity.toLowerCase() === sev.toLowerCase());
  if(type) list = list.filter(a=>a.attack_type === type);
  if(fromDate) list = list.filter(a=>a.timestamp >= fromDate + 'T00:00:00');
  if(toDate) list = list.filter(a=>a.timestamp <= toDate + 'T23:59:59');
  if(ip) list = list.filter(a=>(a.src_ip||'').includes(ip) || (a.dest_ip||'').includes(ip));
  if(search) list = list.filter(a=>((a.src_ip||'') + ' ' + (a.dest_ip||'') + ' ' + (a.attack_type||'') + ' ' + (a.signature||'') + ' ' + (a.rule_id||'')).toLowerCase().includes(search));

  const tbody = document.querySelector('#alerts-table tbody');
  if(tbody){
    tbody.innerHTML = list.map(a=>`
      <tr class="clickable" data-id="${a.id}">
        <td class="ip-mono">${a.src_ip}</td>
        <td class="ip-mono">${a.dest_ip}:${a.dest_port || 0}</td>
        <td><b>${a.attack_type}</b></td>
        <td>${sevBadge(a.severity)}</td>
        <td>${a.detection_engine} / ${a.detection_mode}</td>
        <td class="mono">${(Number(a.confidence || 0)*100).toFixed(0)}%</td>
        <td>${statusBadge(a.response_status)}</td>
        <td class="time-dim">${fmtTime(a.timestamp)}</td>
      </tr>
    `).join('');
    tbody.querySelectorAll('tr').forEach(tr=>tr.addEventListener('click', ()=>openAlertDetail(+tr.dataset.id)));
  }
  const emptyEl = document.getElementById('alerts-empty');
  if(emptyEl) emptyEl.style.display = list.length ? 'none' : 'block';
}

['f-severity','f-type','f-from','f-to','f-ip','f-search'].forEach(id=>{
  const el = document.getElementById(id);
  if(el){
    el.addEventListener('input', applyFilters);
    el.addEventListener('change', applyFilters);
  }
});
const btnClear = document.getElementById('f-clear');
if(btnClear){
  btnClear.addEventListener('click', ()=>{
    ['f-severity','f-type','f-from','f-to','f-ip','f-search'].forEach(id=>{
      const el = document.getElementById(id);
      if(el) el.value = '';
    });
    applyFilters();
  });
}

const btnExportCsv = document.getElementById('export-csv');
if(btnExportCsv){
  btnExportCsv.addEventListener('click', ()=>{
    const rows = [['id','timestamp','src_ip','dest_ip','dest_port','protocol','attack_type','severity','detection_engine','confidence','response_action','response_status']];
    alerts.forEach(a=>rows.push([a.id, a.timestamp, a.src_ip, a.dest_ip, a.dest_port, a.protocol, a.attack_type, a.severity, a.detection_engine, a.confidence, a.response_action, a.response_status]));
    const csv = rows.map(r=>r.join(',')).join(String.fromCharCode(10));
    const blob = new Blob([csv], {type:'text/csv'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `nids_alerts_${Date.now()}.csv`;
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    URL.revokeObjectURL(url);
    fireToast('Exported alerts to CSV', 'info');
  });
}

/* Alert Detail Page */
async function openAlertDetail(id){
  currentAlertId = id;
  showPage('alert-detail');
  let a = alerts.find(x=>x.id===id);
  if(!a){
    const res = await fetch(`/api/events/${id}`);
    a = await res.json();
  }
  if(!a) return;

  document.getElementById('detail-title').textContent = `Security Event #${a.id} — ${a.attack_type}`;
  document.getElementById('detail-sub').textContent = `${a.src_ip} → ${a.dest_ip}:${a.dest_port || 0} · ${fmtTime(a.timestamp)}`;

  const confPct = Math.round(Number(a.confidence || 0)*100);
  document.getElementById('risk-num').textContent = confPct + '%';
  document.getElementById('risk-conf').textContent = confPct + '%';
  document.getElementById('risk-type').textContent = a.attack_type;
  document.getElementById('risk-engine').textContent = `${a.detection_engine} (${a.detection_mode})`;
  document.getElementById('risk-action').textContent = `${a.response_action} (${a.response_status})`;

  const arc = document.getElementById('risk-arc');
  if(arc){
    arc.setAttribute('stroke-dasharray', `${confPct},100`);
    const colors = {Critical:'#ef4a52', High:'#f5943a', Medium:'#e8c33c', Low:'#33c777', Info:'#00d9c0'};
    arc.setAttribute('stroke', colors[a.severity] || '#00d9c0');
  }

  // Raw flow fields
  document.getElementById('raw-src').textContent = a.src_ip || '—';
  document.getElementById('raw-dst').textContent = a.dest_ip || '—';
  document.getElementById('raw-port').textContent = a.dest_port || '—';
  document.getElementById('raw-proto').textContent = a.protocol || '—';
  document.getElementById('raw-sig').textContent = a.signature || 'None (Flow/ML Signal)';
  document.getElementById('raw-rule').textContent = a.rule_id || '—';
  document.getElementById('raw-key').textContent = a.correlation_key || '—';

  // Model bars
  const colors = {Critical:'#ef4a52', High:'#f5943a', Medium:'#e8c33c', Low:'#33c777', Info:'#00d9c0'};
  document.getElementById('model-bars').innerHTML = `
    <div class="model-row">
      <div class="m-label">XGBoost ML</div>
      <div class="model-track"><div class="model-fill" style="width:${confPct}%; background:${colors[a.severity]||'var(--accent)'};"></div></div>
      <div class="model-val">${confPct}%</div>
    </div>
    <div class="model-row">
      <div class="m-label">Severity Level</div>
      <div class="model-track"><div class="model-fill" style="width:${a.severity==='Critical'?100:(a.severity==='High'?75:50)}%; background:${colors[a.severity]||'var(--accent)'};"></div></div>
      <div class="model-val">${a.severity}</div>
    </div>
  `;

  let rawEve = {};
  try{ rawEve = JSON.parse(a.raw_event || '{}'); }catch(e){}
  const flow = rawEve.eve?.flow || {};
  document.getElementById('raw-details-text').innerHTML = `
    <b>Flow Stats:</b> Bytes to server: ${flow.bytes_toserver || 0}, Bytes to client: ${flow.bytes_toclient || 0}, Packets: ${(flow.pkts_toserver||0)+(flow.pkts_toclient||0)}<br>
    <b>Decision Engine:</b> ${a.detection_engine} (${a.detection_mode}) · Rule ID: ${a.rule_id || 'N/A'}
  `;

  document.getElementById('btn-block-detail').onclick = ()=>{
    const duration = document.getElementById('detail-block-duration')?.value || '300';
    triggerBlock(a.src_ip, a.attack_type, a.severity, duration);
  };
  document.getElementById('btn-unblock-detail').onclick = ()=> triggerUnblock(a.src_ip);
  document.getElementById('btn-white-detail').onclick = async ()=>{
    await fetch('/api/response/whitelist/add', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({ip: a.src_ip})
    });
    fireToast(`Added ${a.src_ip} to whitelist`, 'success');
  };
}

/* Analytics Page */
const analyticsTabs = document.getElementById('analytics-tabs');
if(analyticsTabs){
  analyticsTabs.addEventListener('click', function(e){
    const link = e.target.closest('[data-tab]');
    if(!link) return;
    e.preventDefault();
    this.querySelectorAll('.nav-link').forEach(l=>l.classList.toggle('active', l===link));
    ['heatmap','attackers','protocol'].forEach(t=>{
      const el = document.getElementById('tab-'+t);
      if(el) el.style.display = (t===link.dataset.tab) ? '' : 'none';
    });
    if(link.dataset.tab==='protocol') renderProtocolPie();
  });
}

async function renderAnalytics(){
  try{
    const res = await fetch('/api/stats/analytics');
    const data = await res.json();

    // Heatmap
    renderHeatmapGrid(data.heatmap || []);

    // Top attackers
    const top = data.top_attackers || [];
    const topTbody = document.querySelector('#top-attackers-table tbody');
    if(topTbody){
      topTbody.innerHTML = top.map((t,i)=>`
        <tr>
          <td class="mono">${i+1}</td>
          <td class="ip-mono">${escapeHtml(t.src_ip)}</td>
          <td class="mono"><b>${escapeHtml(t.count)}</b></td>
          <td>${escapeHtml(t.attack_type)}</td>
          <td class="time-dim">${timeAgo(t.last_seen)}</td>
        </tr>
      `).join('');
    }

    // Protocol breakdown
    const proto = data.protocol_distribution || {};
    const total = Object.values(proto).reduce((a,b)=>a+b, 0) || 1;
    const protoEl = document.getElementById('protocol-breakdown');
    if(protoEl){
      protoEl.innerHTML = Object.entries(proto).map(([k,v])=>`
        <div class="d-flex justify-content-between align-items-center mb-2">
          <span class="mono">${escapeHtml(k)}</span>
          <span class="mono" style="color:var(--text-dim);">${escapeHtml(v)} events (${((v/total)*100).toFixed(1)}%)</span>
        </div>
      `).join('');
    }
  }catch(e){ console.error('renderAnalytics error', e); }
}

function renderHeatmapGrid(points){
  const days = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
  const grid = document.getElementById('heatmap');
  if(!grid) return;
  let html = `<div></div>`;
  for(let h=0; h<24; h++) html += `<div class="heat-hourlabel">${h%3===0?h:''}</div>`;
  const lookup = {};
  points.forEach(p=> lookup[`${p.day}_${p.hour}`] = p.count);
  days.forEach((d, dayIdx)=>{
    html += `<div class="hlabel">${d}</div>`;
    for(let h=0; h<24; h++){
      const count = lookup[`${dayIdx}_${h}`] || 0;
      const alpha = count > 0 ? Math.min(1, 0.15 + (count/50)*0.85) : 0.03;
      html += `<div class="hcell" style="background:rgba(239,74,82,${alpha})" title="${d} ${h}:00 — ${count} alerts"></div>`;
    }
  });
  grid.innerHTML = html;
}

async function renderProtocolPie(){
  try{
    if(typeof Chart === 'undefined') return;
    const res = await fetch('/api/stats/analytics');
    const data = await res.json();
    const proto = data.protocol_distribution || {};
    const labels = Object.keys(proto);
    const values = Object.values(proto);
    const ctx = document.getElementById('protocolPie');
    if(!ctx) return;
    if(protocolPieChart) protocolPieChart.destroy();
    protocolPieChart = new Chart(ctx, {
      type:'pie',
      data:{
        labels,
        datasets:[{data: values, backgroundColor:['#00d9c0','#f5943a','#7c8cf5','#ef4a52'], borderColor:'#111826', borderWidth:2}]
      },
      options:{responsive:true, plugins:{legend:{position:'bottom', labels:{color:'#8b96ab', font:{size:10}}}}}
    });
  }catch(e){ console.error('renderProtocolPie error', e); }
}

/* AI Models Page */
async function renderAiModels(){
  try{
    const res = await fetch('/api/models/metrics');
    const m = await res.json();
    if(m.classification_report){
      const acc = m.classification_report.accuracy;
      const prec = m.classification_report['macro avg']?.precision;
      const rec  = m.classification_report['macro avg']?.recall;
      const f1   = m.test_macro_f1;
      document.getElementById('m-acc').textContent  = acc  != null ? (acc*100).toFixed(2)+'%'  : 'N/A';
      document.getElementById('m-prec').textContent = prec != null ? (prec*100).toFixed(2)+'%' : 'N/A';
      document.getElementById('m-rec').textContent  = rec  != null ? (rec*100).toFixed(2)+'%'  : 'N/A';
      document.getElementById('m-f1').textContent   = f1   != null ? f1.toFixed(4)              : 'N/A';
    } else {
      ['m-acc','m-prec','m-rec','m-f1'].forEach(id => {
        document.getElementById(id).textContent = 'N/A';
      });
    }
    if(m.confusion_matrix){
      const cm = m.confusion_matrix;
      const classes = m.classes || ['Brute Force', 'Data Exfil', 'Normal', 'Port Scan'];
      let cmHtml = '<table class="table-nids"><thead><tr><th>Actual \\ Pred</th>';
      classes.forEach(c=> cmHtml += `<th>${c}</th>`);
      cmHtml += '</tr></thead><tbody>';
      cm.forEach((row, i)=>{
        cmHtml += `<tr><td class="mono" style="color:var(--text-dim);">${classes[i]}</td>`;
        row.forEach((v, j)=>{
          const color = (i===j) ? 'var(--low)' : (v>0 ? 'var(--critical)' : 'var(--text-faint)');
          cmHtml += `<td class="mono" style="color:${color}; font-weight:${i===j?700:400};">${v}</td>`;
        });
        cmHtml += '</tr>';
      });
      cmHtml += '</tbody></table>';
      document.getElementById('confusion-matrix-box').innerHTML = cmHtml;
    }
    if(m.feature_schema){
      document.getElementById('feature-schema-list').innerHTML = m.feature_schema.map((f,i)=>`
        <div class="col-md-6 col-lg-4">
          <div class="p-2 rounded" style="background:var(--bg-alt); border:1px solid var(--border-soft);">
            <span style="color:var(--text-faint);">${i+1}.</span> <b>${f}</b> <span class="badge-status applied float-end">float64</span>
          </div>
        </div>
      `).join('');
    }
    if(m.feature_importances && typeof Chart !== 'undefined'){
      const feats = m.feature_importances.map(x=>x.feature);
      const vals = m.feature_importances.map(x=>Number((x.importance*100).toFixed(1)));
      const ctx = document.getElementById('importanceChart');
      if(ctx){
        if(importanceChart) importanceChart.destroy();
        importanceChart = new Chart(ctx, {
          type:'bar',
          data:{
            labels: feats,
            datasets:[{data: vals, backgroundColor:'#00d9c0', borderRadius:4}]
          },
          options:{
            indexAxis:'y',
            responsive:true,
            plugins:{legend:{display:false}},
            scales:{
              x:{ticks:{color:'#576078', font:{family:'JetBrains Mono', size:10}}, grid:{color:'rgba(255,255,255,.05)'}},
              y:{ticks:{color:'#8b96ab', font:{size:10, family:'Inter'}}, grid:{display:false}}
            }
          }
        });
      }
    }
  }catch(e){ console.error('renderAiModels error', e); }
}

/* Response Page */
async function renderResponse(){
  await fetchResponseState();
}

function updateResponseUI(){
  const st = responseState || {};
  const blocked = st.active_blocks || [];
  const white = st.whitelist || [];
  const history = st.history || [];

  document.getElementById('c-total').textContent = blocked.length;
  document.getElementById('c-temp').textContent = blocked.filter(b=>b.block_type==='temporary').length;
  document.getElementById('c-perm').textContent = blocked.filter(b=>b.block_type==='permanent').length;
  document.getElementById('c-white').textContent = white.length;

  const blockedBody = document.getElementById('blocked-body');
  if(blockedBody){
    blockedBody.innerHTML = blocked.map(b=>{
      let timeoutCell = '<span style="color:var(--text-faint);">Permanent</span>';
      if(b.block_type === 'temporary'){
        const ep = b.expires_epoch || (Date.now()/1000 + (b.timeout||300));
        const rem = Math.max(0, Math.ceil(ep - (Date.now()/1000)));
        const m = Math.floor(rem / 60);
        const s = rem % 60;
        timeoutCell = `<span class="mono countdown-cell" data-expires-epoch="${ep}" style="color:var(--accent); font-weight:600;">${m}:${String(s).padStart(2, '0')}</span>`;
      }
      return `
      <tr>
        <td class="ip-mono"><b>${escapeHtml(b.ip)}</b></td>
        <td><span class="badge-status ${b.block_type==='temporary'?'whitelisted':'applied'}">${escapeHtml(b.block_type)}</span></td>
        <td style="color:var(--text-dim);">${escapeHtml(b.reason || 'Security threat detected')}</td>
        <td>${timeoutCell}</td>
        <td><button class="btn-ghost" data-unblock-ip="${escapeHtml(b.ip)}"><i class="bi bi-shield-check me-1"></i>Unblock</button></td>
      </tr>`;
    }).join('');
  }
  const blockedEmpty = document.getElementById('blocked-empty');
  if(blockedEmpty) blockedEmpty.style.display = blocked.length ? 'none' : 'block';

  const whiteBody = document.getElementById('whitelist-body');
  if(whiteBody){
    whiteBody.innerHTML = white.map(ip=>`
      <tr>
        <td class="ip-mono">${escapeHtml(ip)}</td>
        <td><button class="btn-ghost" data-remove-white="${escapeHtml(ip)}"><i class="bi bi-x-circle me-1"></i>Remove</button></td>
      </tr>
    `).join('');
  }

  const sshBody = document.getElementById('ssh-body');
  if(sshBody){
    sshBody.innerHTML = history.slice(-20).reverse().map(h=>`
      <tr>
        <td class="mono"><b>${escapeHtml(h.action?.toUpperCase())}</b></td>
        <td class="ip-mono">${escapeHtml(h.ip)}</td>
        <td style="color:var(--text-dim);">${escapeHtml(h.attack || h.source || '—')}</td>
        <td><span class="badge-status ${h.success?'applied':'failed'}">${h.success?'SUCCESS':'FAILED'}</span></td>
        <td class="time-dim">${fmtTime(h.timestamp)}</td>
      </tr>
    `).join('');
  }
}

/* Live 1-second Countdown Timer */
setInterval(()=>{
  document.querySelectorAll('[data-expires-epoch]').forEach(td=>{
    const epoch = parseFloat(td.dataset.expiresEpoch);
    if(!epoch || isNaN(epoch)) return;
    const remaining = Math.max(0, Math.ceil(epoch - (Date.now()/1000)));
    if(remaining <= 0){
      td.innerHTML = '<span class="badge-status applied" style="color:var(--medium); border-color:var(--medium);">Expiring...</span>';
      if(!td.dataset.refreshed){
        td.dataset.refreshed = 'true';
        setTimeout(fetchResponseState, 1500);
      }
    } else {
      const mins = Math.floor(remaining / 60);
      const secs = remaining % 60;
      td.textContent = `${mins}:${String(secs).padStart(2, '0')}`;
    }
  });
}, 1000);

/* Manual Block Button */
const btnManualBlock = document.getElementById('btn-manual-block');
if(btnManualBlock){
  btnManualBlock.addEventListener('click', async ()=>{
    const ipInput = document.getElementById('manual-block-ip');
    const reasonInput = document.getElementById('manual-block-reason');
    const durSelect = document.getElementById('manual-block-duration');
    const ip = ipInput?.value?.trim();
    const reason = reasonInput?.value?.trim() || 'Manual Admin Block';
    const duration = durSelect?.value || '300';
    if(!ip){ fireToast('Please enter an IP address to block.', 'info'); return; }
    btnManualBlock.disabled = true;
    btnManualBlock.textContent = 'Blocking...';
    await triggerBlock(ip, reason, 'High', duration);
    btnManualBlock.disabled = false;
    btnManualBlock.innerHTML = '<i class="bi bi-slash-circle me-1"></i> Block IP on Switch';
    if(ipInput) ipInput.value = '';
  });
}

const btnWhiteAdd = document.getElementById('whitelist-add');
if(btnWhiteAdd){
  btnWhiteAdd.addEventListener('click', async ()=>{
    const input = document.getElementById('whitelist-input');
    const ip = input?.value?.trim();
    if(!ip){ fireToast('Please enter an IP address.', 'info'); return; }
    try{
      const res = await fetch('/api/response/whitelist/add', {
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({ip})
      });
      const result = await res.json();
      if(result.success){
        fireToast(`Added ${ip} to protected whitelist.`, 'success');
        input.value = '';
        fetchResponseState();
      } else {
        fireToast('Failed to add IP to whitelist.', 'critical');
      }
    }catch(e){ fireToast('Whitelist request error: ' + e, 'critical'); }
  });
}

/* =========================================================
   SETTINGS & POLICY CONTROLS
   ========================================================= */

async function renderSettings(){
  try{
    const res = await fetch('/api/settings');
    if(!res.ok) return;
    const data = await res.json();
    const pol = data.policy || {};
    const mode = data.enforcement_mode || 'auto';

    // Set enforcement mode radio
    if(mode === 'host') document.getElementById('mode-host').checked = true;
    else if(mode === 'cisco') document.getElementById('mode-cisco').checked = true;
    else if(mode === 'dry_run') document.getElementById('mode-dry').checked = true;
    else document.getElementById('mode-host').checked = true;

    // Toggle cisco panel
    const ciscoPanel = document.getElementById('cisco-config-panel');
    if(ciscoPanel) ciscoPanel.style.display = (mode === 'cisco') ? 'block' : 'none';

    // Populate policy dropdowns
    if(pol.Critical) document.getElementById('pol-critical').value = pol.Critical;
    if(pol.High) document.getElementById('pol-high').value = pol.High;
    if(pol.Medium) document.getElementById('pol-medium').value = pol.Medium;
    if(pol.Low) document.getElementById('pol-low').value = pol.Low;
    if(pol.temp_block_seconds) document.getElementById('pol-timeout').value = pol.temp_block_seconds;

    // Cisco info
    if(data.cisco?.host) document.getElementById('cfg-cisco-host').value = data.cisco.host;
    if(data.cisco?.username) document.getElementById('cfg-cisco-user').value = data.cisco.username;

    // Update sidebar Engine Target
    const sidebarTarget = document.getElementById('sidebar-cisco-info');
    if(sidebarTarget){
      if(mode === 'cisco' && data.cisco?.host){
        sidebarTarget.textContent = `Cisco (${data.cisco.host})`;
      } else if(mode === 'dry_run'){
        sidebarTarget.textContent = 'Dry-Run (Simulation)';
      } else {
        sidebarTarget.textContent = 'Host Firewall (Local)';
      }
    }
  }catch(e){
    console.warn('Failed to load settings:', e);
  }
}

// Mode radio change listeners
document.querySelectorAll('input[name="enforceMode"]').forEach(radio=>{
  radio.addEventListener('change', e=>{
    const ciscoPanel = document.getElementById('cisco-config-panel');
    if(ciscoPanel) ciscoPanel.style.display = (e.target.value === 'cisco') ? 'block' : 'none';
  });
});

// Save settings button
const btnSaveSettings = document.getElementById('btn-save-settings');
if(btnSaveSettings){
  btnSaveSettings.addEventListener('click', async ()=>{
    const selectedMode = document.querySelector('input[name="enforceMode"]:checked')?.value || 'host';
    const payload = {
      enforcement_mode: selectedMode,
      Critical: document.getElementById('pol-critical')?.value || 'BLOCK',
      High: document.getElementById('pol-high')?.value || 'TEMPORARY_BLOCK',
      Medium: document.getElementById('pol-medium')?.value || 'ALERT',
      Low: document.getElementById('pol-low')?.value || 'LOG',
      temp_block_seconds: parseInt(document.getElementById('pol-timeout')?.value || '300')
    };

    btnSaveSettings.disabled = true;
    btnSaveSettings.innerHTML = '<i class="bi bi-hourglass-split me-1"></i> Saving...';
    try{
      const res = await fetch('/api/settings', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(payload)
      });
      const resData = await res.json();
      if(resData.success){
        fireToast('Settings & policy updated successfully!', 'success');
      } else {
        fireToast('Failed to save settings: ' + (resData.message || 'Unknown error'), 'critical');
      }
    }catch(err){
      fireToast('Network error saving settings: ' + err, 'critical');
    }finally{
      btnSaveSettings.disabled = false;
      btnSaveSettings.innerHTML = '<i class="bi bi-check2-circle me-1"></i> Save All Settings';
    }
  });
}

// Test Cisco SSH connection button
const btnTestCisco = document.getElementById('btn-test-cisco');
if(btnTestCisco){
  btnTestCisco.addEventListener('click', async ()=>{
    const host = document.getElementById('cfg-cisco-host')?.value?.trim();
    const resultDiv = document.getElementById('cisco-test-result');
    if(!host){
      fireToast('Please enter Cisco switch IP address', 'info');
      return;
    }
    btnTestCisco.disabled = true;
    btnTestCisco.innerHTML = '<i class="bi bi-arrow-repeat spin me-1"></i> Testing...';
    if(resultDiv) resultDiv.innerHTML = '<span style="color:var(--text-dim);">Connecting to switch...</span>';
    try{
      const res = await fetch('/api/test-cisco', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({host})
      });
      const data = await res.json();
      if(data.success){
        if(resultDiv) resultDiv.innerHTML = `<span style="color:var(--applied);"><i class="bi bi-check-circle-fill me-1"></i>${data.message}</span>`;
      } else {
        if(resultDiv) resultDiv.innerHTML = `<span style="color:var(--critical);"><i class="bi bi-x-circle-fill me-1"></i>${data.message}</span>`;
      }
    }catch(err){
      if(resultDiv) resultDiv.innerHTML = `<span style="color:var(--critical);">Connection error: ${err}</span>`;
    }finally{
      btnTestCisco.disabled = false;
      btnTestCisco.innerHTML = '<i class="bi bi-hdd-network me-1"></i> Test Switch SSH Connection';
    }
  });
}

// Copy Cisco configuration button
const btnCopyCisco = document.getElementById('btn-copy-cisco');
if(btnCopyCisco){
  btnCopyCisco.addEventListener('click', ()=>{
    const codeEl = document.getElementById('cisco-guide-code');
    if(codeEl){
      navigator.clipboard.writeText(codeEl.innerText).then(()=>{
        fireToast('Cisco commands copied to clipboard!', 'success');
      }).catch(()=>{
        fireToast('Failed to copy text', 'info');
      });
    }
  });
}

/* Init & Polling */
async function init(){
  try{ initPulse(); }catch(e){ console.warn('pulse error', e); }
  tickClock();
  setInterval(tickClock, 1000);
  showPage('dashboard');
  await renderSettings();
  await fetchStatus();
  await fetchEvents();
  renderTrafficChart();
  renderAttackPie();
  setInterval(async ()=>{
    await fetchStatus();
    if(currentPage==='dashboard') await fetchEvents();
    if(currentPage==='topology' && typeof renderTopology==='function') await renderTopology();
    if(currentPage==='response') await fetchResponseState();
  }, 2500);
}

if(document.readyState === 'loading'){
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
