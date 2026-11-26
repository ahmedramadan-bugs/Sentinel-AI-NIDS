/* =========================================================
   SIMPLE NETWORK DEVICES VIEW (ONLINE / OFFLINE / ATTACKING)
   ========================================================= */

let lastTopologyData = null;
let topoStatusFilter = 'all';

function setTopoFilter(filter) {
  topoStatusFilter = filter;
  document.querySelectorAll('[data-topo-filter]').forEach((btn) => {
    const active = btn.dataset.topoFilter === filter;
    btn.classList.toggle('btn-info', active);
    btn.classList.toggle('btn-outline-secondary', !active);
  });
  if (lastTopologyData) {
    renderTopologyFromData(lastTopologyData);
  }
}

async function renderTopology() {
  const tbody = document.getElementById('topologyTableBody');
  if (!tbody) return;

  try {
    const res = await fetch('/api/topology');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    lastTopologyData = data;
    renderTopologyFromData(data);
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="7" class="text-center py-4" style="color:var(--critical);">Failed to load devices: ${escapeHtml(err.message)}</td></tr>`;
  }
}

function renderTopologyFromData(data) {
  const statsEl = document.getElementById('topologyStats');
  const tbody = document.getElementById('topologyTableBody');
  if (!tbody) return;

  renderTopologyStats(statsEl, data.stats || {});

  let nodes = data.nodes || [];
  if (topoStatusFilter === 'online') {
    nodes = nodes.filter((n) => n.status === 'online');
  } else if (topoStatusFilter === 'offline') {
    nodes = nodes.filter((n) => n.status === 'offline');
  } else if (topoStatusFilter === 'attacking') {
    nodes = nodes.filter((n) => n.status === 'attacking' || n.status === 'blocked');
  }

  renderTopologyTable(tbody, nodes);
}

function renderTopologyStats(el, stats) {
  if (!el) return;
  el.innerHTML = `
    <div class="topo-stat"><div class="val">${stats.total || 0}</div><div class="lbl">Total Devices</div></div>
    <div class="topo-stat"><div class="val" style="color:var(--low);">${stats.online || 0}</div><div class="lbl">Online</div></div>
    <div class="topo-stat"><div class="val" style="color:#94a3b8;">${stats.offline || 0}</div><div class="lbl">Offline</div></div>
    <div class="topo-stat"><div class="val" style="color:var(--critical);">${stats.attacking || 0}</div><div class="lbl">Attacking</div></div>
    <div class="topo-stat"><div class="val" style="color:var(--high);">${stats.blocked || 0}</div><div class="lbl">Blocked</div></div>
  `;
}

function renderTopologyTable(tbody, nodes) {
  if (!nodes.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="text-center py-4" style="color:var(--text-dim);">No devices match this filter yet.</td></tr>';
    return;
  }

  tbody.innerHTML = nodes.map((n) => {
    const isAttacking = n.status === 'attacking';
    const isBlocked = n.status === 'blocked';
    const colorMap = {
      attacking: 'var(--critical)',
      blocked: 'var(--high)',
      online: 'var(--low)',
      offline: '#94a3b8',
    };
    const rowStyle = isAttacking ? 'background:rgba(127, 29, 29, 0.25);' : '';

    return `
      <tr style="${rowStyle}">
        <td class="mono fw-semibold">${escapeHtml(n.ip)}</td>
        <td>${n.internal ? '<span class="badge-status applied">Internal</span>' : '<span class="badge-status pending">External</span>'}</td>
        <td><span style="color:${colorMap[n.status] || '#94a3b8'}; font-weight:700; font-family:var(--mono); font-size:.78rem;">● ${escapeHtml(n.status.toUpperCase())}</span></td>
        <td class="mono">${n.alert_count}</td>
        <td>${escapeHtml(n.last_attack || 'Normal')}</td>
        <td class="mono" style="font-size:.76rem;">${timeAgo(n.last_seen)}</td>
        <td class="text-end">
          ${isBlocked
            ? `<button type="button" class="btn btn-sm btn-outline-success py-0 px-2" onclick="topoToggleBlock('${escapeHtml(n.ip)}', false)">Unblock</button>`
            : `<button type="button" class="btn btn-sm btn-outline-danger py-0 px-2" onclick="topoToggleBlock('${escapeHtml(n.ip)}', true)">Block</button>`
          }
        </td>
      </tr>
    `;
  }).join('');
}

async function topoToggleBlock(ip, shouldBlock) {
  const endpoint = shouldBlock ? '/api/response/block' : '/api/response/unblock';
  try {
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, attack: 'Topology Action', severity: 'High' }),
    });
    const data = await res.json();
    fireToast(data.message || `${shouldBlock ? 'Blocked' : 'Unblocked'} ${ip}`, shouldBlock ? 'critical' : 'success');
    await renderTopology();
  } catch (err) {
    fireToast('Action failed: ' + err.message, 'critical');
  }
}
