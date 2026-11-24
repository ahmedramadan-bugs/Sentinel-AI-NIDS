/* =========================================================
   KALI LINUX CONSOLE & PLAYBOOKS
   ========================================================= */

let kaliInitialized = false;

async function initConsolePage() {
  if (!kaliInitialized) {
    kaliInitialized = true;
    setupKaliEvents();
    await loadKaliPlaybooks();
  }
  await refreshKaliStatus();
}

function setupKaliEvents() {
  const connectForm = document.getElementById('kaliConnectForm');
  const disconnectBtn = document.getElementById('kaliDisconnectBtn');
  const execForm = document.getElementById('kaliExecForm');
  const clearBtn = document.getElementById('kaliClearBtn');

  if (connectForm) {
    connectForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const payload = {
        host: document.getElementById('kaliHost').value.trim(),
        port: parseInt(document.getElementById('kaliPort').value, 10) || 22,
        username: document.getElementById('kaliUser').value.trim(),
        password: document.getElementById('kaliPassword').value,
        mode: document.getElementById('kaliMode').value,
      };
      try {
        const res = await fetch('/api/kali/connect', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        const data = await res.json();
        fireToast(data.message || 'Updated connection', data.success ? 'success' : 'critical');
        updateKaliStatusUi(data);
      } catch (err) {
        fireToast('Connection error: ' + err.message, 'critical');
      }
    });
  }

  if (disconnectBtn) {
    disconnectBtn.addEventListener('click', async () => {
      const res = await fetch('/api/kali/disconnect', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
      const data = await res.json();
      fireToast(data.message || 'Disconnected', 'info');
      updateKaliStatusUi(data);
    });
  }

  if (execForm) {
    execForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const input = document.getElementById('kaliCmdInput');
      const cmd = input.value.trim();
      if (!cmd) return;
      await runKaliCommand(cmd);
      input.value = '';
    });
  }

  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      const term = document.getElementById('kaliTerminalOutput');
      if (term) term.innerHTML = '<div class="meta-line">Terminal cleared. Ready for commands.</div>';
    });
  }
}

async function refreshKaliStatus() {
  try {
    const res = await fetch('/api/kali/status');
    const data = await res.json();
    updateKaliStatusUi(data);
  } catch (err) {
    console.warn('Kali status error', err);
  }
}

function updateKaliStatusUi(data) {
  const badge = document.getElementById('kaliConnBadge');
  if (!badge) return;
  if (data.connected) {
    badge.className = 'badge-status applied';
    badge.textContent = `CONNECTED (${data.mode === 'simulation' ? 'DEMO' : 'SSH'}: ${data.username}@${data.host})`;
  } else {
    badge.className = 'badge-status failed';
    badge.textContent = 'DISCONNECTED';
  }
}

async function loadKaliPlaybooks() {
  const container = document.getElementById('kaliPlaybooksGrid');
  if (!container) return;
  try {
    const res = await fetch('/api/kali/playbooks');
    const data = await res.json();
    const playbooks = data.playbooks || [];
    container.innerHTML = playbooks.map((pb) => `
      <button type="button" class="playbook-btn" data-cmd="${escapeHtml(pb.command)}">
        <div class="pb-cat">${escapeHtml(pb.category)}</div>
        <div class="pb-name">${escapeHtml(pb.name)}</div>
        <div class="pb-desc">${escapeHtml(pb.description)}</div>
      </button>
    `).join('');

    container.querySelectorAll('.playbook-btn').forEach((btn) => {
      btn.addEventListener('click', async () => {
        const target = (document.getElementById('kaliTargetIp')?.value || '192.168.56.10').trim();
        const cmd = btn.dataset.cmd.replace('{target}', target);
        const input = document.getElementById('kaliCmdInput');
        if (input) input.value = cmd;
        await runKaliCommand(cmd, target);
      });
    });
  } catch (err) {
    container.innerHTML = `<div style="color:var(--critical); font-size:.82rem;">Failed to load playbooks: ${escapeHtml(err.message)}</div>`;
  }
}

async function runKaliCommand(command, targetOverride) {
  const term = document.getElementById('kaliTerminalOutput');
  const target = targetOverride || (document.getElementById('kaliTargetIp')?.value || '192.168.56.10').trim();

  if (term) {
    const cmdDiv = document.createElement('div');
    cmdDiv.className = 'cmd-line';
    cmdDiv.textContent = `$ ${command}`;
    term.appendChild(cmdDiv);
    term.scrollTop = term.scrollHeight;
  }

  try {
    const res = await fetch('/api/kali/exec', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ command, target }),
    });
    const data = await res.json();
    if (term) {
      if (data.stdout) {
        const out = document.createElement('div');
        out.textContent = data.stdout;
        term.appendChild(out);
      }
      if (data.stderr) {
        const errDiv = document.createElement('div');
        errDiv.className = 'err-line';
        errDiv.textContent = data.stderr;
        term.appendChild(errDiv);
      }
      term.scrollTop = term.scrollHeight;
    }
    if (data.success) {
      // Refresh dashboard & topology data so attacks appear immediately across views
      if (typeof fetchEvents === 'function') fetchEvents();
      if (typeof renderTopology === 'function' && currentPage === 'topology') renderTopology();
    } else if (data.stderr) {
      fireToast(data.stderr, 'critical');
    }
  } catch (err) {
    fireToast('Command execution failed: ' + err.message, 'critical');
  }
}
