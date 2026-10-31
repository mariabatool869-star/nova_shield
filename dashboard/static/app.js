
let currentRole = "admin"; // Default for demo

async function setRole(role) {
    await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ role: role })
    });
    currentRole = role;
    const btnApprove = document.querySelector('.btn-approve');
    if (role === "viewer") {
        btnApprove.disabled = true;
        btnApprove.innerText = "Locked (Viewer Mode)";
        btnApprove.style.opacity = "0.5";
    } else {
        btnApprove.disabled = false;
        btnApprove.innerText = "✓ Approve Block";
        btnApprove.style.opacity = "1";
    }
}

async function checkLedger() {
    try {
        const res = await fetch('/api/verify');
        const data = await res.json();
        const chain = document.getElementById('vault-chain');
        if (data.status === 'intact') {
            chain.innerHTML = `<span class="chain-badge intact">⛓️ HMAC Ledger: INTACT (${data.count})</span>`;
        } else {
            chain.innerHTML = `<span class="chain-badge compromised">⚠️ Ledger: TAMPERED</span>`;
            showForensicReport(data.report);
        }
    } catch (e) { console.error(e); }
}

function showForensicReport(report) {
    if (document.getElementById('forensic-banner')) return;
    let reportHtml = report.map(r => `Record #${r.id}: ${r.reason}`).join('<br>');
    const banner = document.createElement('div');
    banner.id = 'forensic-banner';
    banner.style.cssText = "position:fixed; top:20px; left:50%; transform:translateX(-50%); background:#ef4444; color:white; padding:20px; border-radius:8px; font-family:monospace; z-index:9999; max-width:600px; text-align:center;";
    banner.innerHTML = `<h3>🚨 FORENSIC ALERT: DATABASE TAMPERED</h3><div>${reportHtml}</div>`;
    document.body.appendChild(banner);
}

async function loadHistory() {
    try {
        const res = await fetch('/api/history');
        const data = await res.json();
        const tbody = document.getElementById('audit-body');
        if (data.records.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" class="empty-table">No records yet.</td></tr>`;
            return;
        }
        tbody.innerHTML = data.records.map(r => `
            <tr>
                <td>#${r.decision_id}</td>
                <td>${new Date(r.recorded_at).toLocaleTimeString()}</td>
                <td>root</td>
                <td><strong style="color: var(--danger)">${r.score}</strong></td>
                <td><span class="decision-badge ${r.human_decision}">${r.human_decision.toUpperCase()}</span></td>
                <td class="hash-cell">${r.hash}</td>
            </tr>
        `).join('');
    } catch (e) { console.error(e); }
}

async function triggerScan() {
    const btn = document.getElementById('scan-btn');
    btn.innerText = "Scanning...";
    const res = await fetch('/api/scan');
    const data = await res.json();
    if (data.status === 'threat') showAlert(data);
    btn.innerText = "▶ Run Scan";
}

function showAlert(data) {
    document.getElementById('resting-state').classList.add('hidden');
    document.getElementById('alert-container').classList.remove('hidden');
    document.getElementById('alert-score').innerText = data.score;
    document.getElementById('alert-raw-log').innerText = data.raw_log;
    document.getElementById('shap-bars').innerHTML = data.explanation.map(item => `
        <div class="shap-bar-row">
            <div class="shap-label">${item.feature}</div>
            <div class="shap-track"><div class="shap-fill ${item.direction}" style="width: ${Math.min(item.magnitude * 250, 100)}%"></div></div>
            <div class="shap-value">${item.impact > 0 ? '+' : ''}${item.impact}</div>
        </div>
    `).join('');
    document.getElementById('alert-counterfactual').innerText = data.counterfactual || "No counterfactual available.";
}

async function makeDecision(decision) {
    const res = await fetch('/api/decide', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ decision: decision })
    });
    const data = await res.json();
    
    if (res.status === 403) {
        alert("SECURITY ALERT: " + data.message);
        return;
    }

    document.getElementById('alert-container').classList.add('hidden');
    document.getElementById('resting-state').classList.remove('hidden');
    checkLedger();
    loadHistory();
}

setInterval(async () => {
    if (document.getElementById('alert-container').classList.contains('hidden')) {
        const res = await fetch('/api/live');
        const data = await res.json();
        if (data.status === 'threat') showAlert(data);
    }
}, 2000);

checkLedger();
loadHistory();