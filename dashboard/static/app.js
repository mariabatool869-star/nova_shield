let currentAlerts = [];
let selectedAlertId = null;

// --- ROLE MANAGEMENT ---
async function setRole(role) {
    await fetch('/api/login', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ role: role })
    });
    if (role === 'viewer') {
        document.querySelectorAll('.btn-approve, .btn-reject').forEach(b => b.disabled = true);
    }
}

// --- SYSTEM STATUS ---
async function updateStatus() {
    try {
        const res = await fetch('/api/verify');
        const data = await res.json();
        const vaultBadge = document.getElementById('vault-status');
        if (data.status === 'intact') {
            vaultBadge.innerHTML = `<span class="dot green"></span> Ledger: INTACT (${data.count})`;
        } else {
            vaultBadge.innerHTML = `<span class="dot red"></span> Ledger: TAMPERED`;
        }
        document.getElementById('db-status').innerHTML = `<span class="dot green"></span> PostgreSQL: Online`;
    } catch (e) { console.error(e); }
}

// --- ALERT FEED ---
function addAlertToFeed(alert) {
    currentAlerts.unshift(alert);
    renderFeed();
}

function renderFeed() {
    const feed = document.getElementById('alert-feed');
    document.getElementById('feed-count').innerText = currentAlerts.length;
    if (currentAlerts.length === 0) {
        feed.innerHTML = `<div class="empty-feed">No active threats. System is monitoring.</div>`;
        return;
    }
    feed.innerHTML = currentAlerts.map((a, index) => `
        <div class="feed-item ${selectedAlertId === index ? 'selected' : ''}" onclick="selectAlert(${index})">
            <div class="feed-header">
                <span class="feed-type">${a.alert_type}</span>
                <span class="feed-score">${a.score}</span>
            </div>
            <div class="feed-time">${new Date().toLocaleTimeString()}</div>
        </div>
    `).join('');
}

function selectAlert(index) {
    selectedAlertId = index;
    renderFeed();
    renderDetails(currentAlerts[index]);
}

function renderDetails(alert) {
    const container = document.getElementById('details-container');
    container.innerHTML = `
        <div class="shap-bars">
            ${alert.explanation.map(item => `
                <div class="shap-bar-row">
                    <div class="shap-label">${item.feature}</div>
                    <div class="shap-track"><div class="shap-fill ${item.direction}" style="width: ${Math.min(item.magnitude * 250, 100)}%"></div></div>
                    <div class="shap-value">${item.impact > 0 ? '+' : ''}${item.impact}</div>
                </div>
            `).join('')}
        </div>
        <div class="counterfactual-hint">💡 ${alert.counterfactual}</div>
        <div class="action-buttons">
            <button class="btn-approve" onclick="makeDecision('approve')">✓ Approve Block</button>
            <button class="btn-reject" onclick="makeDecision('reject')">✗ Reject</button>
        </div>
    `;
}

// --- ACTIONS ---
async function triggerScan() {
    const res = await fetch('/api/scan');
    const data = await res.json();
    if (data.status === 'threat') {
        data.alert_type = "DDoS / Port Scan"; // Default name for demo
        addAlertToFeed(data);
        if (selectedAlertId === null) selectAlert(0);
    }
}

async function makeDecision(decision) {
    const res = await fetch('/api/decide', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ decision: decision })
    });
    const data = await res.json();
    if (res.status === 403) {
        alert("SECURITY: Only Admins can block.");
        return;
    }
    currentAlerts = [];
    selectedAlertId = null;
    renderFeed();
    document.getElementById('details-container').innerHTML = `<div class="empty-details"><span>🛡️</span><p>Decision recorded. Select a new alert.</p></div>`;
    updateStatus();
    loadHistory();
}

// --- AUDIT HISTORY ---
async function loadHistory() {
    const res = await fetch('/api/history');
    const data = await res.json();
    const tbody = document.getElementById('audit-body');
    if (data.records.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="empty-table">No records.</td></tr>`;
        return;
    }
    tbody.innerHTML = data.records.map(r => `
        <tr>
            <td>#${r.decision_id}</td>
            <td>${new Date(r.recorded_at).toLocaleTimeString()}</td>
            <td>${r.alert_type}</td>
            <td style="color: var(--danger)">${r.score}</td>
            <td>${r.human_decision.toUpperCase()}</td>
            <td>${r.analyst}</td>
            <td class="hash-cell">${r.hash}</td>
        </tr>
    `).join('');
}

// --- INITIALIZATION ---
setInterval(async () => {
    const res = await fetch('/api/live');
    const data = await res.json();
    if (data.status === 'threat') {
        data.alert_type = "Live Network Anomaly";
        addAlertToFeed(data);
    }
}, 3000);

updateStatus();
loadHistory();