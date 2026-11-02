let currentAlerts = [];
let selectedAlertId = null;

// --- SOCKET.IO CONNECTION (Optional) ---
try {
    const socket = io();
    socket.on('new_alert', (alert) => {
        console.log("📡 Socket received alert:", alert);
        addAlertToFeed(alert);
    });
} catch (e) {
    console.log("Socket.IO not available. Falling back to polling.");
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
    } catch (e) { 
        console.error("Status error:", e);
        document.getElementById('db-status').innerHTML = `<span class="dot red"></span> PostgreSQL: Offline`;
    }
}

// --- ALERT FEED ---
function addAlertToFeed(alert) {
    currentAlerts = [alert]; 
    selectedAlertId = 0; 
    renderFeed();
    renderDetails(alert);
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
                <span class="feed-type">${a.raw_log || a.alert_type || 'Unknown Threat'}</span>
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
    const attackType = document.getElementById('attack-selector')?.value || 'ddos';
    const res = await fetch(`/api/scan?type=${attackType}`);
    const data = await res.json();
    if (data.status === 'threat') {
        addAlertToFeed(data);
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
    try {
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
    } catch (e) {
        console.error("History error:", e);
    }
}

// --- INITIALIZATION ---
currentAlerts = [];
selectedAlertId = null;
renderFeed();
updateStatus();
loadHistory();

// Poll for live alerts (as a fallback)
setInterval(async () => {
    const res = await fetch('/api/live');
    const data = await res.json();
    if (data.status === 'threat') {
        addAlertToFeed(data);
    }
}, 3000);