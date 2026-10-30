async function checkLedger() {
    try {
        const res = await fetch('/api/verify');
        const data = await res.json();
        const chain = document.getElementById('vault-chain');
        
        if (data.status === 'intact') {
            chain.innerHTML = `<span class="chain-badge intact">⛓️ Ledger: INTACT (${data.count} Records)</span>`;
        } else if (data.status === 'compromised') {
            chain.innerHTML = `<span class="chain-badge compromised">⚠️ Ledger: TAMPERED</span>`;
            showForensicReport(data.report);
        } else {
            chain.innerHTML = `<span class="chain-badge checking">Ledger: Empty</span>`;
        }
    } catch (e) { console.error(e); }
}

function showForensicReport(report) {
    // Prevent duplicate banners
    if (document.getElementById('forensic-banner')) return;

    let reportHtml = report.map(r => 
        `Record #${r.id}: Expected ${r.reason} to be <strong>${r.expected}</strong>, but found <strong>${r.actual}</strong>`
    ).join('<br>');

    const banner = document.createElement('div');
    banner.id = 'forensic-banner';
    banner.style.cssText = "position:fixed; top:20px; left:50%; transform:translateX(-50%); background:#ef4444; color:white; padding:20px; border-radius:8px; font-family:monospace; z-index:9999; box-shadow:0 0 30px rgba(239,68,68,0.6); border:2px solid #fca5a5; max-width:600px; text-align:center;";
    banner.innerHTML = `
        <h3 style="margin-bottom:10px;">🚨 FORENSIC ALERT: DATABASE TAMPERED</h3>
        <p style="font-size:13px; margin-bottom:15px;">The cryptographic ledger has detected unauthorized changes:</p>
        <div style="background:rgba(0,0,0,0.3); padding:10px; border-radius:4px; text-align:left; font-size:12px; margin-bottom:15px;">
            ${reportHtml}
        </div>
        <button onclick="this.parentElement.remove()" style="background:white; color:#ef4444; border:none; padding:8px 16px; border-radius:4px; font-weight:bold; cursor:pointer;">Dismiss Alert</button>
    `;
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
        tbody.innerHTML = data.records.map(r => {
            const time = new Date(r.recorded_at).toLocaleTimeString();
            const decisionClass = r.human_decision === 'approved' ? 'approved' : 'rejected';
            return `
                <tr>
                    <td>#${r.decision_id}</td>
                    <td>${time}</td>
                    <td>root</td>
                    <td><strong style="color: var(--danger)">${r.score}</strong></td>
                    <td><span class="decision-badge ${decisionClass}">${r.human_decision.toUpperCase()}</span></td>
                    <td class="hash-cell" title="${r.hash}">${r.hash}</td>
                </tr>
            `;
        }).join('');
    } catch (e) { console.error(e); }
}

async function triggerScan() {
    const btn = document.getElementById('scan-btn');
    btn.innerText = "Scanning...";
    btn.disabled = true;
    try {
        const res = await fetch('/api/scan');
        const data = await res.json();
        if (data.status === 'threat') showAlert(data);
    } catch (e) { console.error(e); } finally {
        btn.innerText = "▶ Run Scan";
        btn.disabled = false;
    }
}

function showAlert(data) {
    document.getElementById('resting-state').classList.add('hidden');
    document.getElementById('alert-container').classList.remove('hidden');
    document.getElementById('alert-score').innerText = data.score;
    document.getElementById('alert-raw-log').innerText = data.raw_log;
    
    const shapContainer = document.getElementById('shap-bars');
    shapContainer.innerHTML = data.explanation.map(item => {
        const widthPct = Math.min(item.magnitude * 250, 100);
        const sign = item.impact > 0 ? '+' : '';
        return `
            <div class="shap-bar-row">
                <div class="shap-label">${item.feature}</div>
                <div class="shap-track">
                    <div class="shap-fill ${item.direction}" style="width: ${widthPct}%"></div>
                </div>
                <div class="shap-value">${sign}${item.impact}</div>
            </div>
        `;
    }).join('');
    
    const cfBox = document.getElementById('counterfactual-box');
    if (data.counterfactual) {
        cfBox.classList.remove('hidden');
        document.getElementById('alert-counterfactual').innerText = data.counterfactual;
    } else {
        cfBox.classList.add('hidden');
    }
}

async function makeDecision(decision) {
    try {
        await fetch('/api/decide', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ decision: decision })
        });
        
        document.getElementById('alert-container').classList.add('hidden');
        document.getElementById('resting-state').classList.remove('hidden');
        checkLedger();
        loadHistory();
    } catch (e) { console.error(e); }
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