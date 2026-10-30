// Check for live packets every 2 seconds
setInterval(async () => {
    // Only check if the alert container is currently hidden
    if (document.getElementById('alert-container').classList.contains('hidden')) {
        const res = await fetch('/api/live');
        const data = await res.json();
        if (data.status === 'threat') {
            showAlert(data);
        }
    }
}, 2000);

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

async function checkLedger() {
    try {
        const res = await fetch('/api/verify');
        const data = await res.json();
        const chain = document.getElementById('vault-chain');
        if (data.status === 'intact') {
            chain.innerHTML = `<span class="chain-badge intact">⛓️ Ledger: INTACT (${data.count})</span>`;
        } else if (data.status === 'compromised') {
            chain.innerHTML = `<span class="chain-badge compromised">⚠️ Ledger: COMPROMISED</span>`;
        } else {
            chain.innerHTML = `<span class="chain-badge checking">Ledger: Empty</span>`;
        }
    } catch (e) { console.error(e); }
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
                    <td>${r.features.is_root_target === 1 ? 'root' : 'user'}</td>
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

checkLedger();
loadHistory();