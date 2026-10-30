// Check ledger status on load and after decisions
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
    } catch (e) {
        console.error("Ledger check failed", e);
    }
}

// Trigger the AI Scan
async function triggerScan() {
    const btn = document.getElementById('scan-btn');
    const resting = document.getElementById('resting-state');
    const container = document.getElementById('alert-container');
    
    btn.innerText = "Scanning...";
    btn.disabled = true;

    try {
        const res = await fetch('/api/scan');
        const data = await res.json();
        
        if (data.status === 'threat') {
            resting.classList.add('hidden');
            container.classList.remove('hidden');
            
            // Populate basic data
            document.getElementById('alert-score').innerText = data.score;
            document.getElementById('alert-raw-log').innerText = data.raw_log;
            
            // Render Visual SHAP Bars
            const shapContainer = document.getElementById('shap-bars');
            shapContainer.innerHTML = data.explanation.map(item => {
                // Scale magnitude for visual (max out at 100% width)
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
            
            // Render Counterfactual
            const cfBox = document.getElementById('counterfactual-box');
            if (data.counterfactual) {
                cfBox.classList.remove('hidden');
                document.getElementById('alert-counterfactual').innerText = data.counterfactual;
            } else {
                cfBox.classList.add('hidden');
            }
        }
    } catch (e) {
        console.error(e);
    } finally {
        btn.innerText = "▶ Run Scan";
        btn.disabled = false;
    }
}

// Handle SERVO Approval Gate
async function makeDecision(decision) {
    try {
        await fetch('/api/decide', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ decision: decision })
        });
        
        // Hide alert, show resting
        document.getElementById('alert-container').classList.add('hidden');
        document.getElementById('resting-state').classList.remove('hidden');
        
        // Refresh ledger count
        checkLedger();
    } catch (e) {
        console.error(e);
    }
}

// Initial check on load
checkLedger();