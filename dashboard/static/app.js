let currentAlerts = [];
let selectedAlertId = null;

// --- ADMINISTRATOR AUTHENTICATION ---
function handleAuthenticationFailure(response) {
    if (response.status !== 401 && response.status !== 403) {
        return false;
    }

    authGeneration += 1;
    setAuthenticationState(false);

    const status = document.getElementById('auth-status');
    if (status) status.textContent = 'Session expired. Sign in again.';

    return true;
}

let adminAuthenticated = false;
let adminCsrfToken = null;
let authGeneration = 0;
let adminSocket = null;

function connectAdminSocket() {
    if (NOVASHIELD_FRONTEND_OFFLINE) return;
    if (!adminAuthenticated || adminSocket || typeof io !== 'function') return;

    try {
        adminSocket = io({ autoConnect: false });
        adminSocket.on('new_alert', (alert) => {
            if (adminAuthenticated) addAlertToFeed(alert);
        });
        adminSocket.connect();
    } catch (error) {
        adminSocket = null;
        console.warn('Socket unavailable; polling remains available.');
    }
}

function setAuthenticationState(authenticated) {
    adminAuthenticated = authenticated === true;
    if (adminAuthenticated) {
        refreshTelemetryPanel();
    } else {
        resetTelemetryPanel();
    }

    const status = document.getElementById('auth-status');
    const form = document.getElementById('login-form');
    const logout = document.getElementById('logout-btn');
    const scan = document.getElementById('scan-btn');

    if (status) {
        status.textContent = adminAuthenticated
            ? 'Signed in as administrator'
            : 'Not signed in';
    }

    if (form) form.hidden = adminAuthenticated;
    if (logout) logout.hidden = !adminAuthenticated;
    if (scan) scan.disabled = !adminAuthenticated || NOVASHIELD_FRONTEND_OFFLINE;
    const offlineButton = document.getElementById('phase6-run-btn');
    if (offlineButton) offlineButton.disabled = !adminAuthenticated;

    const pcapButton = document.getElementById('offline-pcap-run-btn');
    if (pcapButton) {
        pcapButton.disabled = !adminAuthenticated || !adminCsrfToken;
    }

    if (!adminAuthenticated) {
        const pcapStatus = document.getElementById('offline-pcap-status');
        const pcapSummary = document.getElementById('offline-pcap-summary');
        const pcapBody = document.getElementById('offline-pcap-feature-body');

        if (pcapStatus) {
            pcapStatus.textContent =
                'Sign in as an administrator to inspect offline features.';
        }
        if (pcapSummary) pcapSummary.replaceChildren();
        if (pcapBody) pcapBody.replaceChildren();
    }


    if (adminAuthenticated) {
        connectAdminSocket();
    } else {
        adminCsrfToken = null;
        if (adminSocket) {
            adminSocket.disconnect();
            adminSocket = null;
        }
        currentAlerts = [];
        selectedAlertId = null;
        renderFeed();
    }
}

async function initializeAuthentication() {
    const generation = ++authGeneration;
    setAuthenticationState(false);

    try {
        const response = await fetch('/api/session', {
            credentials: 'same-origin',
            cache: 'no-store'
        });

        if (generation !== authGeneration) return;
        if (!response.ok) return;

        const data = await response.json();
        if (generation !== authGeneration) return;

        const authenticated =
            data.authenticated === true &&
            data.role === 'admin' &&
            typeof data.csrf_token === 'string' &&
            data.csrf_token.length >= 32;

        adminCsrfToken = authenticated ? data.csrf_token : null;
        setAuthenticationState(authenticated);
    } catch (error) {
        console.warn('Session check unavailable.');
    }
}

async function submitAdminLogin(event) {
    event.preventDefault();

    const input = document.getElementById('admin-password');
    const button = document.getElementById('login-btn');
    const status = document.getElementById('auth-status');

    if (!input || !input.value) return;

    const password = input.value;
    input.value = '';
    const generation = ++authGeneration;

    if (button) button.disabled = true;

    try {
        const response = await fetch('/api/login', {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password })
        });

        if (generation !== authGeneration) return;

        if (!response.ok) {
            setAuthenticationState(false);
            if (status) status.textContent = 'Sign in failed';
            return;
        }

        const data = await response.json();
        if (generation !== authGeneration) return;

        const authenticated =
            data.status === 'success' && data.role === 'admin';

        if (!authenticated) {
            setAuthenticationState(false);
            return;
        }

        // Fetch the session-bound token before enabling controls.
        const sessionResponse = await fetch('/api/session', {
            credentials: 'same-origin',
            cache: 'no-store'
        });

        if (generation !== authGeneration) return;

        if (!sessionResponse.ok) {
            setAuthenticationState(false);
            if (status) status.textContent = 'Session verification failed';
            return;
        }

        const sessionData = await sessionResponse.json();
        if (generation !== authGeneration) return;

        const verified =
            sessionData.authenticated === true &&
            sessionData.role === 'admin' &&
            typeof sessionData.csrf_token === 'string' &&
            sessionData.csrf_token.length >= 32;

        adminCsrfToken = verified ? sessionData.csrf_token : null;
        setAuthenticationState(verified);

        if (verified) {
            updateStatus();
            loadHistory();
        } else if (status) {
            status.textContent = 'Session verification failed';
        }
    } catch (error) {
        if (generation === authGeneration) {
            setAuthenticationState(false);
            if (status) status.textContent = 'Sign in unavailable';
        }
    } finally {
        if (button) button.disabled = false;
    }
}

async function signOutAdministrator() {
    const button = document.getElementById('logout-btn');
    const status = document.getElementById('auth-status');
    const generation = ++authGeneration;
    const logoutCsrfToken = adminCsrfToken || '';

    // Hide administrator data immediately, before the server responds.
    setAuthenticationState(false);

    if (button) button.disabled = true;

    // Disable privileged controls while logout is in progress.
    const scan = document.getElementById('scan-btn');
    if (scan) scan.disabled = true;

    try {
        const response = await fetch('/api/logout', {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'X-CSRF-Token': logoutCsrfToken
            }
        });

        if (generation !== authGeneration) return;

        if (!response.ok) {
            if (status) status.textContent = 'Sign out failed';
            await initializeAuthentication();
            return;
        }

        setAuthenticationState(false);
    } catch (error) {
        if (status) status.textContent = 'Sign out unavailable';
        await initializeAuthentication();
    } finally {
        if (button) button.disabled = false;
    }
}

function installAuthenticationControls() {
    const form = document.getElementById('login-form');
    const logout = document.getElementById('logout-btn');

    if (form) form.addEventListener('submit', submitAdminLogin);
    if (logout) logout.addEventListener('click', signOutAdministrator);

    initializeAuthentication();
}




// --- SYSTEM STATUS ---
async function updateStatus() {
    if (NOVASHIELD_FRONTEND_OFFLINE) return;
    if (!adminAuthenticated) return;

    const generation = authGeneration;

    try {
        const res = await fetch('/api/verify');

        if (generation !== authGeneration) return;
        if (handleAuthenticationFailure(res)) return;
        if (!res.ok) return;

        const data = await res.json();

        if (generation !== authGeneration || !adminAuthenticated) return;

        const vaultBadge = document.getElementById('vault-status');

        if (data.status === 'intact') {
            vaultBadge.innerHTML =
                `<span class="dot green"></span> Ledger: INTACT (${escapeHTML(data.count)})`;
        } else {
            vaultBadge.innerHTML =
                '<span class="dot red"></span> Ledger: TAMPERED';
        }

        document.getElementById('db-status').innerHTML =
            '<span class="dot green"></span> PostgreSQL: Online';

    } catch (e) {
        if (generation !== authGeneration) return;

        console.error("Status error:", e);

        document.getElementById('db-status').innerHTML =
            '<span class="dot red"></span> PostgreSQL: Offline';
    }
}

// --- ALERT FEED ---
function isValidAlert(alert) {
    return alert !== null
        && typeof alert === 'object'
        && !Array.isArray(alert)
        && typeof alert.alert_id === 'string'
        && alert.alert_id.trim().length > 0
        && Array.isArray(alert.explanation)
        && alert.explanation.every(
            item => item !== null
                && typeof item === 'object'
                && !Array.isArray(item)
        );
}

function addAlertToFeed(alert) {
    if (!isValidAlert(alert)) {
        console.warn("Alert rejected: invalid alert structure");
        return;
    }
    if (currentAlerts.some(a => a.alert_id === alert.alert_id)) return;
    currentAlerts.unshift(alert);
    if (selectedAlertId === null) selectedAlertId = alert.alert_id;
    renderFeed();
    const selectedAlert = currentAlerts.find(a => a.alert_id === selectedAlertId);
    if (selectedAlert) renderDetails(selectedAlert);
}

function escapeHTML(value) {
    return String(value ?? '').replace(/[&<>"']/g, char => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    })[char]);
}

function safeDirection(value) {
    return value === 'positive' || value === 'negative'
        ? value
        : '';
}

function safeBarWidth(value) {
    const number = Number(value);
    if (!Number.isFinite(number)) return 0;
    return Math.round(Math.max(0, Math.min(number * 250, 100)));
}

function renderFeed() {
    const feed = document.getElementById('alert-feed');
    document.getElementById('feed-count').innerText = currentAlerts.length;
    if (currentAlerts.length === 0) {
        feed.innerHTML = `<div class="empty-feed">${NOVASHIELD_FRONTEND_OFFLINE ? "Offline research mode — live monitoring is disabled." : "No registered alerts. Continuous monitoring has not been verified."}</div>`;
        return;
    }
    feed.innerHTML = currentAlerts.map((a, index) => `
        <div class="feed-item ${selectedAlertId === a.alert_id ? 'selected' : ''}" data-alert-index="${index}">
            <div class="feed-header">
                <span class="feed-type">${escapeHTML(a.raw_log || a.alert_type || 'Unknown Threat')}</span>
                <span class="feed-score">${escapeHTML(a.score)}</span>
            </div>
            <div class="feed-time">${new Date().toLocaleTimeString()}</div>
        </div>
    `).join('');
}

function selectAlert(index) {
    const alert = currentAlerts[index];
    if (!alert) return;
    selectedAlertId = alert.alert_id;
    renderFeed();
    renderDetails(alert);
}

function renderDetails(alert) {
    const container = document.getElementById('details-container');
    container.innerHTML = `
        <div class="shap-bars">
            ${alert.explanation.map(item => `
                <div class="shap-bar-row">
                    <div class="shap-label">${escapeHTML(item.feature)}</div>
                    <div class="shap-track"><div class="shap-fill ${safeDirection(item.direction)} width-${safeBarWidth(item.magnitude)}"></div></div>
                    <div class="shap-value">${escapeHTML(item.impact > 0 ? '+' : '')}${escapeHTML(item.impact)}</div>
                </div>
            `).join('')}
        </div>
        <div class="counterfactual-hint">💡 ${escapeHTML(alert.counterfactual)}</div>
        <div class="action-buttons">
            <button class="btn-approve" data-decision="approve">✓ Approve Block</button>
            <button class="btn-reject" data-decision="reject">✗ Reject</button>
        </div>
    `;
}

// --- DASHBOARD EVENT HANDLERS ---
function installDashboardEventHandlers() {
    const scanButton = document.getElementById('scan-btn');
    const feed = document.getElementById('alert-feed');
    const details = document.getElementById('details-container');

    if (scanButton) {
        scanButton.addEventListener('click', () => {
            if (adminAuthenticated) triggerScan();
        });
    }

    if (feed) {
        feed.addEventListener('click', (event) => {
            const item = event.target.closest('[data-alert-index]');
            if (!item || !feed.contains(item)) return;
            if (!adminAuthenticated) return;

            const index = Number(item.dataset.alertIndex);
            if (Number.isInteger(index)) selectAlert(index);
        });
    }

    if (details) {
        details.addEventListener('click', (event) => {
            const button = event.target.closest('[data-decision]');
            if (!button || !details.contains(button)) return;
            if (!adminAuthenticated) return;

            const decision = button.dataset.decision;
            if (decision === 'approve' || decision === 'reject') {
                makeDecision(decision);
            }
        });
    }
}

// --- ACTIONS ---
async function triggerScan() {
    if (NOVASHIELD_FRONTEND_OFFLINE) return;
    if (!adminAuthenticated || !adminCsrfToken) return;
    const generation = authGeneration;
    const res = await fetch('/api/scan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': adminCsrfToken
        },
        body: JSON.stringify({})
    });
    if (generation !== authGeneration) return;
    if (handleAuthenticationFailure(res)) return;
    if (!res.ok) return;

    const data = await res.json();
    if (generation !== authGeneration || !adminAuthenticated) return;

    if (data.status === 'threat') {
        addAlertToFeed(data);
    }
}

async function makeDecision(decision) {
    if (NOVASHIELD_FRONTEND_OFFLINE) return;
    if (!adminAuthenticated || !adminCsrfToken) return;
    const generation = authGeneration;
    const alertId = selectedAlertId;
    const selected = currentAlerts.find(a => a.alert_id === alertId);

    if (!selected) {
        window.alert("Select an alert before making a decision.");
        return;
    }

    if (!["approve", "reject"].includes(decision)) return;

    try {
        const res = await fetch('/api/decide', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': adminCsrfToken
            },
            body: JSON.stringify({
                decision: decision,
                alert_id: alertId
            })
        });

        if (generation !== authGeneration) return;
        if (handleAuthenticationFailure(res)) return;

        const data = await res.json();
        if (generation !== authGeneration || !adminAuthenticated) return;

        if (!res.ok || data.status !== "success") {
            window.alert(data.message || "Decision failed.");
            return;
        }

        currentAlerts = currentAlerts.filter(
            a => a.alert_id !== alertId
        );

        if (selectedAlertId === alertId) {
            selectedAlertId = currentAlerts.length
                ? currentAlerts[0].alert_id
                : null;
        }

        renderFeed();

        if (selectedAlertId !== null) {
            const next = currentAlerts.find(
                a => a.alert_id === selectedAlertId
            );
            if (next) renderDetails(next);
        } else {
            document.getElementById('details-container').innerHTML =
                '<div class="empty-details"><p>No alert selected.</p></div>';
        }

        updateStatus();
        loadHistory();

    } catch (error) {
        console.error("Decision request failed:", error);
        window.alert("Decision request failed. Alert retained.");
    }
}

// --- AUDIT HISTORY ---
async function loadHistory() {
    if (NOVASHIELD_FRONTEND_OFFLINE) return;
    if (!adminAuthenticated) return;

    const generation = authGeneration;

    try {
        const res = await fetch('/api/history');

        if (generation !== authGeneration) return;
        if (handleAuthenticationFailure(res)) return;
        if (!res.ok) return;

        const data = await res.json();

        if (generation !== authGeneration || !adminAuthenticated) return;

        if (!data || !Array.isArray(data.records)) {
            console.warn("Unexpected audit history response");
            return;
        }

        const tbody = document.getElementById('audit-body');

        if (data.records.length === 0) {
            tbody.innerHTML =
                '<tr><td colspan="7" class="empty-table">No records.</td></tr>';
            return;
        }

        tbody.innerHTML = data.records.map(r => `
            <tr>
                <td>#${escapeHTML(r.decision_id)}</td>
                <td>${escapeHTML(new Date(r.recorded_at).toLocaleTimeString())}</td>
                <td>${escapeHTML(r.alert_type)}</td>
                <td class="score-danger">${escapeHTML(r.score)}</td>
                <td>${escapeHTML(String(r.human_decision ?? '').toUpperCase())}</td>
                <td>${escapeHTML(r.analyst)}</td>
                <td class="hash-cell">${escapeHTML(r.hash)}</td>
            </tr>
        `).join('');

    } catch (e) {
        if (generation !== authGeneration) return;
        console.error("History error:", e);
    }
}

// --- INITIALIZATION ---
currentAlerts = [];
selectedAlertId = null;
renderFeed();
installAuthenticationControls();
installDashboardEventHandlers();

// Poll for pending alerts as a SocketIO fallback.
setInterval(async () => {
    if (NOVASHIELD_FRONTEND_OFFLINE) return;
    if (!adminAuthenticated) return;
    try {
        const generation = authGeneration;
        const res = await fetch('/api/live');

        if (generation !== authGeneration) return;
        if (handleAuthenticationFailure(res)) return;

        if (!res.ok) {
            console.warn("Alert polling failed:", res.status);
            return;
        }

        const data = await res.json();
        if (generation !== authGeneration || !adminAuthenticated) return;

        if (!data || !Array.isArray(data.alerts)) {
            console.warn("Unexpected alert polling response");
            return;
        }

        for (const alert of data.alerts) {
            addAlertToFeed(alert);
        }
    } catch (error) {
        console.warn("Alert polling unavailable:", error);
    }
}, 3000);


// PHASE 6: Offline CIC AI analysis within the original dashboard.
// Separate from live alerts, approvals, SIEM, Vault and Servo.
(function () {
    'use strict';

    function addText(parent, tag, text) {
        const element = document.createElement(tag);
        element.textContent = String(text);
        parent.appendChild(element);
        return element;
    }

    function renderModel(parent, title, model) {
        const section = document.createElement('section');
        addText(section, 'h3', title);
        addText(section, 'p', 'Prediction: ' + model.prediction);
        addText(
            section, 'p',
            'Model confidence: ' +
            (Number(model.confidence) * 100).toFixed(2) + '%'
        );
        addText(
            section, 'p',
            'Predicted-class Tree SHAP (' + model.shap_output + ')'
        );

        const list = document.createElement('ol');
        for (const item of model.explanation || []) {
            addText(
                list, 'li',
                item.feature + ': ' +
                Number(item.shap_value).toFixed(5) +
                ' (' + item.direction + ')'
            );
        }
        section.appendChild(list);
        parent.appendChild(section);
    }

    async function runOfflineAnalysis() {
        const button = document.getElementById('phase6-run-btn');
        const input = document.getElementById('phase6-row-index');
        const status = document.getElementById('phase6-status');
        const results = document.getElementById('phase6-results');

        if (!button || !input || !status || !results) return;
        if (!adminAuthenticated || !adminCsrfToken) {
            status.textContent = 'Administrator sign-in required.';
            return;
        }

        const row = Number(input.value);
        if (
            !Number.isInteger(row) ||
            input.value.trim() === '' ||
            row < 0 || row > 19999
        ) {
            status.textContent = 'Choose a whole-number row from 0 to 19999.';
            return;
        }

        const generation = authGeneration;
        button.disabled = true;
        results.replaceChildren();
        status.textContent = 'Analyzing offline CIC flow...';

        try {
            const response = await fetch('/api/phase6/offline-predict', {
                method: 'POST',
                credentials: 'same-origin',
                cache: 'no-store',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': adminCsrfToken
                },
                body: JSON.stringify({ row_index: row })
            });

            if (generation !== authGeneration) return;
            if (handleAuthenticationFailure(response)) return;

            const data = await response.json();
            if (!response.ok || data.status !== 'success') {
                throw new Error(
                    data.message || 'Offline prediction unavailable.'
                );
            }

            if (generation !== authGeneration || !adminAuthenticated) return;

            status.textContent = 'Offline analysis completed for row ' + row;
            addText(
                results, 'p',
                'Models agree: ' + (data.models_agree ? 'Yes' : 'No')
            );
            renderModel(results, 'Random Forest', data.random_forest);
            renderModel(results, 'LightGBM', data.lightgbm);

            if (data.soc_report) {
                const report = data.soc_report;

                addText(results, 'h3', 'SOC Investigation Report');
                addText(results, 'p', 'Case ID: ' + report.case_id);
                addText(results, 'p', 'Classification: ' + report.classification);
                addText(results, 'p', 'Status: ' + report.status);
                addText(results, 'p', 'Assessment: ' + report.assessment);
                addText(results, 'p', 'Recommended action: ' + report.recommended_action);

                if (report.evidence) {
                    addText(results, 'h4', 'AI Evidence');
                    for (const name of ['random_forest', 'lightgbm']) {
                        const model = report.evidence[name];
                        if (!model) continue;
                        addText(results, 'p',
                            (name === 'random_forest' ? 'Random Forest' : 'LightGBM')
                            + ': ' + model.prediction);
                        if (Array.isArray(model.top_features)) {
                            model.top_features.forEach(feature => {
                                addText(
                                    results, 'p',
                                    feature.feature + ': ' +
                                    Number(feature.shap_value).toFixed(5) +
                                    ' (' + feature.direction + ')' +
                                    ' | Observed value: ' + feature.value
                                );
                            });
                        }
                    }
                }

                if (Array.isArray(report.investigation_steps)) {
                    addText(results, 'h4', 'Recommended Investigation Steps');
                    report.investigation_steps.forEach((step, i) => {
                        addText(results, 'p', (i + 1) + '. ' + step);
                    });
                }

                if (Array.isArray(report.limitations)) {
                    addText(results, 'h4', 'Evidence Limitations');
                    report.limitations.forEach((item, i) => {
                        addText(results, 'p', (i + 1) + '. ' + item);
                    });
                }

                addText(results, 'p', 'Human approval required: Yes');
                addText(results, 'p', 'Enforcement: Disabled');

                // Phase 7C: Human review of this server-registered SOC case.
                const review = document.createElement('section');
                addText(review, 'h4', 'Human Analyst Review');

                const decisionLabel = addText(review, 'label', 'Analyst decision');
                const decisionSelect = document.createElement('select');
                decisionSelect.setAttribute('aria-label', 'Analyst decision');

                for (const [value, label] of [
                    ['', 'Select a decision'],
                    ['CONFIRMED_THREAT', 'Confirmed Threat'],
                    ['FALSE_POSITIVE', 'False Positive'],
                    ['NEEDS_INVESTIGATION', 'Needs Investigation']
                ]) {
                    const option = document.createElement('option');
                    option.value = value;
                    option.textContent = label;
                    decisionSelect.appendChild(option);
                }

                decisionLabel.appendChild(decisionSelect);

                const justificationLabel = addText(
                    review, 'label', 'Written justification (required)'
                );
                const justification = document.createElement('textarea');
                justification.rows = 4;
                justification.required = true;
                justification.setAttribute(
                    'aria-label', 'Written justification'
                );
                justificationLabel.appendChild(justification);

                const submit = document.createElement('button');
                submit.type = 'button';
                submit.textContent = 'Submit Review';
                review.appendChild(submit);

                const reviewStatus = addText(
                    review, 'p', 'Awaiting analyst review. No audit record persisted.'
                );
                reviewStatus.setAttribute('role', 'status');

                submit.addEventListener('click', async () => {
                    if (generation !== authGeneration ||
                        !adminAuthenticated || !adminCsrfToken) {
                        reviewStatus.textContent = 'Administrator sign-in required.';
                        return;
                    }

                    if (!decisionSelect.value || !justification.value.trim()) {
                        reviewStatus.textContent =
                            'Select a decision and provide written justification.';
                        return;
                    }

                    submit.disabled = true;
                    reviewStatus.textContent = 'Submitting analyst review...';

                    try {
                        const response = await fetch('/api/phase7/soc-decide', {
                            method: 'POST',
                            credentials: 'same-origin',
                            cache: 'no-store',
                            headers: {
                                'Content-Type': 'application/json',
                                'X-CSRF-Token': adminCsrfToken
                            },
                            body: JSON.stringify({
                                case_id: report.case_id,
                                decision: decisionSelect.value,
                                justification: justification.value.trim()
                            })
                        });

                        const data = await response.json();

                        if (generation !== authGeneration ||
                            !adminAuthenticated) return;

                        if (!response.ok || data.status !== 'success') {
                            reviewStatus.textContent =
                                data.message || 'Review submission failed.';
                            return;
                        }

                        decisionSelect.disabled = true;
                        justification.disabled = true;
                        reviewStatus.textContent =
                            'Review accepted: ' +
                            data.decision.human_decision +
                            '. Audit status: ' +
                            data.decision.audit_status +
                            '. Enforcement disabled.';
                    } catch (error) {
                        if (generation === authGeneration) {
                            reviewStatus.textContent =
                                'Review unavailable: ' + error.message;
                        }
                    } finally {
                        if (generation === authGeneration &&
                            decisionSelect.disabled !== true) {
                            submit.disabled = false;
                        }
                    }
                });

                results.appendChild(review);
            } else if (data.soc_report === null) {
                addText(results, 'p', 'SOC assessment: No investigation report required for this benign flow.');
            }

            addText(
                results, 'p',
                'Offline research result only. No firewall action or alert created.'
            );
        } catch (error) {
            if (generation === authGeneration) {
                status.textContent = 'Analysis unavailable: ' + error.message;
            }
        } finally {
            if (generation === authGeneration) {
                button.disabled = !adminAuthenticated;
            }
        }
    }

    function initializeOfflineAnalysis() {
        const button = document.getElementById('phase6-run-btn');
        if (button) {
            button.addEventListener('click', runOfflineAnalysis);
            button.disabled = !adminAuthenticated || !adminCsrfToken;
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener(
            'DOMContentLoaded', initializeOfflineAnalysis
        );
    } else {
        initializeOfflineAnalysis();
    }
})();


// NX-01: Completed network observation telemetry.
// Read-only. Separate from the alert feed and active packet capture.
function resetTelemetryPanel(message) {
    const values = {
        'telemetry-packets': '—',
        'telemetry-tcp': '—',
        'telemetry-udp': '—',
        'telemetry-other': '—',
        'telemetry-interface': '—',
        'telemetry-timestamp': '—',
        'telemetry-age': '—',
        'telemetry-provenance': '—'
    };

    for (const [id, value] of Object.entries(values)) {
        const element = document.getElementById(id);
        if (element) element.textContent = value;
    }

    const capture = document.getElementById('telemetry-capture-status');
    if (capture) capture.textContent = 'Capture inactive';

    const status = document.getElementById('telemetry-status');
    if (status) {
        status.textContent = message || (
            'Sign in as an administrator to view the last observation.'
        );
    }
}

async function refreshTelemetryPanel() {
    if (!adminAuthenticated) return;

    const generation = authGeneration;

    try {
        const response = await fetch('/api/telemetry', {
            credentials: 'same-origin',
            cache: 'no-store'
        });

        if (generation !== authGeneration || !adminAuthenticated) return;
        if (handleAuthenticationFailure(response)) return;

        if (!response.ok) {
            resetTelemetryPanel(
                'Completed observation unavailable (HTTP ' +
                response.status + ').'
            );
            return;
        }

        const data = await response.json();

        if (generation !== authGeneration || !adminAuthenticated) return;

        const counts = data && data.protocol_counts;
        const valid = (
            data.status === 'success' &&
            data.mode === 'completed_observation' &&
            data.capture_active === false &&
            data.ai_status === 'not_run' &&
            data.enforcement_enabled === false &&
            counts &&
            Number.isSafeInteger(data.observed_packet_lines) &&
            data.observed_packet_lines >= 0 &&
            ['tcp', 'udp', 'other', 'ipv4', 'ipv6'].every(
                key => Number.isSafeInteger(counts[key]) &&
                       counts[key] >= 0
            ) &&
            counts.tcp + counts.udp + counts.other ===
                data.observed_packet_lines &&
            counts.ipv4 + counts.ipv6 ===
                data.observed_packet_lines &&
            typeof data.interface === 'string' &&
            typeof data.collected_at === 'string' &&
            Number.isFinite(data.age_seconds) &&
            data.age_seconds >= 0
        );

        if (!valid) {
            resetTelemetryPanel('Invalid observation response.');
            return;
        }

        const values = {
            'telemetry-packets': data.observed_packet_lines,
            'telemetry-tcp': counts.tcp,
            'telemetry-udp': counts.udp,
            'telemetry-other': counts.other,
            'telemetry-interface': data.interface,
            'telemetry-timestamp': data.collected_at,
            'telemetry-age': Math.round(data.age_seconds) +
                ' seconds at last refresh',
            'telemetry-provenance': data.provenance || 'Unknown'
        };

        for (const [id, value] of Object.entries(values)) {
            const element = document.getElementById(id);
            if (element) element.textContent = String(value);
        }

        const capture = document.getElementById('telemetry-capture-status');
        if (capture) capture.textContent = 'Capture inactive';

        const status = document.getElementById('telemetry-status');
        if (status) {
            status.textContent =
                'Last completed observation. Not continuous monitoring.';
        }
    } catch (error) {
        if (generation !== authGeneration || !adminAuthenticated) return;
        resetTelemetryPanel('Observation API unavailable.');
        console.warn('Telemetry refresh failed:', error);
    }
}

// Refresh only while authenticated; never starts packet capture.
setInterval(refreshTelemetryPanel, 15000);


// NX-03: Offline synthetic PCAP feature inspection.
// Research measurements only; never triggers AI inference or enforcement.
(function () {
    'use strict';

    function addCell(row, text) {
        const cell = document.createElement('td');
        cell.textContent = String(text);
        row.appendChild(cell);
    }

    async function runPcapAnalysis() {
        const button = document.getElementById('offline-pcap-run-btn');
        const status = document.getElementById('offline-pcap-status');
        const summary = document.getElementById('offline-pcap-summary');
        const body = document.getElementById('offline-pcap-feature-body');

        if (!button || !status || !summary || !body) return;

        if (!adminAuthenticated || !adminCsrfToken) {
            status.textContent = 'Administrator sign-in required.';
            return;
        }

        const generation = authGeneration;

        button.disabled = true;
        summary.replaceChildren();
        body.replaceChildren();
        status.textContent = 'Processing allowlisted offline PCAP...';

        try {
            const response = await fetch(
                '/api/phase6/offline-pcap-features',
                {
                    method: 'GET',
                    credentials: 'same-origin',
                    cache: 'no-store'
                }
            );

            if (generation !== authGeneration) return;
            if (handleAuthenticationFailure(response)) return;

            const data = await response.json();

            if (generation !== authGeneration || !adminAuthenticated) {
                return;
            }

            if (!response.ok || data.status !== 'success') {
                throw new Error(
                    data.message || 'Offline PCAP analysis unavailable.'
                );
            }

            const features = data.features;

            if (
                !features ||
                typeof features !== 'object' ||
                Array.isArray(features) ||
                Object.keys(features).length !== 78 ||
                data.feature_count !== 78 ||
                data.ai_status !== 'not_run' ||
                data.enforcement_enabled !== false
            ) {
                throw new Error('Unexpected or unsafe PCAP response.');
            }

            for (const value of Object.values(features)) {
                if (typeof value !== 'number' || !Number.isFinite(value)) {
                    throw new Error('Invalid network-flow feature value.');
                }
            }

            // NX-03 Feature Explorer: presentation only; no inference.
            const metricGrid = document.createElement('div');
            metricGrid.className = 'nx03-metrics';

            [
                ['Packets processed', data.packet_count],
                ['Bidirectional flows', data.flow_count],
                ['Measured features', data.feature_count]
            ].forEach(([label, value]) => {
                const card = document.createElement('div');
                card.className = 'nx03-metric-card';
                const heading = document.createElement('span');
                heading.textContent = label;
                const number = document.createElement('strong');
                number.textContent = Number(value).toLocaleString();
                card.append(heading, number);
                metricGrid.appendChild(card);
            });
            summary.appendChild(metricGrid);

            const toolbar = document.createElement('div');
            toolbar.className = 'nx03-toolbar';

            const search = document.createElement('input');
            search.type = 'search';
            search.className = 'nx03-search';
            search.placeholder = 'Search 78 network-flow features…';
            search.setAttribute('aria-label', 'Search network-flow features');

            const filter = document.createElement('select');
            filter.className = 'nx03-filter';
            filter.setAttribute('aria-label', 'Filter feature category');
            [
                ['all', 'All categories'],
                ['packet', 'Packets & TCP flags'],
                ['timing', 'Timing & intervals'],
                ['length', 'Lengths & bytes'],
                ['rate', 'Rates & bulk'],
                ['activity', 'Active & idle'],
                ['other', 'Other measurements']
            ].forEach(([value, label]) => {
                const option = document.createElement('option');
                option.value = value;
                option.textContent = label;
                filter.appendChild(option);
            });

            const count = document.createElement('span');
            count.className = 'nx03-result-count';
            count.setAttribute('aria-live', 'polite');
            toolbar.append(search, filter, count);
            summary.appendChild(toolbar);

            const aiPanel = document.createElement('div');
            aiPanel.className = 'nx03-ai-status';
            const aiTitle = document.createElement('strong');
            aiTitle.textContent = 'AI integration status';
            aiPanel.appendChild(aiTitle);
            const aiText = document.createElement('p');
            aiText.textContent =
                'Random Forest: NOT RUN  ·  LightGBM: NOT RUN  ·  SHAP: NOT RUN';
            aiPanel.appendChild(aiText);
            const parity = document.createElement('p');
            parity.textContent =
                'CICFlowMeter feature-value parity: pending independent verification. ' +
                (data.ai_reason || '');
            aiPanel.appendChild(parity);
            summary.appendChild(aiPanel);

            function featureCategory(name) {
                const n = name.toLowerCase();
                if (/(iat|duration|active|idle)/.test(n)) {
                    return /(active|idle)/.test(n) ? 'activity' : 'timing';
                }
                if (/(length|bytes|bulk|size|header)/.test(n)) return 'length';
                if (/(rate|packets\/s|bytes\/s)/.test(n)) return 'rate';
                if (/(flag|packet|psh|urg|syn|fin|rst|ack|ece|cwe)/.test(n)) {
                    return 'packet';
                }
                return 'other';
            }

            function featureDescription(name) {
                const n = name.toLowerCase();
                if (n.includes('flow duration')) return 'Elapsed time from the first to last packet in the flow.';
                if (n.includes('iat')) return 'Inter-arrival time between packets; an aggregate statistic for this direction or flow.';
                if (n.includes('active')) return 'Statistics describing periods when the flow is active.';
                if (n.includes('idle')) return 'Statistics describing inactive gaps within the flow.';
                if (n.includes('flag')) return 'Count of packets carrying the named TCP control flag.';
                if (n.includes('header length')) return 'Total TCP header length observed in this direction.';
                if (n.includes('packet length') || n.includes('segment size') || n.includes('packet size')) return 'Packet or TCP payload size statistic.';
                if (n.includes('bulk')) return 'Bulk-transfer measurement for this direction.';
                if (n.includes('rate')) return 'Traffic rate derived from packet or byte measurements.';
                if (n.includes('subflow')) return 'Packet or byte statistic for a subflow.';
                if (n.includes('down/up') || n.includes('ratio')) return 'Ratio comparing traffic measurements between directions.';
                if (n.includes('window')) return 'TCP advertised receive-window measurement.';
                if (n.includes('count')) return 'Count of packets or events matching this feature.';
                return 'Measured network-flow statistic. See the feature name for its specific definition.';
            }

            function featureUnit(name) {
                const n = name.toLowerCase();
                if (n.includes('iat') || n.includes('duration')) return 'µs';
                if (n.includes('rate')) return 'rate (reference unit to verify)';
                if (n.includes('length') || n.includes('bytes') ||
                    n.includes('size') || n.includes('header')) return 'bytes';
                if (n.includes('ratio')) return 'ratio';
                if (n.includes('window')) return 'bytes';
                if (n.includes('count') || n.includes('packets')) return 'count';
                return 'unit not independently confirmed';
            }

            const featureRows = [];
            for (const [name, value] of Object.entries(features)) {
                const row = document.createElement('tr');
                const nameCell = document.createElement('td');
                const title = document.createElement('strong');
                title.textContent = name;
                const detail = document.createElement('small');
                detail.className = 'nx03-feature-description';
                detail.textContent = featureDescription(name);
                nameCell.append(title, detail);

                const valueCell = document.createElement('td');
                valueCell.className = 'nx03-value-cell';
                const formatted = Number(value).toLocaleString('en-GB', {
                    maximumFractionDigits: 3
                });
                valueCell.textContent = formatted + ' ';
                const unit = document.createElement('span');
                unit.className = 'nx03-unit';
                unit.textContent = featureUnit(name);
                valueCell.appendChild(unit);

                row.append(nameCell, valueCell);
                row.dataset.search = (name + ' ' + featureDescription(name)).toLowerCase();
                row.dataset.category = featureCategory(name);
                body.appendChild(row);
                featureRows.push(row);
            }

            function filterFeatureRows() {
                const query = search.value.trim().toLowerCase();
                const category = filter.value;
                let visible = 0;
                featureRows.forEach(row => {
                    const matchesText = row.dataset.search.includes(query);
                    const matchesCategory =
                        category === 'all' || row.dataset.category === category;
                    const show = matchesText && matchesCategory;
                    row.hidden = !show;
                    if (show) visible += 1;
                });
                count.textContent = visible + ' of ' + featureRows.length + ' features';
            }
            search.addEventListener('input', filterFeatureRows);
            filter.addEventListener('change', filterFeatureRows);
            filterFeatureRows();

            status.textContent =
                'Offline PCAP analysis completed: 78 features displayed.';

        } catch (error) {
            if (generation === authGeneration && adminAuthenticated) {
                summary.replaceChildren();
                body.replaceChildren();
                status.textContent =
                    'Offline PCAP analysis unavailable: ' + error.message;
            }
        } finally {
            if (generation === authGeneration && button) {
                button.disabled = !adminAuthenticated || !adminCsrfToken;
            }
        }
    }

    function initializePcapAnalysis() {
        const button = document.getElementById('offline-pcap-run-btn');

        if (!button) return;

        button.addEventListener('click', runPcapAnalysis);
        button.disabled = !adminAuthenticated || !adminCsrfToken;
    }

    if (document.readyState === 'loading') {
        document.addEventListener(
            'DOMContentLoaded', initializePcapAnalysis
        );
    } else {
        initializePcapAnalysis();
    }
})();



// novashield-captured-traffic-ui-v1: read-only, admin-protected saved PCAP summary
(function () {
    'use strict';
    const button = document.getElementById('captured-traffic-load-btn');
    const status = document.getElementById('captured-traffic-status');
    const results = document.getElementById('captured-traffic-results');
    if (!button || !status || !results) return;

    button.addEventListener('click', async function () {
        button.disabled = true;
        status.textContent = 'Loading saved capture statistics…';
        results.replaceChildren();
        try {
            const response = await fetch('/api/phase6/captured-pcap-flows', {
                method: 'GET', credentials: 'same-origin', cache: 'no-store',
                headers: { 'Accept': 'application/json' }
            });
            if (response.status === 401 || response.status === 403) {
                throw new Error('Administrator sign-in required. Sign in and try again.');
            }
            if (!response.ok) throw new Error('API returned HTTP ' + response.status);
            const data = await response.json();
            if (!data || data.status !== 'success' ||
                data.mode !== 'offline_captured_pcap_summary' ||
                data.ai_status !== 'not_run' ||
                data.enforcement_enabled !== false ||
                data.live_capture_active !== false ||
                data.feature_status !== 'not_validated_full_snaplen') {
                throw new Error('Unexpected or unsafe capture summary response.');
            }
            const fields = [
                ['Packets read', 'packet_count'],
                ['TCP packets processed', 'tcp_packet_count'],
                ['TCP flows assembled', 'flow_count'],
                ['Packets skipped', 'skipped_packet_count']
            ];
            const grid = document.createElement('div');
            grid.style.cssText = 'display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));gap:10px;margin:12px 0';
            for (const [label, key] of fields) {
                const value = data[key];
                if (!Number.isSafeInteger(value) || value < 0) throw new Error('Invalid ' + key);
                const card = document.createElement('div');
                card.style.cssText = 'border:1px solid #64748b;border-radius:9px;padding:12px';
                const number = document.createElement('strong');
                number.style.cssText = 'display:block;font-size:1.6rem';
                number.textContent = value.toLocaleString();
                const caption = document.createElement('span');
                caption.textContent = label;
                card.append(number, caption);
                grid.appendChild(card);
            }
            results.appendChild(grid);
            const timestamp = document.getElementById('captured-traffic-timestamp');
            if (timestamp) {
                const value = data.capture_modified_at;
                const date = typeof value === 'string' ? new Date(value) : null;
                timestamp.textContent = date && !Number.isNaN(date.getTime())
                    ? 'Saved PCAP last modified: ' + date.toLocaleString()
                    : 'Capture timestamp unavailable';
            }
            status.textContent = 'Saved en0 capture loaded. Capture is NOT live; AI NOT RUN; enforcement DISABLED.';
        } catch (error) {
            status.textContent = 'Could not load captured traffic: ' + (error.message || 'Unknown error');
        } finally {
            button.disabled = false;
        }
    });
})();
