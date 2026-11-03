import warnings
warnings.filterwarnings("ignore", category=UserWarning)

import sys
import os
import json
import glob
import re
from functools import wraps

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Flask, render_template, jsonify, request, session
from flask_socketio import SocketIO, emit
from minions.optic import Optic
from minions.cortex import Cortex
from minions.vault import Vault
from minions.servo import Servo
from minions.siem import SIEMExporter

app = Flask(__name__)
app.secret_key = "novashield_session_secret_key"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

optic = Optic()
cortex = Cortex()
vault = Vault()
servo = Servo()
siem = SIEMExporter()

pending_alert = None

def require_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("is_admin"):
            return jsonify({"status": "error", "message": "Unauthorized."}), 403
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    session["is_admin"] = (data.get("role") == "admin")
    return jsonify({"status": "success", "role": data.get("role")})

@app.route('/api/scan', methods=['GET', 'POST'])
def scan():
    global pending_alert
    
    # 🔥 FIX: Accept the log_line from the POST body
    bad_log = "Live TCP: 150 connections from 10.0.0.99 on port 80"
    
    if request.method == 'POST' and request.json:
        bad_log = request.json.get("log_line", bad_log)
    
    print(f"🔍 SCAN RECEIVED: {bad_log}")
    
    alert = optic.scan(bad_log, decision_id=500 + len(glob.glob("records/*.json")))
    if not alert: return jsonify({"status": "clean"})
    
    enriched = cortex.explain(alert)
    pending_alert = enriched
    
    siem.save_to_file(enriched)
    siem.send_webhook(enriched)
    
    socketio.emit('new_alert', enriched)
    
    return jsonify({
        "status": "threat", "score": enriched["score"],
        "alert_type": enriched.get("alert_type"),
        "explanation": enriched["explanation"], "counterfactual": enriched.get("counterfactual"),
        "raw_log": enriched["raw_log"]
    })

# 🔥 FIX: Add the missing /api/live route
@app.route('/api/live')
def live():
    return jsonify({"status": "waiting"})

@app.route('/api/decide', methods=['POST'])
@require_admin
def decide():
    global pending_alert
    data = request.json
    decision = data.get("decision")
    
    if not pending_alert:
        return jsonify({"status": "error", "message": "No pending alert"})

    blocked_ip = "unknown"
    match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", pending_alert["raw_log"])
    if match:
        blocked_ip = match.group(1)

    if decision == 'approve':
        pending_alert["human_decision"] = "approved"
        servo.execute_block(blocked_ip)
    else:
        pending_alert["human_decision"] = "rejected"
        
    pending_alert["analyst"] = "mariabatool" 
    vault.record(pending_alert, tenant_id="tenant_001")
    pending_alert = None
    
    return jsonify({"status": "success", "blocked_ip": blocked_ip})

@app.route('/api/verify')
def verify():
    is_intact, count, report = vault.verify_chain(tenant_id="tenant_001")
    return jsonify({"status": "intact" if is_intact else "compromised", "count": count, "report": report})

@app.route('/api/history')
def history():
    rows = vault.get_all(tenant_id="tenant_001")
    records = []
    for r in rows:
        records.append({
            "decision_id": r["id"],
            "alert_type": r["alert_type"],
            "score": r["score"],
            "human_decision": r["human_decision"],
            "analyst": r["analyst"],
            "hash": r["hash"],
            "recorded_at": str(r["recorded_at"])
        })
    return jsonify({"records": records})

if __name__ == '__main__':
    print("Starting NovaShield Dashboard on http://127.0.0.1:5000")
    socketio.run(app, host='127.0.0.1', port=5000, allow_unsafe_werkzeug=True)