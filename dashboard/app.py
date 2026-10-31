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
from minions.optic import Optic
from minions.cortex import Cortex
from minions.vault import Vault
from minions.sniffer import Sniffer
from minions.servo import Servo

app = Flask(__name__)
app.secret_key = "novashield_session_secret_key"

optic = Optic()
cortex = Cortex()
vault = Vault()
servo = Servo()

pending_alert = None
latest_live_alert = None

def require_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("is_admin"):
            return jsonify({"status": "error", "message": "Unauthorized. Only Admins can block IPs."}), 403
        return f(*args, **kwargs)
    return decorated_function

def process_live_packet(log_line):
    global latest_live_alert
    alert = optic.scan(log_line, decision_id=1000 + len(glob.glob("records/*.json")))
    if alert:
        latest_live_alert = cortex.explain(alert)

sniffer = Sniffer(process_live_packet)
sniffer.start()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    if data.get("role") == "admin":
        session["is_admin"] = True
        return jsonify({"status": "success", "role": "admin"})
    else:
        session["is_admin"] = False
        return jsonify({"status": "success", "role": "viewer"})

@app.route('/api/scan')
def scan():
    global pending_alert
    # Simulate a REAL DDoS attack (matches CIC-IDS2017 attack signature)
    bad_log = "Live TCP: 150 connections from 10.0.0.99 on port 80"
    
    alert = optic.scan(bad_log, decision_id=500 + len(glob.glob("records/*.json")))
    if not alert: return jsonify({"status": "clean"})
    
    enriched = cortex.explain(alert)
    pending_alert = enriched
    
    return jsonify({
        "status": "threat", "score": enriched["score"],
        "explanation": enriched["explanation"], "counterfactual": enriched.get("counterfactual"),
        "raw_log": enriched["raw_log"]
    })

@app.route('/api/live')
def live():
    global latest_live_alert, pending_alert
    if latest_live_alert:
        pending_alert = latest_live_alert
        latest_live_alert = None
        return jsonify({
            "status": "threat", "score": pending_alert["score"],
            "explanation": pending_alert["explanation"], "counterfactual": pending_alert.get("counterfactual"),
            "raw_log": pending_alert["raw_log"]
        })
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
        pending_alert["action"] = "block"
        pending_alert["human_decision"] = "approved"
        
        # Trigger REAL firewall block
        success = servo.execute_block(blocked_ip)
        if not success:
            return jsonify({"status": "error", "message": f"Firewall refused to block {blocked_ip}"})
    else:
        pending_alert["action"] = "monitor_only"
        pending_alert["human_decision"] = "rejected"
        
    pending_alert["analyst"] = "mariabatool" 
    vault.record(pending_alert)
    pending_alert = None
    
    return jsonify({"status": "success", "blocked_ip": blocked_ip})

@app.route('/api/verify')
def verify():
    """Verifies the HMAC chain AND the external anchor log."""
    is_intact, count, report = vault.verify_chain()
    anchor_missing = vault.verify_anchor()
    if anchor_missing:
        report.extend(anchor_missing)
        is_intact = False
    return jsonify({"status": "intact" if is_intact else "compromised", "count": count, "report": report})

@app.route('/api/history')
def history():
    rows = vault.get_all()
    records = []
    for r in rows:
        records.append({
            "decision_id": r[0], "alert_type": r[1], "score": r[2],
            "human_decision": r[3], "analyst": r[4], "hash": r[5], "recorded_at": r[7]
        })
    return jsonify({"records": records})

if __name__ == '__main__':
    print("Starting Secure NovaShield Dashboard on http://127.0.0.1:5000")
    app.run(debug=True, port=5000, threaded=True)