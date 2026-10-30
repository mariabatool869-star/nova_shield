import sys
import os
import json
import glob
import hashlib

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Flask, render_template, jsonify, request
from minions.optic import Optic
from minions.cortex import Cortex
from minions.vault import Vault

app = Flask(__name__)

optic = Optic()
cortex = Cortex()
vault = Vault()

pending_alert = None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan')
def scan():
    global pending_alert
    bad_log = "Oct 30 12:01:06 server sshd[1236]: Failed password for root from 10.0.0.99 port 5555 ssh2"
    
    alert = optic.scan(bad_log, decision_id=500 + len(glob.glob("records/*.json")))
    if not alert:
        return jsonify({"status": "clean"})
        
    enriched_alert = cortex.explain(alert)
    pending_alert = enriched_alert
    
    return jsonify({
        "status": "threat",
        "score": enriched_alert["score"],
        "explanation": enriched_alert["explanation"],
        "counterfactual": enriched_alert.get("counterfactual"),
        "raw_log": enriched_alert["raw_log"]
    })

@app.route('/api/decide', methods=['POST'])
def decide():
    global pending_alert
    data = request.json
    decision = data.get("decision")
    
    if pending_alert:
        if decision == 'approve':
            pending_alert["action"] = "block"
            pending_alert["human_decision"] = "approved"
        else:
            pending_alert["action"] = "monitor_only"
            pending_alert["human_decision"] = "rejected"
            
        vault.record(pending_alert)
        pending_alert = None
        return jsonify({"status": "success"})
        
    return jsonify({"status": "error", "message": "No pending alert"})

@app.route('/api/verify')
def verify():
    files = sorted(glob.glob("records/decision_*.json"), key=lambda p: int(p.split("_")[-1].split(".")[0]))
    if not files: return jsonify({"status": "empty", "count": 0})
    
    expected_prev = "GENESIS"
    for path in files:
        with open(path) as f:
            entry = json.load(f)
        if entry["prev_hash"] != expected_prev:
            return jsonify({"status": "compromised", "count": len(files)})
        stored = entry["hash"]
        payload = {k: v for k, v in entry.items() if k != "hash"}
        recomputed = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        if recomputed != stored:
            return jsonify({"status": "compromised", "count": len(files)})
        expected_prev = stored
    return jsonify({"status": "intact", "count": len(files)})

# NEW ROUTE: Fetches the entire ledger for the UI
@app.route('/api/history')
def history():
    files = sorted(glob.glob("records/decision_*.json"), key=lambda p: int(p.split("_")[-1].split(".")[0]), reverse=True)
    records = []
    for path in files:
        with open(path) as f:
            records.append(json.load(f))
    return jsonify({"records": records})

if __name__ == '__main__':
    print("Starting NovaShield Dashboard on http://127.0.0.1:5000")
    app.run(debug=True, port=5000)