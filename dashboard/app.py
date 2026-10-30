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
from minions.sniffer import Sniffer

app = Flask(__name__)

optic = Optic()
cortex = Cortex()
vault = Vault()

pending_alert = None
latest_live_alert = None

def process_live_packet(log_line):
    global latest_live_alert
    print(f"📡 LIVE PACKET CAUGHT: {log_line}")
    
    alert = optic.scan(log_line, decision_id=1000 + len(glob.glob("records/*.json")))
    if alert:
        enriched = cortex.explain(alert)
        latest_live_alert = enriched

# Start the sniffer
sniffer = Sniffer(process_live_packet)
sniffer.start()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan')
def scan():
    global pending_alert
    # This line matches the NEW sniffer format
    bad_log = "Live TCP: 15 connections from 10.0.0.99 on port 22"
    
    alert = optic.scan(bad_log, decision_id=500 + len(glob.glob("records/*.json")))
    if not alert:
        return jsonify({"status": "clean"})
    
    enriched = cortex.explain(alert)
    pending_alert = enriched
    
    return jsonify({
        "status": "threat",
        "score": enriched["score"],
        "explanation": enriched["explanation"],
        "counterfactual": enriched.get("counterfactual"),
        "raw_log": enriched["raw_log"]
    })

@app.route('/api/live')
def live():
    global latest_live_alert, pending_alert
    if latest_live_alert:
        pending_alert = latest_live_alert
        latest_live_alert = None
        return jsonify({
            "status": "threat",
            "score": pending_alert["score"],
            "explanation": pending_alert["explanation"],
            "counterfactual": pending_alert.get("counterfactual"),
            "raw_log": pending_alert["raw_log"]
        })
    return jsonify({"status": "waiting"})

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
    return jsonify({"status": "error"})

@app.route('/api/verify')
def verify():
    files = sorted(glob.glob("records/decision_*.json"), key=lambda p: int(p.split("_")[-1].split(".")[0]))
    if not files: return jsonify({"status": "empty", "count": 0})
    expected_prev = "GENESIS"
    for path in files:
        with open(path) as f:
            entry = json.load(f)
        if entry["prev_hash"] != expected_prev: return jsonify({"status": "compromised"})
        payload = {k: v for k, v in entry.items() if k != "hash"}
        recomputed = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        if recomputed != entry["hash"]: return jsonify({"status": "compromised"})
        expected_prev = entry["hash"]
    return jsonify({"status": "intact", "count": len(files)})

@app.route('/api/history')
def history():
    files = sorted(glob.glob("records/decision_*.json"), key=lambda p: int(p.split("_")[-1].split(".")[0]), reverse=True)
    records = []
    for path in files:
        with open(path) as f: records.append(json.load(f))
    return jsonify({"records": records})

if __name__ == '__main__':
    print("Starting NovaShield Dashboard on http://127.0.0.1:5000")
    app.run(debug=True, port=5000)