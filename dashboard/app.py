import warnings
warnings.filterwarnings("ignore", category=UserWarning)

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
from minions.servo import Servo

app = Flask(__name__)

optic = Optic()
cortex = Cortex()
vault = Vault()
servo = Servo()

pending_alert = None
latest_live_alert = None

def process_live_packet(log_line):
    global latest_live_alert
    alert = optic.scan(log_line, decision_id=1000 + len(glob.glob("records/*.json")))
    if alert:
        enriched = cortex.explain(alert)
        latest_live_alert = enriched

sniffer = Sniffer(process_live_packet)
sniffer.start()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan')
def scan():
    global pending_alert
    bad_log = "Live TCP: 15 connections from 10.0.0.99 on port 22"
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
def decide():
    global pending_alert
    data = request.json
    decision = data.get("decision")
    
    if pending_alert:
        if decision == 'approve':
            pending_alert["action"] = "block"
            pending_alert["human_decision"] = "approved"
            servo.execute_block("10.0.0.99")
        else:
            pending_alert["action"] = "monitor_only"
            pending_alert["human_decision"] = "rejected"
            
        vault.record(pending_alert)
        pending_alert = None
        return jsonify({"status": "success"})
    return jsonify({"status": "error"})

@app.route('/api/verify')
def verify():
    is_intact, count, report = vault.verify_chain()
    return jsonify({"status": "intact" if is_intact else "compromised", "count": count, "report": report})

@app.route('/api/history')
def history():
    rows = vault.get_all()
    records = []
    for r in rows:
        records.append({
            "decision_id": r[0], "alert_type": r[1], "score": r[2],
            "human_decision": r[4], "hash": r[5], "recorded_at": r[7]
        })
    return jsonify({"records": records})

if __name__ == '__main__':
    print("Starting NovaShield Dashboard on http://127.0.0.1:5000")
    app.run(debug=True, port=5000)