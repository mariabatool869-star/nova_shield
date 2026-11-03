# 🛡️ NovaShield v2.0 — Hybrid Explainable IDS

**Network Intrusion Detection with Explainable AI (SHAP)**

![Python](https://img.shields.io/badge/Python-3.8+-blue)
![Models](https://img.shields.io/badge/Models-Hybrid-purple)
![SHAP](https://img.shields.io/badge/SHAP-Explainable-orange)
![License](https://img.shields.io/badge/License-MIT-green)

---

## Overview

NovaShield v2.0 is a **Hybrid Explainable AI Network Intrusion Detection System**. It detects 15 attack types, explains every decision with SHAP feature importance, and blocks threats only after human approval.

**Key Features:**
- Detects 15 attack types from CIC-IDS 2017 + 2018
- Explains every detection with SHAP feature importance
- Human-in-the-loop: the AI recommends, the analyst decides
- Real firewall blocking via macOS `pfctl`
- Records every decision in PostgreSQL with Ed25519 signatures
- Exports alerts to Discord and SIEM in ECS format

Trained on **2,827,876 network flows** from a **hybrid dataset**: CIC-IDS 2017 (15 attack types) + CSE-CIC-IDS 2018 (DDoS).

---

## Key Metrics

| Metric | Value |
| :--- | :--- |
| Total Training Flows | 2,827,876 |
| Attack Types | 15 classifications |
| Network Features | 78 metrics |
| Primary Model | RandomForest (200 trees) |
| Explainer | LightGBM + SHAP |
| Inference Speed | 20–50ms per flow |
| Training Time | 3.9 minutes |

---

## System Architecture

| Unit | Name | Role |
| :--- | :--- | :--- |
| NX-01 | OPTIC | Real network packet capture (Scapy) |
| NX-02 | CORTEX | Hybrid detection (RandomForest + SHAP) |
| NX-03 | SERVO | Human-in-the-loop firewall actuator |
| NX-04 | VAULT | PostgreSQL + Ed25519 audit ledger |
| NX-05 | SENTINEL | Discord webhooks + SIEM export |

---

## Supported Attack Types

- DDoS
- PortScan
- DoS Hulk
- DoS GoldenEye
- DoS slowloris
- DoS Slowhttptest
- FTP-Patator
- SSH-Patator
- Bot
- Web Attack — Brute Force
- Web Attack — XSS
- Web Attack — SQL Injection
- Infiltration
- Heartbleed
- BENIGN

---

## Installation

bash
git clone https://github.com/mariabatool869-star/nova_shield.git
cd nova_shield
pip3 install -r requirements.txt

## Configure

Create a .env file in the root:
DATABASE_URL=postgresql://postgres:novashield@localhost:5432/novashield
NOVASHIELD_PRIVATE_KEY=<your_ed25519_private_key_hex>
WEBHOOK_URL=<your_discord_webhook_url>

## Run Dashboard

sudo python3 dashboard/app.py

Access: http://localhost:5000


## Project Structure

nov@shield/
├── dashboard/          # Flask web app
├── minions/            # NX Fleet modules
├── models/             # Trained AI models
├── docs/               # Documentation
├── tests/              # Attack test suite
├── records/            # Runtime data (SIEM export)
├── .env                # Secrets
├── requirements.txt    # Dependencies
└── README.md

##  The Honest Story

NovaShield was built with a defensive security mindset. A professional audit revealed critical issues that were fixed:

Issue	                   What Was Wrong	                                         What We Fixed
Data Leakage	          Random split of one CSV file	             Time-based split + cross-dataset validation
Port-80 Routing           DDoS only detected on port 80	             Unified pipeline for all 15 attack types
Closed-World Assumption	  Unknown attacks classified as BENIGN 	     Hybrid rules + RF + SHAP for explainability
Feature Mismatch	      Model expected 78 features,                got 5	Explicit feature mapping in optic.py

We do not claim 100% accuracy. We claim honest detection with explainable AI.
## Requirements
text

pandas>=1.3.0
numpy>=1.21.0
scikit-learn>=0.24.0
lightgbm>=3.0.0
shap>=0.40.0
scapy>=2.4.0
flask>=2.0.0
psycopg2-binary>=2.9.0
python-dotenv>=0.19.0
cryptography>=3.4.0

## License

MIT License — See LICENSE file.
## Acknowledgments

    CIC-IDS 2017 & 2018: Canadian Institute for Cybersecurity

    scikit-learn: ML framework

    SHAP: Explainable AI

    LightGBM: Gradient boosting

    Scapy: Network packet capture

##  Status
Component	     Status
Data Collection  	✅ Complete
Model Training	    ✅ Complete
SHAP Integration	✅ Complete
Dashboard	        ✅ Complete
Human-in-the-Loop	✅ Complete
PostgreSQL Ledger	✅ Complete
Discord Alerts	    ✅ Complete
SIEM Export	        ✅ Complete

Version: 2.0.0

Status: ✅ Working Prototype (Honest Evaluation)

🛡️ NovaShield v2.0 — Explainable AI Network Guardian
text



