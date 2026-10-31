<div align="center">

# 🛡️ NovaShield

**Verifiable AI Security Triage.**
*Explain every alert. Prove every decision. Block with confidence.*

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg?style=for-the-badge&logo=python)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0+-lightgrey.svg?style=for-the-badge&logo=flask)](https://flask.palletsprojects.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-18.0+-336791.svg?style=for-the-badge&logo=postgresql)](https://www.postgresql.org/)
[![Scikit-Learn](https://img.shields.io/badge/scikit--learn-1.0+-orange.svg?style=for-the-badge&logo=scikit-learn)](https://scikit-learn.org/)
[![LightGBM](https://img.shields.io/badge/LightGBM-Enterprise-green.svg?style=for-the-badge)](https://lightgbm.readthedocs.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

NovaShield is an open-source, enterprise-grade AI Security Operations Center (SOC). Unlike traditional black-box security tools, NovaShield uses Explainable AI (XAI) to tell you *exactly* why a threat was flagged, requires human approval before executing a real firewall block, and locks every decision in an immutable, multi-tenant, cryptographically signed ledger.

[Architecture](#-the-nx-fleet-architecture) · [Key Features](#-enterprise-features) · [Quick Start](#-quick-start) · [Forensic Demo](#-the-forensic-tamper-test)

</div>

---

## 🧠 The NX Fleet Architecture

NovaShield is built as a pipeline of specialized modules (minions), each doing one job perfectly:

| Unit | Name | Role | Description |
| :--- | :--- | :--- | :--- |
| **NX-01** | **OPTIC** | Vision | Sniffs live network traffic (Scapy) and parses telemetry for suspicious bursts. |
| **NX-02** | **CORTEX** | Brain | Uses a LightGBM model trained on 100,000 CIC-IDS2017 flows (76 features) + SHAP to explain *why* a threat was flagged. |
| **NX-03** | **SERVO** | Actuator | The human-in-the-loop gate. Executes **real system-level firewall blocks** (macOS `pfctl`). |
| **NX-04** | **VAULT** | Memory | PostgreSQL multi-tenant database. Uses HMAC chains + **Ed25519 cryptographic signatures** + External Anchor Logs. |
| **NX-05** | **SENTINEL** | Comms | Real-time alerting to Slack/Discord and export to SIEM (ECS format). |

---

## ✨ Enterprise Features

-   **Real-Time Sniffing:** Listens to live Wi-Fi traffic (`en0`) and detects port scans and brute-force bursts.
-   **Explainable AI (XAI):** Visualizes SHAP values so you see exactly which enterprise features (e.g., `Max_Packet_Length`, `Flow_Duration`) drove the AI's decision.
-   **Counterfactual Hints:** Tells you what would have changed the outcome (e.g., *"If Max_Packet_Length were normal, this traffic would be classified as BENIGN"*).
-   **Role-Based Access Control (RBAC):** Admin vs. Viewer roles enforced on the server side (no JS spoofing).
-   **Actual Firewall Blocking:** Clicking "Approve" executes `pfctl -t novashield_blocklist -T add <IP>` to drop the attacker at the kernel level.
-   **Forensic Tamper Detection:** Ed25519 signatures ensure that if anyone modifies a database record, the signature becomes invalid, and the UI alerts you.
-   **External Anchoring:** Every record hash is written to `anchor.log`. Even if the database is deleted, the proof remains.
-   **SIEM Ready:** Alerts are exported in Elastic Common Schema (ECS) format for Splunk/Elastic ingestion.
-   **Real-Time Webhooks:** Instant alerts to Discord or Slack on threat detection.

---

## 🚀 Quick Start

### 1. Prerequisites
-   **Python 3.10+**
-   **Git**
-   **PostgreSQL 18+** (Installed and running on port 5432)
-   **macOS** (Required for the `pfctl` firewall actuator)

### 2. Installation
```bash
# Clone the repository
git clone https://github.com/mariabatool869-star/nova_shield.git
cd nova_shield

# Install required packages
pip3 install flask flask-cors scikit-learn pandas shap scapy lightgbm psycopg2-binary python-dotenv cryptography requests
