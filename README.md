# 🛡️ NovaShield

> **Verifiable AI Security Triage.** 
> Explain every alert. Prove every decision. Block with confidence.

NovaShield is an open-source, AI-powered SOC (Security Operations Center) console. Unlike traditional black-box security tools, NovaShield uses Explainable AI to tell you *exactly* why a threat was flagged, requires human approval before executing a firewall block, and locks every decision in an immutable, cryptographic SQLite ledger.

*(Replace this text with your screenshot: Drag and drop your dashboard image into GitHub to generate a URL, then paste it here like `![NovaShield](URL)`)*

---

## 🧠 The NX Fleet Architecture

NovaShield is built as a pipeline of four specialized modules (minions), each doing one job perfectly:

| Unit | Name | Role | Description |
| :--- | :--- | :--- | :--- |
| **NX-01** | **OPTIC** | Vision | Sniffs live network traffic (Scapy) and parses telemetry for suspicious bursts. |
| **NX-02** | **CORTEX** | Brain | Uses a Random Forest ML model + SHAP to explain *which features* drove the risk score. |
| **NX-03** | **SERVO** | Gate & Actuator | The human-in-the-loop gate. If approved, executes a system-level firewall block. |
| **NX-04** | **VAULT** | Memory | Writes to a SQLite database using a cryptographic hash chain. Detects forensic tampering. |

---

## ✨ Key Features

*   **Real-Time Sniffing:** Listens to live Wi-Fi traffic (`en0`) and detects port scans or brute-force bursts.
*   **Explainable AI (XAI):** Visualizes SHAP (Shapley Additive exPlanations) bars so you see exactly what drove the AI's decision.
*   **Counterfactual Hints:** Tells you what would have changed the outcome (e.g., *"If failed logins were below 5, risk would drop to 0.45"*).
*   **Human-in-the-Loop:** The AI recommends; you decide. Prevents false positives from breaking production.
*   **Actual Firewall Blocking:** Clicking "Approve" triggers a network block command (simulated via `pfctl`/`iptables` logic).
*   **Forensic Ledger:** Every decision is saved to a SQLite database with a SHA-256 hash chain. If someone tampers with the database, the UI generates a **Forensic Alert** detailing exactly what was changed.
*   **Enterprise UI:** A dark-mode, cyber-grid SOC console built for real analysts.

---

## 🚀 Quick Start

### 1. Prerequisites
Ensure you have **Python 3.10+** and **Git** installed.

### 2. Installation
```bash
# Clone the repository
git clone https://github.com/mariabatool869-star/nova_shield.git
cd nova_shield

# Install required packages
pip3 install flask flask-cors scikit-learn pandas shap scapy
