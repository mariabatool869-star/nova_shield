# 🛡️ NovaShield

> **Verifiable AI Security Triage.** 
> Explain every alert. Prove every decision.

NovaShield is an open-source, AI-powered SOC (Security Operations Center) console. Unlike traditional black-box security tools, NovaShield uses Explainable AI to tell you *exactly* why a threat was flagged, requires human approval before acting, and locks every decision in a tamper-proof ledger.

---

## 🧠 The NX Fleet Architecture

NovaShield is built as a pipeline of four specialized modules (minions), each doing one job perfectly:

| Unit | Name | Role | Description |
| :--- | :--- | :--- | :--- |
| **NX-01** | **OPTIC** | Vision | Ingests telemetry and parses log files for suspicious activity. |
| **NX-02** | **CORTEX** | Brain | Uses Machine Learning + SHAP to explain *which features* drove the risk score. |
| **NX-03** | **SERVO** | Gate | The human-in-the-loop gate. Irreversible actions require explicit approval. |
| **NX-04** | **VAULT** | Memory | Writes an append-only, hash-chained ledger. Tamper-evident and auditable. |

---

## ✨ Key Features

*   **Explainable AI (XAI):** Visualizes SHAP (Shapley Additive exPlanations) bars so you see exactly what drove the AI's decision.
*   **Counterfactual Hints:** Tells you what would have changed the outcome (e.g., *"If failed logins were below 5, risk would drop to 0.45"*).
*   **Human-in-the-Loop:** The AI recommends; you decide. Prevents false positives from breaking production.
*   **Tamper-Evident Ledger:** Every human decision is cryptographically sealed. Change one byte, and the UI turns red.

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
pip3 install flask flask-cors scikit-learn pandas shap
