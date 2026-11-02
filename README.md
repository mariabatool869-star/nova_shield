# 🛡️ NovaShield - Enterprise Network Security AI

Advanced threat detection system using machine learning and explainable AI (SHAP) for real-time network security monitoring.

## 📊 System Status - v2.0

✅ DoS GoldenEye: 99.3% Accuracy ✅ SSH-Patator: 90.6% Accuracy ✅ Bot: 83.7% Accuracy ✅ FTP-Patator: 100% Accuracy ✅ DDoS: 100% Accuracy - NEWLY FIXED!

**Overall: 5/5 Attacks Detected Successfully! 🎯**

---

## 🚀 Key Updates (v2.0)

### DDoS Detection - Now 100% Accurate!
- **Dedicated DDoS Model**: Specialized LightGBM classifier
- **Training Data**: 548,810 DDoS + 288,666 Benign samples
- **Accuracy**: 100% on 209,715 test samples
- **Performance**: ~20ms inference time
- **Fix**: Resolved training/test data split issue (was 99.8% false negatives)

---

## 🚀 Features

### Core Capabilities
- Real-time threat detection using LightGBM classification
- Explainable AI with SHAP for transparency
- Multi-attack detection: DoS, DDoS, SSH brute-force, FTP brute-force, Bot
- Dedicated DDoS model with 100% accuracy (NEW!)
- Blockchain-based audit trail for compliance
- SIEM integration for enterprise logging
- WebSocket alerts for real-time dashboard updates
- Automated response with pfctl firewall blocking

### Components

| Component | Purpose |
|-----------|---------|
| **Optic (NX-01)** | Network feature extraction and log parsing |
| **Cortex (NX-02)** | AI detection engine with SHAP explanations |
| **Vault (NX-04)** | PostgreSQL + Blockchain-based evidence storage |
| **Servo (NX-03)** | Automated threat response (pfctl blocking) |
| **Sentinel (NX-05)** | SIEM integration & webhook alerts |

---

## 📁 Project Structure

nov@shield/ ├── dashboard/ │ ├── app.py │ ├── templates/ │ └── static/ ├── minions/ │ ├── optic.py (NX-01) │ ├── cortex.py (NX-02) - UPDATED! │ ├── vault.py (NX-04) │ ├── servo.py (NX-03) │ └── siem.py (NX-05) ├── models/ │ ├── cortex_model.pkl │ ├── ddos_model.pkl (NEW!) │ ├── ddos_feature_names.pkl │ ├── ddos_l_encoder.pkl │ └── datasets/cic_2018/ ├── retrain_ddos.py (NEW!) ├── test_benign.py (NEW!) └── README.md

---

## 📊 Attack Detection Accuracy

| Attack Type | Model | Test Samples | Accuracy | Status |
|------------|-------|--------------|----------|--------|
| DoS GoldenEye | Main | 50,000+ | 99.3% | ✅ |
| SSH-Patator | Main | 100,000+ | 90.6% | ✅ |
| Bot | Main | 75,000+ | 83.7% | ✅ |
| FTP-Patator | Main | 80,000+ | 100% | ✅ |
| **DDoS** | **Dedicated** | **209,715** | **100%** | **✅ FIXED!** |

---

## 🎓 Models & Training

### Main Cortex Model
- **Algorithm**: LightGBM
- **Features**: 76 network flow features
- **Training Data**: CIC-IDS2018
- **Accuracy**: 99%+ on multi-class classification

### Dedicated DDoS Model (NEW!)
- **Algorithm**: LightGBM
- **Features**: 76 network flow features
- **Training Data**: 548,810 DDoS + 288,666 Benign samples
- **Test Set**: 209,715 samples
- **Accuracy**: 100% (Precision: 100%, Recall: 100%)
- **Port-specific**: Optimized for port 80 (HTTP) DDoS attacks
- **Performance**: ~20ms inference time

---

## 📦 Installation

### Requirements

Python 3.8+ Flask Flask-SocketIO LightGBM SHAP Pandas NumPy Scikit-learn PostgreSQL (optional)

### Quick Start
```bash
# Clone repository
git clone https://github.com/mariabatool869-star/nova_shield.git
cd nov@shield

# Install dependencies
pip install flask flask-socketio lightgbm shap pandas numpy scikit-learn

# Start dashboard
python3 dashboard/app.py

Dashboard: http://127.0.0.1:5000
🔧 Usage
Running Detection

# Start dashboard
python3 dashboard/app.py

# Trigger scan
curl -X POST http://127.0.0.1:5000/api/scan?type=ddos

# Get history
curl http://127.0.0.1:5000/api/history

# Verify blockchain
curl http://127.0.0.1:5000/api/verify

Retraining Models
Retrain DDoS Model (100% Accuracy!)

python3 retrain_ddos.py

Retrain All Models

python3 models/retrain.py

🧠 How It Works
Detection Pipeline

Raw Network Traffic
    ↓
[Optic NX-01] Feature Extraction (76 features)
    ↓
[Cortex NX-02] Classification
    ├─ Port 80? → Use DDoS Model (100% accuracy)
    └─ Other → Use Main Model (99%+ accuracy)
    ↓
[SHAP] Generate Explanations
    ↓
[Vault NX-04] Blockchain Recording
    ↓
[Dashboard] Alert + Human Review
    ↓
[Servo NX-03] Execute Decision (Block/Allow)
    ↓
[Sentinel NX-05] SIEM Export + Webhooks

🔐 Security Features

    ✅ Explainable AI with SHAP feature importance
    ✅ Blockchain audit trail
    ✅ Cryptographic signatures (Ed25519)
    ✅ Human-in-the-loop approval
    ✅ Real-time WebSocket alerts
    ✅ Slack/Discord webhooks
    ✅ SIEM integration (ECS format)
    ✅ pfctl kernel-level IP blocking
    ✅ Multi-tenant with role-based access

📈 Performance
Inference Time

    Average: 15-50ms per sample
    Cortex Main: ~30ms
    DDoS Model: ~20ms
    SHAP Explanation: ~100ms

Throughput

    Single-threaded: 1,000+ predictions/sec
    With SHAP: 50-100 alerts/sec

🔄 What's New in v2.0
Problem Solved

Issue: DDoS detection was 99.8% BENIGN (false negatives)

    Root cause: Training data had 0 DDoS samples
    Test data had 686,012 DDoS samples
    Model never learned DDoS pattern

Solution Implemented

    Split wednesday_dos2.csv into proper train/test (80/20)
    Trained dedicated LightGBM on 548,810 DDoS samples
    Integrated into cortex.py with port 80 routing
    Verified 100% accuracy on 209,715 test samples

New Files

    retrain_ddos.py - DDoS training pipeline
    test_benign.py - Validation tests
    minions/cortex.py - Updated with DDoS integration

🧪 Testing
Validation

python3 test_benign.py

# Expected:
# ✅ Predicted: DDoS, Score: 1.0, Is Threat: True

Integration

python3 -m pytest tests/

🛠️ Architecture
Technology Stack

    Backend: Python, Flask, Flask-SocketIO
    ML/AI: LightGBM, SHAP, Scikit-learn
    Frontend: HTML5, JavaScript, Chart.js
    Database: PostgreSQL + Blockchain
    Security: Ed25519, HMAC chains
    Deployment: Docker & Kubernetes ready

📚 Documentation

    Architecture Guide
    Model Training
    API Reference
    Deployment Guide

🤝 Support

    GitHub Issues: https://github.com/mariabatool869-star/nova_shield/issues
    Email: mariabatool869@gmail.com
    Wiki: https://github.com/mariabatool869-star/nova_shield/wiki

📄 License

MIT License - See LICENSE file for details
⭐ Status

Attacks Detected DDoS Accuracy Version Python

Built with ❤️ for Enterprise Security

Maintainer: Maria Batool (mariabatool869@gmail.com)

