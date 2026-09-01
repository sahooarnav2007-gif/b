# 🙁 Attack Forecaster Pro - Autonomous SOC Threat Intelligence & Predictive Defense Suite

---

## 🚀 Project Overview

**Attack Forecaster Pro** is an industry-grade, research-level Cybersecurity Operations Center (SOC) platform. Unlike basic classifiers that only read static CSV records, this system:
1. **Ingests Real Network Traffic**: Parses raw appearing Wireshark `.pcap` files and computes rolling flow statistics and Shannon payload entropy.
2. **Dual AI Threat Engine**: Forecasts future 24-hour attack velocity trends while classifying known attacks and detecting unseen *Novel Zero-Day Anomalies* using Unsupervised Isolation Forests.
3. **Explainable AI (XAI) & What-If Lab**: Deconstructs black-box predictions into SHAP feature attributions and allows interactive counterfactual policy simulation.
4. **SOAR Active Defense & Decoy Honeypot**: Maps threats to MITRE ATT&CK TTPs, auto-generates live firewall rules (iptables, Windows netsh, Cisco ACLs), and diverts attackers into a sandbox honeypot.
5. **Cryptographic Forensic Audit & PDF Reporting**: Ensures tamper-proof chain of custody using SHA-256 Merkle chaining and exports executive SOC Incident PDF reports.

---

## 🏐 Architecture Diagram

` network pcap / flow stream
                                                                    
                                                                    
                         [ PC AP & Flow Engine ]
                         (Shannon Entropy, Flow IAT)
                                                                   
                                                                  
                                                                 
                         [ Dual AI Engine ]
                        (24h Trend Forecaster +
                         xGBoost + Zero-Day Isolation)
                                                                 
                                                                 
                                                                 
                         [ Explainable AI ]
                        (SHAP Weights, What-If Lab)
                                                                 
                                                                 
                                                                 
                         [ SOAR Active Defense ]
                        (MITRE Mapping, Firewall Generator,
                         Dynamic Decoy Honeypot Trap)
                                                                  
                                                                  
                                                                 
                         [ Crypto Audit & PDF Report  ]
                        (SHA-256 Merkle Chain, FPTF2 PDF)
```

---

## 🚀 How to Run Offline

1. **Install Dependencies:**
   ``bash
   pip install -r requirements.txt
   ``

2. **Launch the Streamlit SOC Dashboard:**
   ``bash
   streamlit run app.py
   ``

3. The app will open in your browser at `http://localhost:8501`. This entire project runs **100% offline** without any internet connectivity required.

---

## 🌟 What to Tell Your Professors / Evaluators
 
> *"Our Attack Forecaster Pro platform goes beyond toy classification by implementing an end-to-end Security Operations Center (SOC) pipeline: true 24-hour temporal threat velocity forecasting, unsupervised zero-day anomaly detection, transparent EXPLAINABLE II (XAI), automated SOAR active defense with decoy honeypots, and cryptographically verified forensic Incident PDF reporting."*
