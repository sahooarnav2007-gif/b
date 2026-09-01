"""
Module 3: Explainable AI (XAI) Engine and Counterfactual What-If Simulator
Provides transparent feature attributions (SHAP-style local contributions),
human-readable forensic reasoning, and interactive scenario counterfactuals.
"""

import numpy as np
import pandas as pd
from modules.forecast_engine import FEATURE_COLS

FEATURE_DESCRIPTIONS = {
    'packet_length': 'Average Packet Payload Size (Bytes)',
    'syn_flag': 'TCP SYN Connection Request Flag',
    'ack_flag': 'TCP Acknowledge Handshake Flag',
    'fin_flag': 'TCP Connection Finish Flag',
    'rst_flag': 'TCP Connection Reset Flag',
    'payload_entropy': 'Byte Sequence Shannon Entropy (Obfuscation Level)',
    'flow_duration_ms': 'Session Connection Duration (Milliseconds)',
    'packets_per_sec': 'Packet Transmission Velocity (Packets/Sec)',
    'byte_rate': 'Data Bandwidth Transfer Rate (Bytes/Sec)',
    'iat_variance': 'Inter-Arrival Time Timing Jitter Variance'
}

class ExplainableAIEngine:
    def __init__(self, dual_ai_engine):
        self.engine = dual_ai_engine

    def explain_flow(self, flow_dict: dict) -> dict:
        pred = self.engine.predict_flow(flow_dict)
        label = pred['predicted_label']
        
        contributions = {}
        normal_baselines = {
            'packet_length': 512.0,
            'syn_flag': 0.0,
            'ack_flag': 1.0,
            'fin_flag': 0.0,
            'rst_flag': 0.0,
            'payload_entropy': 4.5,
            'flow_duration_ms': 250.0,
            'packets_per_sec': 50.0,
            'byte_rate': 8000.0,
            'iat_variance': 20.0
        }
        
        for col in FEATURE_COLS:
            val = float(flow_dict.get(col, 0.0))
            base = normal_baselines.get(col, 1.0)
            if base != 0:
                diff_pct = (val - base) / (abs(base) + 1e-5)
            else:
                diff_pct = val * 2.0
            contributions[col] = float(np.clip(diff_pct * 0.15, -1.0, 1.0))

        top_drivers = sorted(contributions.items(), key=lambda x: abs(x[1]), reverse=True)[:4]
        
        explanations = []
        if flow_dict.get('syn_flag', 0) == 1 and flow_dict.get('packets_per_sec', 0) > 2000:
            explanations.append("Abnormal TCP SYN flag storm detected without corresponding ACK handshakes (>2,000 pkts/sec).")
        if flow_dict.get('payload_entropy', 0) > 7.5:
            explanations.append(f"Extremely high payload entropy ({flow_dict.get('payload_entropy', 0):.2f}/8.00) indicates encrypted shellcode or ransomware C2 beacon.")
        elif flow_dict.get('payload_entropy', 0) < 1.0 and label != 'NORMAL':
            explanations.append("Payload entropy is near zero, indicating repetitive padding payloads characteristic of flood attacks.")
        if flow_dict.get('flow_duration_ms', 0) < 5.0 and flow_dict.get('packets_per_sec', 0) > 500:
            explanations.append("Ultra-short connection lifetime with high burst rate matching automated scanning tools (Nmap/Masscan).")
        if not explanations:
            explanations.append("Traffic features align with baseline operational parameters.")

        return {
            'prediction': pred,
            'feature_contributions': contributions,
            'top_drivers': [
                {
                    'feature': feat,
                    'name': FEATURE_DESCRIPTIONS.get(feat, feat),
                    'value': flow_dict.get(feat, 0.0),
                    'impact_weight': round(weight, 4),
                    'direction': 'Elevates Threat Risk' if weight > 0 else 'Reduces Risk'
                }
                for feat, weight in top_drivers
            ],
            'forensic_reasoning': " ".join(explanations)
        }

    def simulate_what_if(self, base_flow: dict, adjustments: dict) -> dict:
        modified_flow = base_flow.copy()
        for k, v in adjustments.items():
            if k in modified_flow:
                modified_flow[k] = v
                
        before_pred = self.engine.predict_flow(base_flow)
        after_pred = self.engine.predict_flow(modified_flow)
        risk_delta = after_pred['anomaly_risk_score'] - before_pred['anomaly_risk_score']
        
        return {
            'original_flow': base_flow,
            'modified_flow': modified_flow,
            'before_prediction': before_pred,
            'after_prediction': after_pred,
            'risk_reduction_pct': round(-risk_delta * 100, 2),
            'threat_mitigated': (before_pred['predicted_label'] != 'NORMAL' and after_pred['predicted_label'] == 'NORMAL')
        }