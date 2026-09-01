"""
active_defense.py
-----------------
SOAR-style active-defense helpers for SIH26153 (ported from the
Attack_Forecaster_Pro dashboard and adapted to the main project's real attack
family names and MITRE stage mapping).

Everything here is deterministic, self-contained, and offline:
  - get_mitre_intel(): MITRE ATT&CK tactic/technique + CVSS + illustrative CVE
    per attack family (aligned with knowledge_base.py / kill_chain_mapping.json).
  - generate_firewall_rules(): real multi-OS (iptables / Windows netsh / Cisco
    ACL) block/rate-limit commands for a source IP + port + family.
  - Flux traps (honeypot): a DNAT-style redirection simulation for demo purposes.

NOTE: the firewall rules are *generated* for the operator to review/apply; this
module does not execute any system commands. The honeypot is a simulation.
"""

# Family names follow the CICIDS mapping used across the main pipeline.
MITRE_ATTACK_MAPPING = {
    "dos": {
        "tactic": "Impact (TA0040)",
        "technique_id": "T1498.001",
        "technique_name": "Network DoS: Direct Network Flood",
        "cvss_score": 7.5,
        "severity": "HIGH",
        "cve_example": "CVE-2023-44487 (HTTP/2 Rapid Reset)",
        "recommended_action": "Rate-limit ingress SYN/TCP, enable SYN cookies, "
        "and shape the offending source at the edge.",
    },
    "port_scan": {
        "tactic": "Reconnaissance (TA0043)",
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "cvss_score": 5.3,
        "severity": "MEDIUM",
        "cve_example": "N/A (active reconnaissance)",
        "recommended_action": "Blackhole the scanner subnet and drop "
        "unacknowledged FIN/NULL/XMAS probe packets.",
    },
    "brute_force": {
        "tactic": "Credential Access (TA0006)",
        "technique_id": "T1110.001",
        "technique_name": "Brute Force: Password Guessing",
        "cvss_score": 8.1,
        "severity": "HIGH",
        "cve_example": "CVE-2024-6387 (regreSSHion)",
        "recommended_action": "Enforce fail2ban, disable password auth, and "
        "require hardware SSH keys.",
    },
    "web_attack": {
        "tactic": "Initial Access (TA0001)",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "cve_example": "CVE-2023-34362 (MOVEit Transfer SQLi); Log4Shell",
        "recommended_action": "Deploy ModSecurity WAF rules, sanitize URI "
        "parameters, and block the attacker session token.",
    },
    "botnet": {
        "tactic": "Command & Control (TA0011)",
        "technique_id": "T1071.001",
        "technique_name": "Application Layer Protocol: Web",
        "cvss_score": 8.0,
        "severity": "HIGH",
        "cve_example": "Mirai (CVE-2017-17215)",
        "recommended_action": "Isolate the beaconing host, block the C2 "
        "destination, and begin host forensics.",
    },
    "none": {
        "tactic": "Legitimate traffic",
        "technique_id": "N/A",
        "technique_name": "Standard operational flow",
        "cvss_score": 0.0,
        "severity": "NONE",
        "cve_example": "N/A",
        "recommended_action": "Allow.",
    },
}


class ActiveDefenseEngine:
    # families we surface with explicit action; anything else falls back to 'none'
    _FALLBACK = {**MITRE_ATTACK_MAPPING, "infiltration": {
        "tactic": "Initial Access (TA0001)",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application (foothold)",
        "cvss_score": 8.5,
        "severity": "HIGH",
        "cve_example": "CVE-2020-1472 (Zerologon)",
        "recommended_action": "Contain the foothold host and segment it.",
    }, "exploit": {
        "tactic": "Initial Access (TA0001)",
        "technique_id": "T1203",
        "technique_name": "Exploitation for Client Execution",
        "cvss_score": 9.0,
        "severity": "CRITICAL",
        "cve_example": "CVE-2019-0708 (BlueKeep)",
        "recommended_action": "Patch the vulnerable service and block the "
        "attacker IP.",
    }}

    @staticmethod
    def get_mitre_intel(attack_type):
        return ActiveDefenseEngine._FALLBACK.get(
            str(attack_type).lower(), MITRE_ATTACK_MAPPING["none"])

    @staticmethod
    def generate_firewall_rules(src_ip, dst_port, attack_type):
        """Return ready-to-review iptables / netsh / Cisco ACL commands."""
        family = str(attack_type).lower()
        if family == "none":
            return {"iptables": "# No action required",
                    "windows_netsh": "# No action required",
                    "cisco_acl": "! No action required"}
        if not src_ip or src_ip in ("", "None", "nan"):
            src_ip = "0.0.0.0/0"
        try:
            port = int(dst_port)
        except (TypeError, ValueError):
            port = 0

        if family == "dos":
            iptables = (
                f"iptables -A INPUT -p tcp --syn -s {src_ip} "
                f"-m limit --limit 1/s --limit-burst 3 -j ACCEPT && "
                f"iptables -A INPUT -s {src_ip} -j DROP")
        elif family == "port_scan":
            iptables = (
                f"iptables -A INPUT -s {src_ip} -m state "
                f"--state NEW -j DROP")
        else:
            iptables = (
                f"iptables -I INPUT -s {src_ip} "
                f"{'-p tcp --dport %d ' % port if port else ''}-j DROP").strip()
        netsh = (f'netsh advfirewall firewall add rule name="SOC_BLOCK_{src_ip}" '
                 f'dir=in action=block remoteip={src_ip}')
        cisco = (f"access-list 101 deny ip host {src_ip} any log\n"
                 f"access-list 101 permit ip any any")
        return {"iptables": iptables, "windows_netsh": netsh, "cisco_acl": cisco}

    @staticmethod
    def simulate_honeypot_trap(attacker_ip, target_port):
        """Simulate redirecting an attacker to a decoy sandbox (demo only)."""
        decoy_ports = {80: 8080, 22: 2222, 443: 8443, 3306: 33060}
        try:
            tport = int(target_port)
        except (TypeError, ValueError):
            tport = 9999
        decoy = decoy_ports.get(tport, 9999)
        session = f"HP-TRAP-{abs(hash((attacker_ip, tport))) % 1000000:06d}"
        return {
            "status": "QUARANTINED",
            "attacker_ip": attacker_ip,
            "diverted_to_decoy_port": decoy,
            "sandbox_session_id": session,
            "honeypot_log": [
                f"[TRAP] Rerouted {attacker_ip} from :{tport} -> sandbox :{decoy}",
                "[INTERCEPT] Fake service banner returned to the probe",
                "[ISOLATE] Bidirectional traffic logged in isolated buffer",
            ],
        }
