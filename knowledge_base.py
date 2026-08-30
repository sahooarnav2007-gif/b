"""
knowledge_base.py
-----------------
CAPEC / CVE enrichment for SIH26153. The NCIIPC note for the PS lists MITRE
CAPEC and CVE/NVD as available knowledge bases — this module adds a light,
explainable layer on top of the MITRE ATT&CK stage mapping: for every predicted
attack family we surface the relevant CAPEC attack patterns and well-known real
CVEs, so the demo can answer "what technique, and has this been seen in the
wild?" alongside "what stage?".

CAPEC IDs are authoritative MITRE identifiers; the CVE examples are illustrative
well-known instances of the technique class, not claims that the specific window
IS that CVE.
"""

FAMILY_META = {
    "port_scan": {
        "description": "Active reconnaissance — probing services/ports to map the target",
        "stage": "Reconnaissance",
        "capec": [("CAPEC-287", "TCP Scan"), ("CAPEC-300", "Port Scanning"),
                  ("CAPEC-541", "Application Fingerprinting")],
        "cves": ["CVE-2019-0708 scan campaigns (BlueKeep pre-conditions)",
                 "CVE-2020-0601 cert-processor scanning"],
    },
    "brute_force": {
        "description": "Repeated credential guesses against a login service",
        "stage": "Initial Access",
        "capec": [("CAPEC-600", "Credential Stuffing"), ("CAPEC-16", "Brute Force"),
                  ("CAPEC-49", "Password Brute Forcing")],
        "cves": ["CVE-2021-39144 (Apache Ambari auth bypass)",
                 "Hafnium exchange password-spray campaigns (2021)"],
    },
    "web_attack": {
        "description": "Exploitation of a web-facing application",
        "stage": "Initial Access",
        "capec": [("CAPEC-66", "SQL Injection"), ("CAPEC-242", "XSS"),
                  ("CAPEC-586", "Overflow in Application"), ("CAPEC-272", "Protocol Manipulation")],
        "cves": ["CVE-2017-5638 (Apache Struts2 RCE)", "CVE-2021-44228 (Log4Shell)"],
    },
    "infiltration": {
        "description": "Introductory foothold inside the network (delivery/replication)",
        "stage": "Initial Access",
        "capec": [("CAPEC-10", "Buffer Overflow via Environment Variables"),
                  ("CAPEC-54", "Probing in an Application Container")],
        "cves": ["CVE-2019-19781 (Citrix ADC)", "CVE-2020-1472 (Zerologon)"],
    },
    "exploit": {
        "description": "Direct exploitation of a vulnerable service",
        "stage": "Initial Access",
        "capec": [("CAPEC-233", "Privilege Escalation via Exploitation"),
                  ("CAPEC-94", "Man in the Middle Attacks")],
        "cves": ["CVE-2021-44228 (Log4Shell)", "CVE-2019-0708 (BlueKeep)"],
    },
    "botnet": {
        "description": "Compromised hosts phoning home / receiving commands",
        "stage": "Command & Control",
        "capec": [("CAPEC-491", "C2 of compromised endpoint through simulated API"),
                  ("CAPEC-649", "Command Line Execution via Malicious files")],
        "cves": ["CVE-2017-17215 (Mirai/Huawei HG532)", "CVE-2016-10401 (Netgear genie)"],
    },
    "dos": {
        "description": "Resource exhaustion / flooding (availability impact)",
        "stage": "Impact (MITRE TA0040 — noted explicitly)",
        "capec": [("CAPEC-125", "Flooding"), ("CAPEC-130", "Excessive Allocation"),
                  ("CAPEC-469", "HTTP DoS")],
        "cves": ["CVE-2018-1000115 (memcached UDP amplification)",
                 "CVE-2023-36439 (networking DoS)"],
    },
    "none": {
        "description": "No active attack family predicted",
        "stage": "-",
        "capec": [],
        "cves": [],
    },
}


def family_meta(family):
    return FAMILY_META.get(str(family), {
        "description": "Unknown family",
        "stage": "unmapped",
        "capec": [],
        "cves": [],
    })


def capec_chain(family):
    """Return the CAPEC IDs for a family joined into a display string."""
    meta = family_meta(family)
    if not meta["capec"]:
        return "-"
    return "; ".join(f"{cid} {name}" for cid, name in meta["capec"])