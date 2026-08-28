"""
packet_features.py
------------------
Packet-level (PCAP) feature extraction for SIH26153 — closes the flow-level-only
gap flagged in the README. Streams a PCAP with Scapy (PcapReader, no big sockets),
groups packets into windows, and derives:

  1. the SAME 10 per-window raw fields the trained models expect
     (packet_rate, byte_rate, unique_dst_ips, unique_dst_ports, syn_ack_ratio,
      avg_pkt_size, dst_port_entropy, failed_conn_rate, fwd_psh_rate,
      avg_flow_duration) so the existing RandomForest / LSTM forecasters can run
     unchanged on live packet captures, and
  2. packet-level extras the PS explicitly asks for: TTL variance, TCP window
     sizes, IP fragmentation flags, retransmission rate, SYN-only flood rate,
     protocol mix.

A lightweight flow table (5-tuple -> first/last time, seq, bytes) backs the
flow-derived fields and a cheap retransmission estimate. Each window also gets a
heuristic attack family (SYN-scan -> port_scan, ICMP/SYN flood -> dos, ...) so
pcap-only inputs still land on a MITRE stage.

Output is a pre-featurized window CSV (window_id + y_forecast marker) that
infer.py consumes as-is:

    python3 packet_features.py capture.pcap -o windows.csv
    python3 infer.py windows.csv
    streamlit run app.py        # or upload windows.csv in the app

No packet leaves the machine; everything runs offline.
"""

import argparse
import csv
import math
import os
import tempfile
from collections import defaultdict

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.utils import PcapReader

import infer

PACKETS_PER_WINDOW = 500
OUT_COLS = infer.RAW_FEATURE_COLS + [
    "ttl_mean", "ttl_std", "tcp_win_mean", "tcp_win_std", "frag_ratio",
    "df_ratio", "syn_only_rate", "icmp_ratio", "udp_ratio", "retrans_ratio",
    "distinct_src_ips",
]


def _dst_port(pkt):
    if TCP in pkt:
        return int(pkt[TCP].dport)
    if UDP in pkt:
        return int(pkt[UDP].dport)
    return 0


def _heuristic_family(w):
    """Map packet-level signals to a family/stage when no ground-truth labels
    exist (raw pcap input). Cheap interpretable rules, not a model."""
    if w["icmp_ratio"] > 0.4 and w["packet_rate"] > 300:
        return "dos", "Impact (DDoS is MITRE TA0040 — noted explicitly)"
    if w["retrans_ratio"] > 0.2 and w["syn_only_rate"] > 0.15:
        return "dos", "Impact (DDoS is MITRE TA0040 — noted explicitly)"
    if w["syn_only_rate"] > 0.25 and w["unique_dst_ports"] > 50:
        return "port_scan", "Reconnaissance"
    if w["syn_only_rate"] > 0.25:
        return "port_scan", "Reconnaissance"
    if w["unique_dst_ports"] > 20 and w["syn_only_rate"] > 0.05:
        return "port_scan", "Reconnaissance"
    return "none", "-"


class PacketWindowIterator:
    """Streams a pcap and yields one window dict per `window_packets` packets
    (plus a trailing partial window)."""

    def __init__(self, path, window_packets=PACKETS_PER_WINDOW):
        self.path = path
        self.window_packets = window_packets

    def __iter__(self):
        tweets = {
            "n": 0, "ip_bytes": 0, "t_first": None, "t_last": None,
            "dst_ips": set(), "dst_ports": set(), "src_ips": set(),
            "ports_total": 0,
            "syn_ack": 0, "syn_noack": 0, "rst": 0, "tcp": 0, "psh": 0,
            "pkt_sizes": [], "ttls": [], "win_sizes": [], "frag": 0, "df": 0,
            "icmp": 0, "udp": 0,
            "flows": defaultdict(lambda: {"t0": None, "t1": None, "seq": -1,
                                           "seen": 0}),
            "retrans": 0,
        }

        def reset():
            t = tweets
            t["n"] = 0; t["ip_bytes"] = 0; t["t_first"] = None; t["t_last"] = None
            t["dst_ips"] = set(); t["dst_ports"] = set(); t["src_ips"] = set()
            t["ports_total"] = 0
            t["syn_ack"] = 0; t["syn_noack"] = 0; t["rst"] = 0; t["tcp"] = 0
            t["psh"] = 0; t["pkt_sizes"] = []; t["ttls"] = []; t["win_sizes"] = []
            t["frag"] = 0; t["df"] = 0; t["icmp"] = 0; t["udp"] = 0
            t["flows"] = defaultdict(lambda: {"t0": None, "t1": None, "seq": -1,
                                               "seen": 0})
            t["retrans"] = 0

        def finish():
            nonlocal tweets
            out = {}
            n = tweets["n"]
            if n == 0:
                return None
            dur = max(0.0, (tweets["t_last"] or tweets["t_first"]) -
                      (tweets["t_first"] or tweets["t_last"]))
            dur = max(dur, 1e-6)
            tcp_n = max(tweets["tcp"], 1)
            sizes = tweets["pkt_sizes"]
            ttls = tweets["ttls"]
            wins = tweets["win_sizes"]

            flow_durs = [f["t1"] - f["t0"] for f in tweets["flows"].values()
                         if f["t0"] is not None and f["t1"] >= f["t0"]]

            out["packet_rate"] = n / dur
            out["byte_rate"] = tweets["ip_bytes"] / dur
            out["unique_dst_ips"] = len(tweets["dst_ips"])
            out["unique_dst_ports"] = len(tweets["dst_ports"])
            out["syn_ack_ratio"] = (tweets["syn_noack"] + 1.0) / (tweets["syn_ack"] + 1.0)
            out["avg_pkt_size"] = sum(sizes) / len(sizes) if sizes else 0.0
            out["dst_port_entropy"] = infer._entropy(tweets["dst_ports"])
            out["failed_conn_rate"] = tweets["rst"] / tcp_n
            out["fwd_psh_rate"] = tweets["psh"] / tcp_n
            out["avg_flow_duration"] = (sum(flow_durs) / len(flow_durs)) if flow_durs else 0.0

            out["ttl_mean"] = sum(ttls) / len(ttls) if ttls else 0.0
            out["ttl_std"] = (sum((t - out["ttl_mean"]) ** 2 for t in ttls) /
                              len(ttls)) ** 0.5 if len(ttls) > 1 else 0.0
            out["tcp_win_mean"] = sum(wins) / len(wins) if wins else 0.0
            out["tcp_win_std"] = (sum((w - out["tcp_win_mean"]) ** 2 for w in wins) /
                                  len(wins)) ** 0.5 if len(wins) > 1 else 0.0
            out["frag_ratio"] = tweets["frag"] / n
            out["df_ratio"] = tweets["df"] / n
            out["syn_only_rate"] = tweets["syn_noack"] / n
            out["icmp_ratio"] = tweets["icmp"] / n
            out["udp_ratio"] = tweets["udp"] / n
            out["retrans_ratio"] = tweets["retrans"] / n
            out["distinct_src_ips"] = len(tweets["src_ips"])
            out["attack_family"], out["heuristic_stage"] = _heuristic_family(out)
            reset()
            return out

        with PcapReader(self.path) as reader:
            for pkt in reader:
                if IP not in pkt:
                    tweets["n"] += 1
                    tweets["t_last"] = float(pkt.time)
                    continue
                t = float(pkt.time)
                ip = pkt[IP]
                tweets["n"] += 1
                tweets["ip_bytes"] += int(ip.len) if ip.len else 0
                tweets["t_last"] = t
                if tweets["t_first"] is None:
                    tweets["t_first"] = t
                tweets["dst_ips"].add(ip.dst)
                tweets["src_ips"].add(ip.src)
                tweets["ttls"].append(int(ip.ttl))
                if ip.flags != 0:
                    tweets["df"] += 1
                if ip.frag != 0:
                    tweets["frag"] += 1
                sport, dport, proto, winsize, flags = None, None, 0, None, None
                if TCP in pkt:
                    tcp = pkt[TCP]
                    sport, dport, proto = int(tcp.sport), int(tcp.dport), 6
                    winsize = int(tcp.window)
                    flags = int(tcp.flags)
                    tweets["tcp"] += 1
                    tweets["win_sizes"].append(winsize)
                    if flags & 0x02 and not (flags & 0x10):
                        tweets["syn_noack"] += 1
                    elif flags & 0x02 and (flags & 0x10):
                        tweets["syn_ack"] += 1
                    if flags & 0x04:
                        tweets["rst"] += 1
                    if flags & 0x08:
                        tweets["psh"] += 1
                    fkey = (ip.src, ip.dst, sport, dport, proto)
                    f = tweets["flows"][fkey]
                    if f["t0"] is None:
                        f["t0"] = t
                    f["t1"] = t
                    seq = int(tcp.seq)
                    if flags & 0x09:  # FIN / RST/SYN edge cases not retrans
                        pass
                    if flags & 0x02:
                        if flags & 0x10:        # SYN-ACK → next expected client seq
                            f["seq"] = seq + 1
                        elif f["seen"] and seq <= f["seq"]:
                            tweets["retrans"] += 1
                    elif f["seen"] and not (flags & 0x10) and seq < f["seq"]:
                        tweets["retrans"] += 1
                    f["seq"] = max(f["seq"], seq)
                    f["seen"] += 1
                elif UDP in pkt:
                    u = pkt[UDP]
                    sport, dport, proto = int(u.sport), int(u.dport), 17
                    tweets["udp"] += 1
                    fkey = (ip.src, ip.dst, sport, dport, proto)
                    f = tweets["flows"][fkey]
                    f["t1"] = t
                    if f["t0"] is None:
                        f["t0"] = t
                elif ICMP in pkt:
                    tweets["icmp"] += 1
                tweets["ports_total"] += 1
                if dport:
                    tweets["dst_ports"].add(dport)
                tweets["pkt_sizes"].append(int(ip.len) if ip.len else 0)
                if sport and dport and proto:
                    pass

                if tweets["n"] >= self.window_packets:
                    w = finish()
                    if w:
                        yield w
            w = finish()
            if w:
                yield w


def pcap_to_windows_csv(pcap_path, out_path):
    """Write pre-featurized windows CSV readable by infer.py."""
    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["window_id"] + OUT_COLS +
                                             ["attack_family", "heuristic_stage",
                                              "y_forecast"])
        writer.writeheader()
        for wid, w in enumerate(PacketWindowIterator(pcap_path)):
            row = {"window_id": wid, "y_forecast": 0}
            for k in OUT_COLS:
                row[k] = round(float(w.get(k, 0.0)), 6)
            row["attack_family"] = w["attack_family"]
            row["heuristic_stage"] = w["heuristic_stage"]
            writer.writerow(row)


def run_pcap(pcap_path, model="rf", threshold=0.5):
    """Full chain: pcap -> windows CSV (temp) -> saved forecaster -> timeline."""
    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tmp:
        tmp_path = tmp.name
    try:
        pcap_to_windows_csv(pcap_path, tmp_path)
        engine = (infer.RandomForestEngine(threshold=threshold) if model == "rf"
                  else infer.LSTMEngine(threshold=threshold))
        return infer.run_inference(tmp_path, engine)
    finally:
        os.unlink(tmp_path)


def main():
    parser = argparse.ArgumentParser(description="Packet-level feature extraction")
    parser.add_argument("pcap", help="input .pcap (streamed, not loaded in RAM)")
    parser.add_argument("-o", "--out", default="pcap_windows.csv",
                        help="output pre-featurized windows CSV")
    parser.add_argument("--model", choices=["rf", "lstm"], default="rf")
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--infer", action="store_true",
                        help="also run the saved forecaster and print the timeline")
    args = parser.parse_args()

    print(f"Reading {args.pcap} in windows of {PACKETS_PER_WINDOW} packets...")
    pcap_to_windows_csv(args.pcap, args.out)
    print(f"Wrote {args.out}")
    if args.infer:
        timeline, summary = run_pcap(args.pcap, args.model, args.threshold)
        print(f"\n=== Summary ({args.model.upper()}) ===")
        for k, v in summary.items():
            print(f"  {k}: {v}")


if __name__ == "__main__":
    main()