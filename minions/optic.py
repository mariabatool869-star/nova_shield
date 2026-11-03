import re


class Optic:
    """NX-01 OPTIC — The vision sensor. Watches logs, produces candidate alerts."""

    UNIT_ID = "NX-01"
    CALLSIGN = "OPTIC"

    FEATURE_NAMES = [
        "Dst Port", "Protocol", "Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts",
        "TotLen Fwd Pkts", "TotLen Bwd Pkts", "Fwd Pkt Len Max", "Fwd Pkt Len Min",
        "Fwd Pkt Len Mean", "Fwd Pkt Len Std", "Bwd Pkt Len Max", "Bwd Pkt Len Min",
        "Bwd Pkt Len Mean", "Bwd Pkt Len Std", "Flow Byts/s", "Flow Pkts/s",
        "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
        "Fwd IAT Tot", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
        "Bwd IAT Tot", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
        "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
        "Fwd Header Len", "Bwd Header Len", "Fwd Pkts/s", "Bwd Pkts/s",
        "Pkt Len Min", "Pkt Len Max", "Pkt Len Mean", "Pkt Len Std",
        "Pkt Len Var", "FIN Flag Cnt", "SYN Flag Cnt", "RST Flag Cnt",
        "PSH Flag Cnt", "ACK Flag Cnt", "URG Flag Cnt", "CWE Flag Count",
        "ECE Flag Cnt", "Down/Up Ratio", "Pkt Size Avg", "Fwd Seg Size Avg",
        "Bwd Seg Size Avg", "Fwd Byts/b Avg", "Fwd Pkts/b Avg", "Fwd Blk Rate Avg",
        "Bwd Byts/b Avg", "Bwd Pkts/b Avg", "Bwd Blk Rate Avg", "Subflow Fwd Pkts",
        "Subflow Fwd Byts", "Subflow Bwd Pkts", "Subflow Bwd Byts",
        "Init Fwd Win Byts", "Init Bwd Win Byts", "Fwd Act Data Pkts",
        "Fwd Seg Size Min", "Active Mean", "Active Std", "Active Max",
        "Active Min", "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
    ]

    def __init__(self):
        self.pattern = re.compile(r"(\d+) connections from (\S+) on port (\d+)")

    def scan(self, log_line: str, decision_id: int) -> dict | None:
        match = self.pattern.search(log_line)

        if match:
            connection_count = int(match.group(1))
            src_ip = match.group(2)
            port = int(match.group(3))

            if port == 80 and connection_count >= 100:
                alert_type = "DDoS"
                values = {
                    "Dst Port": 80, "Protocol": 6,
                    "Flow Duration": 9636.79, "Tot Fwd Pkts": 2.23,
                    "Tot Bwd Pkts": 0.95, "TotLen Fwd Pkts": 93,
                    "TotLen Bwd Pkts": 40, "Fwd Pkt Len Max": 42,
                    "Fwd Pkt Len Min": 20, "Fwd Pkt Len Mean": 42,
                    "Flow Byts/s": 60793.61, "Flow Pkts/s": 890.52,
                    "Flow IAT Mean": 7312.7, "SYN Flag Cnt": 1,
                    "ACK Flag Cnt": 1, "Init Fwd Win Byts": 40566,
                }
            elif port == 22 and connection_count >= 40:
                alert_type = "PortScan"
                values = {
                    "Dst Port": 22, "Protocol": 6,
                    "Flow Duration": 500, "Tot Fwd Pkts": 1,
                    "Tot Bwd Pkts": 0, "Fwd Pkt Len Max": 64,
                    "Flow Pkts/s": 100, "SYN Flag Cnt": 1,
                    "ACK Flag Cnt": 0,
                }
            elif port == 22 and connection_count >= 20:
                alert_type = "SSH-Patator"
                values = {
                    "Dst Port": 22, "Protocol": 6,
                    "Flow Duration": 2000, "Tot Fwd Pkts": 5,
                    "Tot Bwd Pkts": 5, "Fwd Pkt Len Max": 80,
                    "Flow Pkts/s": 10, "SYN Flag Cnt": 1,
                    "ACK Flag Cnt": 1,
                }
            elif port == 443 and connection_count >= 10:
                alert_type = "Bot"
                values = {
                    "Dst Port": 443, "Protocol": 6,
                    "Flow Duration": 15000, "Tot Fwd Pkts": 10,
                    "Tot Bwd Pkts": 10, "Fwd Pkt Len Max": 120,
                    "Flow Pkts/s": 2, "SYN Flag Cnt": 1,
                    "ACK Flag Cnt": 1,
                }
            else:
                alert_type = f"Anomaly_{port}"
                values = {
                    "Dst Port": port, "Protocol": 6,
                    "Flow Duration": 1000, "Tot Fwd Pkts": 2,
                    "Tot Bwd Pkts": 2,
                }

            features = {}
            for name in self.FEATURE_NAMES:
                features[name] = values.get(name, 0)

            return {
                "decision_id": decision_id,
                "alert_type": alert_type,
                "features": features,
                "score": 0.0,
                "explanation": [],
                "action": "monitor",
                "raw_log": log_line.strip()
            }

        return None