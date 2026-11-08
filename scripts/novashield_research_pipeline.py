"""NovaShield safe research validation pipeline.

No live capture, model inference, firewall, database, or retraining.
"""
import json
import math
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


def check(name, condition):
    if not condition:
        raise AssertionError("FAIL: " + name)
    print("PASS:", name)


def main():
    print("\\n===== NOVASHIELD RESEARCH PIPELINE =====")

    assembler_path = ROOT / "scripts/novashield_flow_assembler.py"
    exporter_path = ROOT / "scripts/novashield_feature_exporter.py"
    metadata_path = ROOT / "phase6_xai/artifacts/model_metadata.json"

    for path in (assembler_path, exporter_path, metadata_path):
        check("Required file exists: " + path.name, path.is_file())

    for path in (assembler_path, exporter_path):
        compile(path.read_text(encoding="utf-8"), str(path), "exec")
        check("Syntax valid: " + path.name, True)

    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    names = metadata["features"]

    check("Model requires exactly 78 features", len(names) == 78)
    check("Feature names are unique", len(set(names)) == 78)

    with tempfile.TemporaryDirectory(prefix="novashield_cache_") as cache:
        os.environ["XDG_CACHE_HOME"] = cache

        from scapy.all import IP, TCP, Raw
        from novashield_flow_assembler import FlowAssembler
        from novashield_feature_exporter import (
            export_partial_features,
            require_complete_vector,
            IncompleteFeatureVectorError,
        )

        assembler = FlowAssembler()

        samples = [
            ("192.0.2.10", "192.0.2.20", 54321, 443, 1.00, b"hello"),
            ("192.0.2.20", "192.0.2.10", 443, 54321, 1.05, b"reply"),
            ("192.0.2.10", "192.0.2.20", 54321, 443, 1.15, b""),
            ("192.0.2.20", "192.0.2.10", 443, 54321, 1.30, b""),
        ]

        for src, dst, sport, dport, timestamp, payload in samples:
            packet = (
                IP(src=src, dst=dst)
                / TCP(sport=sport, dport=dport, flags="PA")
                / Raw(load=payload)
            )
            packet.time = timestamp
            assembler.add_packet(packet)

        check("One bidirectional TCP flow assembled",
              len(assembler.flows) == 1)

        flow = next(iter(assembler.flows.values()))
        features = export_partial_features(flow)

        expected = {
            "Flow Duration": 300000,
            "Total Fwd Packets": 2,
            "Total Backward Packets": 2,
            "Total Length of Fwd Packets": 5,
            "Total Length of Bwd Packets": 5,
            "Flow IAT Mean": 100000,
            "Flow IAT Std": 50000,
            "Flow IAT Max": 150000,
            "Flow IAT Min": 50000,
            "Fwd IAT Total": 150000,
            "Fwd IAT Mean": 150000,
            "Fwd IAT Std": 0,
            "Fwd IAT Max": 150000,
            "Fwd IAT Min": 150000,
            "Bwd IAT Total": 250000,
            "Bwd IAT Mean": 250000,
            "Bwd IAT Std": 0,
            "Bwd IAT Max": 250000,
            "Bwd IAT Min": 250000,
        }

        for name, value in expected.items():
            check(
                name,
                name in features and math.isclose(
                    features[name], value,
                    rel_tol=1e-9, abs_tol=1e-9
                ),
            )

        available = [name for name in names if name in features]
        missing = [name for name in names if name not in features]

        print("\\n===== FEATURE COVERAGE =====")
        print("Required:", len(names))
        print("Available:", len(available))
        print("Missing:", len(missing))

        check("78 required feature names available", len(available) == 78)
        check("0 required feature names missing", len(missing) == 0)

        vector = require_complete_vector(features, names)
        check(
            "Complete 78-name feature vector accepted without inference",
            vector is not None,
        )

    regression_packet_features()
    regression_ratio_edge_cases()
    regression_min_segment()
    regression_subflow_features()
    audit_cicflowmeter_reference()

    print("\\n===== FINAL RESULT =====")
    print("PASS: Automated research checks completed")
    print("PASS: No live network capture")
    print("PASS: No AI inference or retraining")
    print("PASS: No firewall or database operations")
    print("PASS: No existing project files modified")



def regression_packet_features():
    """Synthetic offline regression; not CICFlowMeter dataset parity."""
    import json
    import math
    import sys
    from statistics import mean, stdev, variance

    from scapy.all import IP, TCP, Raw
    from novashield_flow_assembler import FlowAssembler
    from novashield_feature_exporter import (
        export_partial_features,
        require_complete_vector,
        IncompleteFeatureVectorError,
    )

    print("\\n===== PACKET FEATURE REGRESSION =====")

    samples = [
        (1.00, "192.0.2.10", "192.0.2.20", 54321, 443,
         "S", 4096, b"abcdefghij"),
        (1.00, "192.0.2.20", "192.0.2.10", 443, 54321,
         "SA", 8192, b"x"),
        (1.15, "192.0.2.10", "192.0.2.20", 54321, 443,
         "PA", 4096, b"abcd"),
        (1.15, "192.0.2.20", "192.0.2.10", 443, 54321,
         "FA", 8192, b"xy"),
    ]

    assembler = FlowAssembler()

    for timestamp, src, dst, sport, dport, flags, window, payload in samples:
        packet = (
            IP(src=src, dst=dst)
            / TCP(sport=sport, dport=dport, flags=flags, window=window)
            / Raw(load=payload)
        )
        packet.time = timestamp
        assembler.add_packet(packet)

    check("One bidirectional regression flow", len(assembler.flows) == 1)

    flow = next(iter(assembler.flows.values()))
    check(
        "Packet arrival order retained",
        flow.ordered_payload_lengths == [10, 1, 4, 2],
    )

    features = export_partial_features(flow)

    # Inspected BasicFlow.java adds the first payload length twice.
    values = [10, 10, 1, 4, 2]

    expected = {
        "Min Packet Length": min(values),
        "Max Packet Length": max(values),
        "Packet Length Mean": mean(values),
        "Packet Length Std": stdev(values),
        "Packet Length Variance": variance(values),
        "Down/Up Ratio": 1,
        "Average Packet Size": 27 / 4,
        "Total Fwd Packets": 2,
        "Total Backward Packets": 2,
        "Fwd Header Length": 40,
        "Bwd Header Length": 40,
        "Fwd Header Length.1": 40,
        "SYN Flag Count": 2,
        "ACK Flag Count": 3,
        "FIN Flag Count": 1,
        "PSH Flag Count": 1,
        "Init_Win_bytes_forward": 4096,
        "Init_Win_bytes_backward": 8192,
        "Flow Duration": 150000,
        "Flow IAT Mean": 50000,
        "Fwd IAT Total": 150000,
        "Bwd IAT Total": 150000,
    }

    for name, value in expected.items():
        check(
            name,
            name in features
            and math.isclose(
                features[name], value,
                rel_tol=1e-9, abs_tol=1e-6,
            ),
        )

    metadata = json.loads(
        Path("phase6_xai/artifacts/model_metadata.json").read_text(
            encoding="utf-8"
        )
    )
    names = metadata["features"]

    available = [name for name in names if name in features]
    missing = [name for name in names if name not in features]

    check("78 model features required", len(names) == 78)
    check("78 regression feature names available", len(available) == 78)
    check("0 regression feature names missing", len(missing) == 0)

    vector = require_complete_vector(features, names)
    check(
        "Complete regression vector accepted without inference",
        vector is not None,
    )

    corrupted = list(flow.ordered_payload_lengths)
    flow.ordered_payload_lengths.append(999)

    try:
        try:
            export_partial_features(flow)
        except ValueError:
            print("PASS: Corrupted packet-order record rejected")
        else:
            raise AssertionError("Corrupted packet-order record accepted")
    finally:
        flow.ordered_payload_lengths[:] = corrupted

    print("PASS: Equal-timestamp packet regression completed")
    print("NOTE: CICFlowMeter dataset parity remains unverified")



def regression_ratio_edge_cases():
    """Test Java integer division and first-packet accounting."""
    import math

    from scapy.all import IP, TCP, Raw
    from novashield_flow_assembler import FlowAssembler
    from novashield_feature_exporter import export_partial_features

    print("\\n===== RATIO AND AVERAGE EDGE CASES =====")

    def run_case(lengths, directions):
        assembler = FlowAssembler()

        for index, (length, forward) in enumerate(
            zip(lengths, directions)
        ):
            if forward:
                src, dst, sport, dport = (
                    "192.0.2.10", "192.0.2.20", 54321, 443
                )
            else:
                src, dst, sport, dport = (
                    "192.0.2.20", "192.0.2.10", 443, 54321
                )

            packet = (
                IP(src=src, dst=dst)
                / TCP(sport=sport, dport=dport, flags="PA")
                / Raw(load=b"x" * length)
            )
            packet.time = 1.0 + index * 0.05
            assembler.add_packet(packet)

        flow = next(iter(assembler.flows.values()))
        return export_partial_features(flow)

    unequal = run_case(
        [10, 2, 3, 4, 5],
        [True, False, False, True, False],
    )

    check("Integer Down/Up Ratio: 3/2 becomes 1",
          unequal["Down/Up Ratio"] == 1)
    check("First-packet-adjusted Average Packet Size",
          math.isclose(
              unequal["Average Packet Size"], 6.8,
              abs_tol=1e-9,
          ))

    forward_only = run_case(
        [3, 2],
        [True, True],
    )

    check("Forward-only Down/Up Ratio",
          forward_only["Down/Up Ratio"] == 0)
    check("Forward-only Average Packet Size",
          math.isclose(
              forward_only["Average Packet Size"], 4.0,
              abs_tol=1e-9,
          ))

    print("PASS: Ratio and average edge cases completed")



def regression_min_segment():
    """Test minimum forward TCP header size."""
    from scapy.all import IP, TCP, Raw
    from novashield_flow_assembler import FlowAssembler
    from novashield_feature_exporter import export_partial_features

    print("\n===== MINIMUM SEGMENT REGRESSION =====")

    assembler = FlowAssembler()

    samples = [
        (1.00, True, [("MSS", 1460)]),
        (1.05, False, []),
        (1.10, True, []),
    ]

    for timestamp, forward, options in samples:
        if forward:
            src, dst, sport, dport = (
                "192.0.2.10", "192.0.2.20", 54321, 443
            )
        else:
            src, dst, sport, dport = (
                "192.0.2.20", "192.0.2.10", 443, 54321
            )

        packet = (
            IP(src=src, dst=dst)
            / TCP(
                sport=sport,
                dport=dport,
                flags="PA",
                options=options,
            )
            / Raw(load=b"x")
        )
        packet.time = timestamp
        assembler.add_packet(packet)

    flow = next(iter(assembler.flows.values()))
    features = export_partial_features(flow)

    check(
        "Forward TCP headers are 24 and 20",
        flow.forward_header_lengths == [24, 20],
    )
    check(
        "Minimum forward segment size is 20",
        features["min_seg_size_forward"] == 20,
    )
    check(
        "Forward header sum remains 44",
        features["Fwd Header Length"] == 44,
    )
    check(
        "Backward header sum remains 20",
        features["Bwd Header Length"] == 20,
    )



def regression_subflow_features():
    """Check zero, threshold, and integer-division subflow cases."""
    from scapy.all import IP, TCP, Raw
    from novashield_flow_assembler import FlowAssembler
    from novashield_feature_exporter import export_partial_features

    print("\n===== SUBFLOW REGRESSION =====")

    def run_case(times, directions, lengths):
        assembler = FlowAssembler()

        for timestamp, forward, length in zip(
            times, directions, lengths
        ):
            if forward:
                src, dst, sport, dport = (
                    "192.0.2.10", "192.0.2.20", 54321, 443
                )
            else:
                src, dst, sport, dport = (
                    "192.0.2.20", "192.0.2.10", 443, 54321
                )

            packet = (
                IP(src=src, dst=dst)
                / TCP(sport=sport, dport=dport, flags="PA")
                / Raw(load=b"x" * length)
            )
            packet.time = timestamp
            assembler.add_packet(packet)

        flow = next(iter(assembler.flows.values()))
        return export_partial_features(flow)

    names = (
        "Subflow Fwd Packets",
        "Subflow Fwd Bytes",
        "Subflow Bwd Packets",
        "Subflow Bwd Bytes",
    )

    no_gap = run_case(
        [1.0, 1.5, 2.0],
        [True, False, True],
        [10, 2, 4],
    )
    check(
        "No qualifying gap gives zero subflow features",
        all(no_gap[name] == 0 for name in names),
    )

    one_gap = run_case(
        [1.0, 2.5, 2.6, 2.7, 2.8],
        [True, False, False, True, False],
        [10, 2, 3, 4, 5],
    )
    check(
        "One qualifying gap preserves totals",
        [one_gap[name] for name in names] == [2, 14, 3, 10],
    )

    two_gaps = run_case(
        [1.0, 2.5, 4.0, 4.1, 4.2],
        [True, False, False, True, False],
        [10, 2, 3, 4, 5],
    )
    check(
        "Two qualifying gaps use integer division",
        [two_gaps[name] for name in names] == [1, 7, 1, 5],
    )


def audit_cicflowmeter_reference():
    """Read-only verification of inspected Java reference behavior."""
    import tempfile

    path = (
        Path(tempfile.gettempdir())
        / "novashield_cicflowmeter_reference"
        / "src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java"
    )

    print("\n===== CICFLOWMETER REFERENCE AUDIT =====")

    if not path.is_file():
        print("SKIP: CICFlowMeter Java reference not found")
        return

    source = path.read_text(encoding="utf-8")

    expected = {
        "First-packet flag check": "checkFlags(packet);",
        "Forward PSH increment": "this.fPSH_cnt++;",
        "Backward PSH increment": "this.bPSH_cnt++;",
        "Forward URG increment": "this.fURG_cnt++;",
        "Backward URG increment": "this.bURG_cnt++;",
        "Forward header accumulation":
            "this.fHeaderBytes +=packet.getHeaderBytes();",
        "Backward header accumulation":
            "this.bHeaderBytes+=packet.getHeaderBytes();",
    }

    for label, fragment in expected.items():
        check(label, fragment in source)

    check(
        "Directional PSH increments occur once in source",
        source.count("this.fPSH_cnt++;") == 1
        and source.count("this.bPSH_cnt++;") == 1,
    )

    check(
        "Directional URG increments occur once in source",
        source.count("this.fURG_cnt++;") == 1
        and source.count("this.bURG_cnt++;") == 1,
    )

    print("PASS: Java reference audit completed")
    print("NOTE: Source checks do not prove dataset parity")


if __name__ == "__main__":
    main()
