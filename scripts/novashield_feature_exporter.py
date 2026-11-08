"""Research-only partial CIC-IDS2017 feature exporter.

Produces measured features, not a complete 78-feature model vector.
Does not perform capture, inference, enforcement, or database operations.
"""

from math import isfinite
from statistics import mean, stdev, variance


class IncompleteFeatureVectorError(ValueError):
    """Raised when a complete model vector is requested prematurely."""


def _length_statistics(values, prefix):
    if not values:
        return {}

    return {
        f"{prefix} Packet Length Max": max(values),
        f"{prefix} Packet Length Min": min(values),
        f"{prefix} Packet Length Mean": mean(values),
        f"{prefix} Packet Length Std": (
            stdev(values) if len(values) > 1 else 0.0
        ),
    }


def _iat_gaps_microseconds(timestamps):
    """Calculate adjacent packet gaps in microseconds."""
    gaps = []

    for previous, current in zip(timestamps, timestamps[1:]):
        gap = (current - previous) * 1_000_000

        if not isfinite(gap) or gap < 0:
            raise ValueError("Invalid packet timestamp sequence.")

        gaps.append(round(gap))

    return gaps


def _iat_statistics(gaps, prefix, include_total=False):
    """Calculate measured IAT statistics."""
    if not gaps:
        result = {
            f"{prefix} IAT Mean": 0.0,
            f"{prefix} IAT Std": 0.0,
            f"{prefix} IAT Max": 0.0,
            f"{prefix} IAT Min": 0.0,
        }
        if include_total:
            result[f"{prefix} IAT Total"] = 0.0
        return result

    result = {
        f"{prefix} IAT Mean": mean(gaps),
        f"{prefix} IAT Std": (
            stdev(gaps) if len(gaps) > 1 else 0.0
        ),
        f"{prefix} IAT Max": max(gaps),
        f"{prefix} IAT Min": min(gaps),
    }

    if include_total:
        result[f"{prefix} IAT Total"] = sum(gaps)

    return result



def _reference_bulk_features(times, lengths, directions):
    """Reproduce inspected BasicFlow.java directional bulk state machine."""
    if not (len(times) == len(lengths) == len(directions)):
        raise ValueError("Bulk packet metadata count mismatch.")

    states = {
        True: {
            "start": 0, "last": 0, "candidate_packets": 0,
            "candidate_bytes": 0, "states": 0, "packets": 0,
            "bytes": 0, "duration": 0,
        },
        False: {
            "start": 0, "last": 0, "candidate_packets": 0,
            "candidate_bytes": 0, "states": 0, "packets": 0,
            "bytes": 0, "duration": 0,
        },
    }

    for timestamp, size, direction in zip(times, lengths, directions):
        if type(direction) is not bool:
            raise ValueError("Invalid ordered packet direction.")

        # CICFlowMeter stores timestamps in microseconds.
        ts = round(float(timestamp) * 1_000_000)
        current = states[direction]
        other = states[not direction]

        # Java resets the candidate when opposite-direction bulk
        # activity occurred after this candidate began.
        if other["last"] > current["start"]:
            current["start"] = 0

        # Zero-payload packets may reset the candidate but cannot
        # start, extend, or complete a bulk.
        if size <= 0:
            continue

        if current["start"] == 0:
            current["start"] = ts
            current["candidate_packets"] = 1
            current["candidate_bytes"] = size
            current["last"] = ts
        elif ts - current["last"] > 1_000_000:
            current["start"] = ts
            current["last"] = ts
            current["candidate_packets"] = 1
            current["candidate_bytes"] = size
        else:
            current["candidate_packets"] += 1
            current["candidate_bytes"] += size

            if current["candidate_packets"] == 4:
                current["states"] += 1
                current["packets"] += 4
                current["bytes"] += current["candidate_bytes"]
                current["duration"] += ts - current["start"]
            elif current["candidate_packets"] > 4:
                current["packets"] += 1
                current["bytes"] += size
                current["duration"] += ts - current["last"]

            current["last"] = ts

    result = {}

    for direction, prefix in ((True, "Fwd"), (False, "Bwd")):
        state = states[direction]
        count = state["states"]
        duration = state["duration"]

        result[f"{prefix} Avg Bytes/Bulk"] = (
            state["bytes"] // count if count else 0
        )
        result[f"{prefix} Avg Packets/Bulk"] = (
            state["packets"] // count if count else 0
        )
        result[f"{prefix} Avg Bulk Rate"] = (
            int(state["bytes"] / (duration / 1_000_000))
            if duration else 0
        )

    return result



def _reference_active_idle_features(times, threshold_us=5_000_000):
    """Research approximation of inspected CICFlowMeter activity updates.

    No automatic flow-end finalization, splitting, or model execution.
    """
    from math import isfinite
    from statistics import mean, stdev

    if type(threshold_us) is not int or threshold_us <= 0:
        raise ValueError("Invalid activity timeout")

    if not times:
        raise ValueError("Missing packet timestamps")

    timestamps = []

    for value in times:
        timestamp = float(value)

        if not isfinite(timestamp):
            raise ValueError("Non-finite packet timestamp")

        timestamps.append(round(timestamp * 1_000_000))

    if any(
        current < previous
        for previous, current in zip(timestamps, timestamps[1:])
    ):
        raise ValueError("Out-of-order packet timestamps")

    start = end = timestamps[0]
    active = []
    idle = []

    # Ordinary accepted packets update active/idle state.
    for current in timestamps[1:]:
        gap = current - end

        if gap > threshold_us:
            if end - start > 0:
                active.append(end - start)

            idle.append(gap)
            start = end = current
        else:
            end = current

    # Do not invent an unfinished final active interval.
    result = {}

    for prefix, values in (("Active", active), ("Idle", idle)):
        result[f"{prefix} Mean"] = mean(values) if values else 0.0
        result[f"{prefix} Std"] = (
            stdev(values) if len(values) > 1 else 0.0
        )
        result[f"{prefix} Max"] = max(values) if values else 0.0
        result[f"{prefix} Min"] = min(values) if values else 0.0

    return result


def export_partial_features(flow):
    """Return genuine available measurements for an assembled TCP flow."""
    duration = float(flow.duration_seconds)

    if not isfinite(duration) or duration < 0:
        raise ValueError("Invalid flow duration.")

    forward = list(flow.forward_lengths)
    backward = list(flow.backward_lengths)

    if len(forward) != flow.forward_packets:
        raise ValueError("Forward packet count mismatch.")

    if len(backward) != flow.backward_packets:
        raise ValueError("Backward packet count mismatch.")

    if any(
        not isinstance(length, int) or length < 0
        for length in forward + backward
    ):
        raise ValueError("Invalid TCP payload length.")

    total_packets = flow.forward_packets + flow.backward_packets
    total_bytes = sum(forward) + sum(backward)

    features = {
        "Destination Port": int(flow.destination[1]),
        "Flow Duration": round(duration * 1_000_000),
        "Total Fwd Packets": flow.forward_packets,
        "Total Backward Packets": flow.backward_packets,
        "Total Length of Fwd Packets": sum(forward),
        "Total Length of Bwd Packets": sum(backward),
        "Avg Fwd Segment Size": (
            mean(forward) if forward else 0.0
        ),
        "Avg Bwd Segment Size": (
            mean(backward) if backward else 0.0
        ),
    }

    features.update(_length_statistics(forward, "Fwd"))
    features.update(_length_statistics(backward, "Bwd"))

    all_times = list(flow.packet_timestamps)
    fwd_times = list(flow.forward_timestamps)
    bwd_times = list(flow.backward_timestamps)

    if len(all_times) != total_packets:
        raise ValueError("Total timestamp count mismatch.")

    if len(fwd_times) != flow.forward_packets:
        raise ValueError("Forward timestamp count mismatch.")

    if len(bwd_times) != flow.backward_packets:
        raise ValueError("Backward timestamp count mismatch.")

    if any(
        not isfinite(float(value))
        for value in all_times + fwd_times + bwd_times
    ):
        raise ValueError("Invalid packet timestamp.")

    flow_gaps = _iat_gaps_microseconds(all_times)
    fwd_gaps = _iat_gaps_microseconds(fwd_times)
    bwd_gaps = _iat_gaps_microseconds(bwd_times)

    features.update(_iat_statistics(flow_gaps, "Flow"))
    features.update(
        _iat_statistics(fwd_gaps, "Fwd", include_total=True)
    )
    features.update(
        _iat_statistics(bwd_gaps, "Bwd", include_total=True)
    )


    # TCP metadata collected from the actual Scapy packet fields.
    all_flags = list(flow.tcp_flags)
    fwd_flags = list(flow.forward_tcp_flags)
    bwd_flags = list(flow.backward_tcp_flags)
    fwd_headers = list(flow.forward_header_lengths)
    bwd_headers = list(flow.backward_header_lengths)
    fwd_windows = list(flow.forward_window_sizes)
    bwd_windows = list(flow.backward_window_sizes)

    metadata_checks = [
        (all_flags, total_packets),
        (fwd_flags, flow.forward_packets),
        (bwd_flags, flow.backward_packets),
        (fwd_headers, flow.forward_packets),
        (bwd_headers, flow.backward_packets),
        (fwd_windows, flow.forward_packets),
        (bwd_windows, flow.backward_packets),
    ]

    if any(len(values) != expected for values, expected in metadata_checks):
        raise ValueError("TCP metadata count mismatch.")

    if any(
        not isinstance(value, int) or value < 0
        for values, _ in metadata_checks
        for value in values
    ):
        raise ValueError("Invalid TCP metadata value.")

    # CICFlowMeter's inspected BasicFlow implementation increments
    # directional PSH/URG counters only in firstPacket().
    features.update({
        "Fwd PSH Flags": int(bool(fwd_flags and fwd_flags[0] & 0x08)),
        "Bwd PSH Flags": int(bool(
            not fwd_flags and bwd_flags and bwd_flags[0] & 0x08
        )),
        "Fwd URG Flags": int(bool(fwd_flags and fwd_flags[0] & 0x20)),
        "Bwd URG Flags": int(bool(
            not fwd_flags and bwd_flags and bwd_flags[0] & 0x20
        )),
        "Fwd Header Length": sum(fwd_headers),
        "min_seg_size_forward": min(fwd_headers) if fwd_headers else 0,
        "Bwd Header Length": sum(bwd_headers),
        "Fwd Header Length.1": sum(fwd_headers),
        "FIN Flag Count": sum(bool(flags & 0x01) for flags in all_flags),
        "SYN Flag Count": sum(bool(flags & 0x02) for flags in all_flags),
        "RST Flag Count": sum(bool(flags & 0x04) for flags in all_flags),
        "PSH Flag Count": sum(bool(flags & 0x08) for flags in all_flags),
        "ACK Flag Count": sum(bool(flags & 0x10) for flags in all_flags),
        "URG Flag Count": sum(bool(flags & 0x20) for flags in all_flags),
        "CWE Flag Count": sum(bool(flags & 0x80) for flags in all_flags),
        "ECE Flag Count": sum(bool(flags & 0x40) for flags in all_flags),
        "Init_Win_bytes_forward": fwd_windows[0] if fwd_windows else -1,
        "Init_Win_bytes_backward": (
            bwd_windows[-1] if bwd_windows else -1
        ),
        "act_data_pkt_fwd": sum(length >= 1 for length in forward[1:]),
    })

    # Use integer-microsecond duration for per-second rates.
    # Avoid floating-point cancellation in large epoch timestamps.
    rate_duration = features["Flow Duration"] / 1_000_000

    if rate_duration > 0:
        features["Fwd Packets/s"] = flow.forward_packets / rate_duration
        features["Bwd Packets/s"] = flow.backward_packets / rate_duration


    # Inspected CICFlowMeter BasicFlow.java behavior:
    # firstPacket() inserts the first payload length twice into
    # flowLengthStats; addPacket() inserts subsequent lengths once.
    # This is a reference-version compatibility calculation,
    # not proof of CIC-IDS2017 dataset parity.
    ordered_lengths = list(flow.ordered_payload_lengths)

    if len(ordered_lengths) != total_packets:
        raise ValueError("Ordered payload count mismatch.")

    if any(
        not isinstance(length, int) or length < 0
        for length in ordered_lengths
    ):
        raise ValueError("Invalid ordered payload length.")

    if sum(ordered_lengths) != total_bytes:
        raise ValueError("Ordered payload byte total mismatch.")

    # Inspected CICFlowMeter BasicFlow.java compatibility:
    # Java performs integer division before casting Down/Up Ratio.
    features["Down/Up Ratio"] = (
        flow.backward_packets // flow.forward_packets
        if flow.forward_packets > 0 else 0.0
    )

    # flowLengthStats contains the first payload length twice.
    # Its sum is divided by the real packet count, not the
    # number of observations in flowLengthStats.
    features["Average Packet Size"] = (
        (total_bytes + ordered_lengths[0]) / total_packets
        if total_packets > 0 else 0.0
    )

    if ordered_lengths:
        reference_lengths = [
            ordered_lengths[0],
            *ordered_lengths,
        ]

        features.update({
            "Min Packet Length": min(reference_lengths),
            "Max Packet Length": max(reference_lengths),
            "Packet Length Mean": mean(reference_lengths),
            "Packet Length Std": (
                stdev(reference_lengths)
                if len(reference_lengths) > 1 else 0.0
            ),
            "Packet Length Variance": (
                variance(reference_lengths)
                if len(reference_lengths) > 1 else 0.0
            ),
        })

    # A zero-duration flow has undefined per-second rates.
    # Do not silently invent finite values.
    if rate_duration > 0:
        features["Flow Bytes/s"] = total_bytes / rate_duration
        features["Flow Packets/s"] = total_packets / rate_duration

    # Inspected CICFlowMeter BasicFlow.java:
    # sfCount starts at zero and increases only for gaps > 1 second.
    # Java integer division is preserved.
    subflow_count = sum(
        (current - previous) > 1.0
        for previous, current in zip(all_times, all_times[1:])
    )

    features.update({
        "Subflow Fwd Packets": (
            flow.forward_packets // subflow_count
            if subflow_count else 0
        ),
        "Subflow Fwd Bytes": (
            sum(forward) // subflow_count
            if subflow_count else 0
        ),
        "Subflow Bwd Packets": (
            flow.backward_packets // subflow_count
            if subflow_count else 0
        ),
        "Subflow Bwd Bytes": (
            sum(backward) // subflow_count
            if subflow_count else 0
        ),
    })

    ordered_directions = list(flow.ordered_directions)

    if len(ordered_directions) != total_packets:
        raise ValueError("Ordered direction count mismatch.")

    if (
        sum(direction is True for direction in ordered_directions)
        != flow.forward_packets
        or sum(direction is False for direction in ordered_directions)
        != flow.backward_packets
    ):
        raise ValueError("Ordered direction totals mismatch.")

    # Check that direction and payload sequences agree.
    if [
        size for size, direction in zip(
            ordered_lengths, ordered_directions
        ) if direction
    ] != forward:
        raise ValueError("Forward ordered payload mismatch.")

    if [
        size for size, direction in zip(
            ordered_lengths, ordered_directions
        ) if not direction
    ] != backward:
        raise ValueError("Backward ordered payload mismatch.")

    features.update(
        _reference_bulk_features(
            all_times, ordered_lengths, ordered_directions
        )
    )

    features.update(_reference_active_idle_features(all_times))

    return features


def require_complete_vector(features, expected_names):
    """Fail closed if any trained-model feature is unavailable."""
    missing = [
        name for name in expected_names
        if name not in features
    ]

    if missing:
        raise IncompleteFeatureVectorError(
            f"Cannot run AI inference: {len(missing)} "
            f"required features are unavailable. "
            f"First missing feature: {missing[0]}"
        )

    if any(
        not isinstance(features[name], (int, float))
        or not isfinite(features[name])
        for name in expected_names
    ):
        raise ValueError("Model vector contains invalid values.")

    return [features[name] for name in expected_names]
