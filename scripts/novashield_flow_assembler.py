"""NovaShield research-only bidirectional TCP flow assembler.

No live capture, AI inference, firewall actions, or database operations.
This is NOT a complete CIC-IDS2017 feature extractor.
"""

from dataclasses import dataclass, field
from math import isfinite


@dataclass
class Flow:
    origin: tuple
    destination: tuple
    first_seen: float
    last_seen: float
    forward_packets: int = 0
    backward_packets: int = 0
    forward_lengths: list = field(default_factory=list)
    backward_lengths: list = field(default_factory=list)
    packet_timestamps: list = field(default_factory=list)
    ordered_payload_lengths: list = field(default_factory=list)
    ordered_directions: list = field(default_factory=list)
    forward_timestamps: list = field(default_factory=list)
    backward_timestamps: list = field(default_factory=list)
    tcp_flags: list = field(default_factory=list)
    forward_tcp_flags: list = field(default_factory=list)
    backward_tcp_flags: list = field(default_factory=list)
    forward_header_lengths: list = field(default_factory=list)
    backward_header_lengths: list = field(default_factory=list)
    forward_window_sizes: list = field(default_factory=list)
    backward_window_sizes: list = field(default_factory=list)

    @property
    def duration_seconds(self):
        return self.last_seen - self.first_seen


class FlowAssembler:
    def __init__(self):
        self.flows = {}
        self.completed_flows = []
        self.lifecycle_timeout_seconds = 120.0

    def add_packet(self, packet):
        from scapy.layers.inet import IP, TCP

        if IP not in packet or TCP not in packet:
            raise ValueError("Only IPv4 TCP packets are supported.")

        timestamp = float(packet.time)
        if not isfinite(timestamp):
            raise ValueError("Invalid packet timestamp.")

        source = (packet[IP].src, int(packet[TCP].sport))
        destination = (packet[IP].dst, int(packet[TCP].dport))

        key = (6, tuple(sorted((source, destination))))

        # CICFlowMeter reference: TCP payload length excludes headers.
        # This does not establish full 78-feature compatibility.
        packet_length = len(bytes(packet[TCP].payload))
        tcp_flags = int(packet[TCP].flags)
        tcp_header_length = len(bytes(packet[TCP])) - packet_length
        tcp_window = int(packet[TCP].window)

        existing = self.flows.get(key)

        if existing is not None:
            if timestamp < existing.last_seen:
                raise ValueError("Out-of-order packet timestamp.")

            inactive = (
                timestamp - existing.last_seen
                > self.lifecycle_timeout_seconds
            )

            # SYN without ACK indicates a new connection attempt.
            new_connection = bool(tcp_flags & 0x02) and not bool(
                tcp_flags & 0x10
            )

            # Close after RST or FIN observed in both directions.
            fwd_fin = any(flag & 0x01 for flag in existing.forward_tcp_flags)
            bwd_fin = any(flag & 0x01 for flag in existing.backward_tcp_flags)
            reset_seen = any(flag & 0x04 for flag in existing.tcp_flags)
            closed = reset_seen or (fwd_fin and bwd_fin)

            if inactive or new_connection or closed:
                self.completed_flows.append(existing)
                del self.flows[key]

        if key not in self.flows:
            self.flows[key] = Flow(
                origin=source,
                destination=destination,
                first_seen=timestamp,
                last_seen=timestamp,
            )

        flow = self.flows[key]

        if timestamp < flow.last_seen:
            raise ValueError("Out-of-order packet timestamp.")

        flow.last_seen = timestamp
        flow.packet_timestamps.append(timestamp)
        flow.ordered_payload_lengths.append(packet_length)
        flow.ordered_directions.append(
            source == flow.origin and destination == flow.destination
        )
        flow.tcp_flags.append(tcp_flags)

        if source == flow.origin and destination == flow.destination:
            flow.forward_packets += 1
            flow.forward_lengths.append(packet_length)
            flow.forward_timestamps.append(timestamp)
            flow.forward_tcp_flags.append(tcp_flags)
            flow.forward_header_lengths.append(tcp_header_length)
            flow.forward_window_sizes.append(tcp_window)
        else:
            flow.backward_packets += 1
            flow.backward_lengths.append(packet_length)
            flow.backward_timestamps.append(timestamp)
            flow.backward_tcp_flags.append(tcp_flags)
            flow.backward_header_lengths.append(tcp_header_length)
            flow.backward_window_sizes.append(tcp_window)

        return flow
