from dataclasses import dataclass
from typing import Optional


@dataclass
class FlowRecord:
    # Information useful for logs/dashboard
    source_ip: Optional[str]
    destination_ip: Optional[str]
    source_port: Optional[int]
    destination_port: Optional[int]
    protocol: Optional[str]

    # ML-compatible features
    flow_duration_sec: float

    total_fwd_packets: int
    total_backward_packets: int

    total_fwd_bytes: int
    total_backward_bytes: int

    flow_bytes_per_sec: float
    flow_packets_per_sec: float

    fwd_packets_per_sec: float
    bwd_packets_per_sec: float

    packet_length_mean: float
    packet_length_std: float

    syn_flag_count: int
    rst_flag_count: int
    ack_flag_count: int

    average_packet_size: float