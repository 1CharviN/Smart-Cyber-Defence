from collections import defaultdict
from datetime import datetime
from statistics import mean, pstdev

from flow_schema import FlowRecord


class FlowAggregator:
    """
    Aggregates packets into bidirectional network flows.

    The first observed direction is treated as the forward direction.
    Reverse packets are treated as backward traffic.
    """

    def __init__(self):
        self.flows = defaultdict(self._create_flow)

    @staticmethod
    def _create_flow():
        return {
            "first_seen": None,
            "last_seen": None,

            "source_ip": None,
            "destination_ip": None,
            "source_port": None,
            "destination_port": None,
            "protocol": None,

            "forward_key": None,

            "total_fwd_packets": 0,
            "total_backward_packets": 0,

            "total_fwd_bytes": 0,
            "total_backward_bytes": 0,

            "packet_lengths": [],

            "syn_flag_count": 0,
            "rst_flag_count": 0,
            "ack_flag_count": 0,
        }

    @staticmethod
    def _make_flow_key(features):
        """
        Create a bidirectional flow key.

        The two endpoints are stored without direction so that
        forward and backward packets belong to the same flow.
        """

        endpoint_1 = (
            features["source_ip"],
            features["source_port"],
        )

        endpoint_2 = (
            features["destination_ip"],
            features["destination_port"],
        )

        return (
            features["protocol"],
            frozenset((endpoint_1, endpoint_2)),
        )

    def add_packet(self, features):
        flow_key = self._make_flow_key(features)

        flow = self.flows[flow_key]

        timestamp = datetime.fromisoformat(
            features["timestamp"]
        )

        # First packet establishes the flow's forward direction.
        if flow["first_seen"] is None:

            flow["first_seen"] = timestamp

            flow["source_ip"] = features["source_ip"]
            flow["destination_ip"] = features["destination_ip"]

            flow["source_port"] = features["source_port"]
            flow["destination_port"] = features["destination_port"]

            flow["protocol"] = features["protocol"]

            flow["forward_key"] = (
                features["source_ip"],
                features["destination_ip"],
                features["source_port"],
                features["destination_port"],
            )

        flow["last_seen"] = timestamp

        current_key = (
            features["source_ip"],
            features["destination_ip"],
            features["source_port"],
            features["destination_port"],
        )

        is_forward = (
            current_key == flow["forward_key"]
        )

        packet_size = features["packet_size"]

        flow["packet_lengths"].append(
            packet_size
        )

        if is_forward:

            flow["total_fwd_packets"] += 1
            flow["total_fwd_bytes"] += packet_size

        else:

            flow["total_backward_packets"] += 1
            flow["total_backward_bytes"] += packet_size

        # TCP flag counting
        tcp_flags = features.get("tcp_flags")

        if tcp_flags:

            if "S" in tcp_flags:
                flow["syn_flag_count"] += 1

            if "R" in tcp_flags:
                flow["rst_flag_count"] += 1

            if "A" in tcp_flags:
                flow["ack_flag_count"] += 1

    def get_flows(self):

        results = []

        for flow in self.flows.values():

            if flow["first_seen"] is None:
                continue

            duration = (
                flow["last_seen"]
                - flow["first_seen"]
            ).total_seconds()

            packet_count = (
                flow["total_fwd_packets"]
                + flow["total_backward_packets"]
            )

            total_bytes = (
                flow["total_fwd_bytes"]
                + flow["total_backward_bytes"]
            )

            if duration > 0:

                flow_bytes_per_sec = (
                    total_bytes / duration
                )

                flow_packets_per_sec = (
                    packet_count / duration
                )

                fwd_packets_per_sec = (
                    flow["total_fwd_packets"]
                    / duration
                )

                bwd_packets_per_sec = (
                    flow["total_backward_packets"]
                    / duration
                )

            else:

                flow_bytes_per_sec = 0.0
                flow_packets_per_sec = 0.0
                fwd_packets_per_sec = 0.0
                bwd_packets_per_sec = 0.0

            packet_lengths = flow[
                "packet_lengths"
            ]

            if packet_lengths:

                packet_length_mean = mean(
                    packet_lengths
                )

                packet_length_std = pstdev(
                    packet_lengths
                )

            else:

                packet_length_mean = 0.0
                packet_length_std = 0.0

            average_packet_size = (
                total_bytes / packet_count
                if packet_count > 0
                else 0.0
            )

            record = FlowRecord(

                source_ip=flow["source_ip"],

                destination_ip=flow[
                    "destination_ip"
                ],

                source_port=flow[
                    "source_port"
                ],

                destination_port=flow[
                    "destination_port"
                ],

                protocol=flow["protocol"],

                flow_duration_sec=round(
                    duration,
                    6,
                ),

                total_fwd_packets=(
                    flow[
                        "total_fwd_packets"
                    ]
                ),

                total_backward_packets=(
                    flow[
                        "total_backward_packets"
                    ]
                ),

                total_fwd_bytes=(
                    flow[
                        "total_fwd_bytes"
                    ]
                ),

                total_backward_bytes=(
                    flow[
                        "total_backward_bytes"
                    ]
                ),

                flow_bytes_per_sec=round(
                    flow_bytes_per_sec,
                    6,
                ),

                flow_packets_per_sec=round(
                    flow_packets_per_sec,
                    6,
                ),

                fwd_packets_per_sec=round(
                    fwd_packets_per_sec,
                    6,
                ),

                bwd_packets_per_sec=round(
                    bwd_packets_per_sec,
                    6,
                ),

                packet_length_mean=round(
                    packet_length_mean,
                    6,
                ),

                packet_length_std=round(
                    packet_length_std,
                    6,
                ),

                syn_flag_count=flow[
                    "syn_flag_count"
                ],

                rst_flag_count=flow[
                    "rst_flag_count"
                ],

                ack_flag_count=flow[
                    "ack_flag_count"
                ],

                average_packet_size=round(
                    average_packet_size,
                    6,
                ),
            )

            results.append(record)

        return results