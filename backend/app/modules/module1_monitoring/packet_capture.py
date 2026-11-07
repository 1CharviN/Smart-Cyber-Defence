from scapy.all import sniff

from feature_extractor import extract_packet_features
from flow_aggregator import FlowAggregator
from flow_buffer import FlowBuffer
from monitoring_service import monitoring_service


flow_aggregator = FlowAggregator()
flow_buffer = FlowBuffer()


def packet_handler(packet):
    features = extract_packet_features(packet)

    # Ignore packets that are not usable for our
    # TCP/UDP network-flow ML pipeline.
    if (
        features["source_ip"] is None
        or features["destination_ip"] is None
        or features["protocol"] not in {"TCP", "UDP"}
    ):
        return

    flow_aggregator.add_packet(features)

    print("\n--- Packet Captured ---")
    print(
        f"{features['source_ip']} "
        f"-> "
        f"{features['destination_ip']} "
        f"| "
        f"{features['protocol']} "
        f"| "
        f"{features['packet_size']} bytes"
    )


if __name__ == "__main__":

    print("Starting packet capture...")
    print("Capturing 30 packets...")

    sniff(
        prn=packet_handler,
        store=False,
        count=30,
    )

    flows = flow_aggregator.get_flows()

    for flow in flows:
        flow_buffer.add_flow(flow)
        monitoring_service.add_flow(flow)

    print(f"Flows exported to dashboard: {len(flows)}")

    print("\n")
    print("=" * 70)
    print("D1 FLOW BUFFER")
    print("=" * 70)

    print(
        f"Flows stored: {flow_buffer.size()}"
    )

    print("\n")
    print("=" * 70)
    print("ML-COMPATIBLE FLOW RECORDS")
    print("=" * 70)

    for index, flow in enumerate(
        flow_buffer.get_all(),
        start=1,
    ):

        print(f"\nFlow {index}")

        print(
            f"Source IP             : "
            f"{flow.source_ip}"
        )

        print(
            f"Destination IP        : "
            f"{flow.destination_ip}"
        )

        print(
            f"Destination Port      : "
            f"{flow.destination_port}"
        )

        print(
            f"Protocol              : "
            f"{flow.protocol}"
        )

        print(
            f"Flow Duration         : "
            f"{flow.flow_duration_sec}"
        )

        print(
            f"Total Fwd Packets     : "
            f"{flow.total_fwd_packets}"
        )

        print(
            f"Total Backward Packets: "
            f"{flow.total_backward_packets}"
        )

        print(
            f"Total Fwd Bytes       : "
            f"{flow.total_fwd_bytes}"
        )

        print(
            f"Total Backward Bytes  : "
            f"{flow.total_backward_bytes}"
        )

        print(
            f"Flow Bytes/sec        : "
            f"{flow.flow_bytes_per_sec}"
        )

        print(
            f"Flow Packets/sec      : "
            f"{flow.flow_packets_per_sec}"
        )

        print(
            f"Fwd Packets/sec       : "
            f"{flow.fwd_packets_per_sec}"
        )

        print(
            f"Bwd Packets/sec       : "
            f"{flow.bwd_packets_per_sec}"
        )

        print(
            f"Packet Length Mean    : "
            f"{flow.packet_length_mean}"
        )

        print(
            f"Packet Length Std     : "
            f"{flow.packet_length_std}"
        )

        print(
            f"SYN Flag Count        : "
            f"{flow.syn_flag_count}"
        )

        print(
            f"RST Flag Count        : "
            f"{flow.rst_flag_count}"
        )

        print(
            f"ACK Flag Count        : "
            f"{flow.ack_flag_count}"
        )

        print(
            f"Average Packet Size   : "
            f"{flow.average_packet_size}"
        )

    print("\n")
    print(
        "Packet capture and "
        "flow processing finished."
    )