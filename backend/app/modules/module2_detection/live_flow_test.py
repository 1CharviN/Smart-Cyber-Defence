import sys
from pathlib import Path


# =========================================================
# Project paths
# =========================================================
# =========================================================
# Module 1 path
# =========================================================

MODULE1_PATH = (
    Path(__file__).resolve().parent.parent
    / "module1_monitoring"
)

if str(MODULE1_PATH) not in sys.path:
    sys.path.insert(
        0,
        str(MODULE1_PATH),
    )


# =========================================================
# Make Module 1 importable
# =========================================================

if str(MODULE1_PATH) not in sys.path:
    sys.path.insert(
        0,
        str(MODULE1_PATH),
    )


# =========================================================
# Module 1 imports
# =========================================================

from flow_aggregator import FlowAggregator
from flow_buffer import FlowBuffer
from feature_extractor import extract_packet_features


# =========================================================
# Module 2 imports
# =========================================================

from detection_engine import DetectionEngine
from detection_logger import DetectionLogger


def main():

    print("=" * 70)
    print("MODULE 1 -> MODULE 2 INTEGRATION TEST")
    print("=" * 70)

    # -----------------------------------------------------
    # Create fresh Module 1 components
    # -----------------------------------------------------

    flow_aggregator = FlowAggregator()
    flow_buffer = FlowBuffer()

    # -----------------------------------------------------
    # Packet handler
    # -----------------------------------------------------

    def packet_handler(packet):

        features = extract_packet_features(
            packet
        )

        # Ignore packets that aren't usable
        # for our TCP/UDP flow-based ML pipeline.
        if (
            features["source_ip"] is None
            or features["destination_ip"] is None
            or features["protocol"]
            not in {"TCP", "UDP"}
        ):
            return

        flow_aggregator.add_packet(
            features
        )

        print(
            f"{features['source_ip']} "
            f"-> "
            f"{features['destination_ip']} "
            f"| "
            f"{features['protocol']} "
            f"| "
            f"{features['packet_size']} bytes"
        )

    # -----------------------------------------------------
    # Start capture
    # -----------------------------------------------------

    print("\nStarting live packet capture...")
    print("Capturing 30 packets...")

    from scapy.all import sniff

    sniff(
        prn=packet_handler,
        store=False,
        count=30,
    )

    # -----------------------------------------------------
    # Build flows
    # -----------------------------------------------------

    flows = (
        flow_aggregator.get_flows()
    )

    for flow in flows:

        flow_buffer.add_flow(
            flow
        )

    print("\n" + "=" * 70)
    print("MODULE 1 COMPLETE")
    print("=" * 70)

    print(
        f"\nFlows available in D1: "
        f"{flow_buffer.size()}"
    )

    if flow_buffer.size() == 0:

        print(
            "\nNo usable flows were captured."
        )

        return

    # -----------------------------------------------------
    # Load Module 2
    # -----------------------------------------------------

    print("\nLoading Module 2...")

    engine = DetectionEngine(
        confidence_threshold=0.80
    )

    logger = DetectionLogger()

    print(
        "Module 2 loaded successfully."
    )

    # -----------------------------------------------------
    # Analyze flows
    # -----------------------------------------------------

    print("\n" + "=" * 70)
    print("DETECTION RESULTS")
    print("=" * 70)

    for index, flow in enumerate(
        flow_buffer.get_all(),
        start=1,
    ):

        result = engine.analyze(
            flow
        )

        event = logger.log(
            result
        )

        print(
            f"\nFlow {index}"
        )

        print(
            f"Source IP      : "
            f"{result.source_ip}"
        )

        print(
            f"Destination IP : "
            f"{result.destination_ip}"
        )

        print(
            f"Prediction     : "
            f"{result.attack_type}"
        )

        print(
            f"Confidence     : "
            f"{result.confidence * 100:.2f}%"
        )

        print(
            f"Severity       : "
            f"{result.severity}"
        )

        print(
            f"Action Required: "
            f"{result.action_required}"
        )

    print("\n" + "=" * 70)
    print(
        "MODULE 1 -> MODULE 2 "
        "TEST COMPLETE"
    )
    print("=" * 70)


if __name__ == "__main__":
    main()