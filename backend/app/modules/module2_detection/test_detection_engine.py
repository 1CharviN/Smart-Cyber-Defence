from pathlib import Path
from detection_logger import DetectionLogger
import sys


# Allow imports from Module 1.
MODULE1_PATH = str(
    Path(__file__).resolve().parent.parent
    / "module1_monitoring"
)

if MODULE1_PATH not in sys.path:
    sys.path.insert(
        0,
        MODULE1_PATH,
    )


from flow_schema import FlowRecord
from detection_engine import DetectionEngine


def main():

    print("=" * 70)
    print("MODULE 2 DETECTION ENGINE TEST")
    print("=" * 70)

    # Example flow based on the structure
    # produced by Module 1.
    flow = FlowRecord(
        source_ip="192.168.1.2",
        destination_ip="8.8.8.8",

        source_port=55000,
        destination_port=443,

        protocol="TCP",

        flow_duration_sec=1.0,

        total_fwd_packets=10,
        total_backward_packets=8,

        total_fwd_bytes=5000,
        total_backward_bytes=3000,

        flow_bytes_per_sec=8000,
        flow_packets_per_sec=18,

        fwd_packets_per_sec=10,
        bwd_packets_per_sec=8,

        packet_length_mean=444.44,
        packet_length_std=200.0,

        syn_flag_count=1,
        rst_flag_count=0,
        ack_flag_count=16,

        average_packet_size=444.44,
    )

    print("\nLoading detection engine...")

    engine = DetectionEngine(
        confidence_threshold=0.80
    )

    print(
        "Detection engine loaded."
    )

    print("\nAnalyzing test flow...")

    result = engine.analyze(
        flow
    )

    logger = DetectionLogger()

    event = logger.log(
    result
    )

    print("\nD2 detection event saved:")
    print(event)

    print("\n" + "-" * 70)
    print("DETECTION RESULT")
    print("-" * 70)

    print(
        f"Source IP       : "
        f"{result.source_ip}"
    )

    print(
        f"Destination IP  : "
        f"{result.destination_ip}"
    )

    print(
        f"Attack Type     : "
        f"{result.attack_type}"
    )

    print(
        f"Confidence      : "
        f"{result.confidence * 100:.2f}%"
    )

    print(
        f"Severity        : "
        f"{result.severity}"
    )

    print(
        f"Action Required : "
        f"{result.action_required}"
    )

    print("\n" + "=" * 70)
    print("MODULE 2 TEST COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()