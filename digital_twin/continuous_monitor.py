import json
import os
import sys
import time
from pathlib import Path
from urllib.request import Request, urlopen

PROJECT = Path(__file__).resolve().parents[1]
MODULE = PROJECT / "backend/app/modules/module1_monitoring"

sys.path.insert(0, str(MODULE))
sys.path.insert(0, str(PROJECT))

from scapy.all import sniff
from feature_extractor import extract_packet_features
from flow_aggregator import FlowAggregator
from monitoring_service import monitoring_service

INTERFACE = os.environ.get("CAPTURE_INTERFACE", "enp0s1")
API = 'http://127.0.0.1:8001/api/detection/analyze'
PID_FILE = MODULE / "collector.pid"

FEATURES = [
    "destination_port", "flow_duration_sec",
    "total_fwd_packets", "total_backward_packets",
    "total_fwd_bytes", "total_backward_bytes",
    "flow_bytes_per_sec", "flow_packets_per_sec",
    "fwd_packets_per_sec", "bwd_packets_per_sec",
    "packet_length_mean", "packet_length_std",
    "syn_flag_count", "rst_flag_count",
    "ack_flag_count", "average_packet_size",
]

aggregator = FlowAggregator()
packet_count = 0


def packet_handler(packet):
    global packet_count
    try:
        features = extract_packet_features(packet)
        if (
            not features["source_ip"]
            or not features["destination_ip"]
            or features["protocol"] not in {"TCP", "UDP"}
        ):
            return
        aggregator.add_packet(features)
        packet_count += 1
    except Exception as exc:
        print(f"[CAPTURE WARNING] {exc}", flush=True)


def process_window():
    global aggregator

    flows = aggregator.get_flows()
    aggregator = FlowAggregator()

    for flow in flows:
        monitoring_service.add_flow(flow)
        record = {
            k: (v if not isinstance(v, float) else float(v))
            for k, v in vars(flow).items()
        }

        payload = {k: record[k] for k in FEATURES}
        payload["destination_port"] = int(payload["destination_port"] or 0)
        payload["source_ip"] = record.get("source_ip")
        payload["destination_ip"] = record.get("destination_ip")

        try:
            request = Request(
                API,
                data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(request, timeout=20) as response:
                result = json.loads(response.read().decode())

            defence = result.get("defence", {})
            print(
                "[AI]",
                result.get("attack_type"),
                "| source:", result.get("source_ip"),
                "| confidence:", result.get("confidence"),
                "| defence:", defence.get("action"),
                "| mode:", defence.get("mode"),
                "| executed:", defence.get("executed"),
                flush=True,
            )
        except Exception as exc:
            print(f"[AI WARNING] Flow saved, inference failed: {exc}", flush=True)

    if flows:
        print(f"[MONITOR] Exported {len(flows)} flows", flush=True)


def main():
    global packet_count

    if PID_FILE.exists():
        try:
            old_pid = int(PID_FILE.read_text().strip())
            os.kill(old_pid, 0)
            raise SystemExit(
                f"Collector PID {old_pid} may already be running. "
                "Check it before starting another."
            )
        except ProcessLookupError:
            PID_FILE.unlink(missing_ok=True)
        except ValueError:
            PID_FILE.unlink(missing_ok=True)

    PID_FILE.write_text(str(os.getpid()))
    print(f"[MONITOR] Interface: {INTERFACE}", flush=True)
    print("[MONITOR] Continuous capture started; Ctrl+C to stop.", flush=True)

    try:
        while True:
            before = packet_count
            sniff(
                iface=INTERFACE,
                prn=packet_handler,
                store=False,
                timeout=5,
            )
            process_window()
            print(
                f"[MONITOR] Last window packets: {packet_count - before}; "
                f"total captured: {packet_count}",
                flush=True,
            )
    except KeyboardInterrupt:
        print("\n[MONITOR] Stop requested.", flush=True)
        process_window()
    finally:
        PID_FILE.unlink(missing_ok=True)
        print("[MONITOR] Stopped.", flush=True)


if __name__ == "__main__":
    main()
