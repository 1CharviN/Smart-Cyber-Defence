import json
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PCAP = Path("/tmp/cyber_twin_ai_test.pcap")
API = "http://127.0.0.1:8001"
MONITORING = ROOT / "backend/app/modules/module1_monitoring"
VENV_PYTHON = ROOT / ".venv-ml-compat311/bin/python"


def post_json(url, payload):
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        return response.status, response.read().decode("utf-8")


def process_pcap():
    import sys
    from datetime import datetime, timezone
    from scapy.all import IP, TCP, rdpcap

    sys.path.insert(0, str(MONITORING))
    from feature_extractor import extract_packet_features
    from flow_aggregator import FlowAggregator

    if not PCAP.is_file() or PCAP.stat().st_size == 0:
        raise SystemExit("Packet capture is missing or empty.")

    packets = rdpcap(str(PCAP))
    aggregator = FlowAggregator()
    captured = 0

    for packet in packets:
        if IP not in packet or TCP not in packet:
            continue
        if packet[TCP].sport != 8080 and packet[TCP].dport != 8080:
            continue

        features = extract_packet_features(packet)
        features["timestamp"] = datetime.fromtimestamp(
            float(packet.time), timezone.utc
        ).isoformat()

        aggregator.add_packet(features)
        captured += 1

    flows = aggregator.get_flows()
    print(f"Captured TCP packets: {captured}")
    print(f"Aggregated flows: {len(flows)}")

    if not flows:
        raise SystemExit(
            "No eligible TCP flows found. Check the capture file and tcpdump log."
        )

    numeric_fields = [
        "destination_port",
        "flow_duration_sec",
        "total_fwd_packets",
        "total_backward_packets",
        "total_fwd_bytes",
        "total_backward_bytes",
        "flow_bytes_per_sec",
        "flow_packets_per_sec",
        "fwd_packets_per_sec",
        "bwd_packets_per_sec",
        "packet_length_mean",
        "packet_length_std",
        "syn_flag_count",
        "rst_flag_count",
        "ack_flag_count",
        "average_packet_size",
    ]

    successes = 0
    for index, flow in enumerate(flows[:5], start=1):
        payload = {
            "source_ip": flow.source_ip,
            "destination_ip": flow.destination_ip,
        }

        for name in numeric_fields:
            payload[name] = getattr(flow, name)

        try:
            status, body = post_json(
                API + "/api/detection/analyze", payload
            )
            result = json.loads(body)
            print(f"\nAI inference {index}: HTTP {status}")
            print(json.dumps(result, indent=2))
            successes += 1
        except (urllib.error.HTTPError, urllib.error.URLError) as exc:
            detail = (
                exc.read().decode("utf-8", errors="replace")
                if isinstance(exc, urllib.error.HTTPError)
                else str(exc)
            )
            print(f"AI inference {index} failed: {detail}")

    print(f"\nSuccessful AI inferences: {successes}/{min(len(flows), 5)}")
    if successes == 0:
        raise SystemExit("No captured flow was successfully analyzed.")


def run_mininet():
    from mininet.net import Mininet
    from mininet.node import OVSSwitch
    from mininet.topo import Topo

    class StandaloneSwitch(OVSSwitch):
        def __init__(self, name, **params):
            params["failMode"] = "standalone"
            super().__init__(name, **params)

    class HttpTopology(Topo):
        def build(self):
            client = self.addHost("client", ip="10.0.0.1/24")
            server = self.addHost("server", ip="10.0.0.2/24")
            switch = self.addSwitch("s1")
            self.addLink(client, switch)
            self.addLink(server, switch)

    with urllib.request.urlopen(API + "/api/health", timeout=5) as response:
        if response.status != 200:
            raise SystemExit("Backend health check failed.")

    net = Mininet(
        topo=HttpTopology(),
        controller=None,
        switch=StandaloneSwitch,
        autoSetMacs=True,
    )
    capture_pid = ""

    try:
        print("Starting isolated Mininet HTTP traffic test...")
        net.start()
        client = net.get("client")
        server = net.get("server")

        interface = client.defaultIntf().name
        client.cmd(f"rm -f {PCAP}")
        client.cmd("command -v tcpdump >/dev/null 2>&1")
        if client.cmd("echo $?").strip() != "0":
            raise RuntimeError("tcpdump is not available to the Mininet client.")

        capture_pid = client.cmd(
            f"tcpdump -i {interface} -U -w {PCAP} "
            "'tcp port 8080' >/tmp/cyber_twin_tcpdump.log 2>&1 & echo $!"
        ).strip().splitlines()[-1]

        time.sleep(1)
        server.cmd(
            "python3 -m http.server 8080 --bind 10.0.0.2 "
            ">/tmp/cyber_twin_ai_http.log 2>&1 &"
        )

        successful = 0
        for attempt in range(10):
            time.sleep(0.2)
            result = client.cmd(
                "curl --connect-timeout 2 --max-time 3 -sS "
                "-o /dev/null -w '%{http_code}' "
                "http://10.0.0.2:8080/"
            ).strip()
            if result == "200":
                successful += 1
            print(f"HTTP request {attempt + 1}/10: {result or 'FAILED'}")

        if successful == 0:
            raise RuntimeError("The simulated HTTP service was unreachable.")

        print(f"HTTP requests successful: {successful}/10")

    finally:
        if capture_pid:
            client.cmd(f"kill -INT {capture_pid} 2>/dev/null || true")
            time.sleep(1)
        net.stop()
        print("Mininet stopped; firewall rules were not changed.")

    print("\nProcessing capture with project virtual environment...")
    subprocess.run(
        [str(VENV_PYTHON), str(Path(__file__).resolve()), "--process-pcap"],
        check=True,
        cwd=str(ROOT),
    )


if __name__ == "__main__":
    if "--process-pcap" in sys.argv:
        process_pcap()
    else:
        run_mininet()
