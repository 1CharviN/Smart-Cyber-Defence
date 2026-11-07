import json
import re
import sys
import time
import urllib.error
import urllib.request

from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.topo import Topo


API_URL = "http://127.0.0.1:8001/api/twin/validations"
SERVER_IP = "10.0.0.2"
SERVER_PORT = 8080
REQUEST_COUNT = 10


class StandaloneSwitch(OVSSwitch):
    def __init__(self, name, **params):
        params["failMode"] = "standalone"
        super().__init__(name, **params)


class HttpTopology(Topo):
    def build(self):
        client = self.addHost("client", ip="10.0.0.1/24")
        server = self.addHost("server", ip=f"{SERVER_IP}/24")
        switch = self.addSwitch("s1")
        self.addLink(client, switch)
        self.addLink(server, switch)


def http_request(client):
    command = (
        f"curl --connect-timeout 2 --max-time 3 -sS "
        f"-o /dev/null -w '%{{http_code}} %{{time_total}}' "
        f"http://{SERVER_IP}:{SERVER_PORT}/"
    )
    output = client.cmd(command).strip()
    match = re.search(r"(\d{3})\s+([\d.]+)$", output)
    if not match:
        return {"success": False, "http_status": None,
                "response_seconds": None, "output": output}
    status = int(match.group(1))
    duration = float(match.group(2))
    return {
        "success": 200 <= status < 400,
        "http_status": status,
        "response_seconds": duration,
    }


def submit_validation(payload):
    request = urllib.request.Request(
        API_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return response.status, response.read().decode("utf-8")


def main():
    net = Mininet(
        topo=HttpTopology(),
        controller=None,
        switch=StandaloneSwitch,
        autoSetMacs=True,
    )

    completed = False
    before = {}
    after = {}
    notes = ""

    try:
        print("Starting isolated Mininet HTTP test...")
        net.start()
        client = net.get("client")
        server = net.get("server")

        server.cmd(
            f"python3 -m http.server {SERVER_PORT} "
            f"--bind {SERVER_IP} >/tmp/twin_http_server.log 2>&1 &"
        )

        # Wait briefly for the server to become ready.
        initial = None
        for _ in range(10):
            time.sleep(0.3)
            initial = http_request(client)
            if initial["success"]:
                break

        if not initial or not initial["success"]:
            raise RuntimeError(
                "The virtual HTTP server did not become available. "
                "Check /tmp/twin_http_server.log."
            )

        print("Baseline HTTP request: PASS")
        before = {
            "http_available": True,
            "http_status": initial["http_status"],
            "response_seconds": initial["response_seconds"],
        }

        successes = 0
        durations = []
        print(f"Sending {REQUEST_COUNT} sequential HTTP requests...")
        for index in range(REQUEST_COUNT):
            result = http_request(client)
            if result["success"]:
                successes += 1
            if result["response_seconds"] is not None:
                durations.append(result["response_seconds"])
            print(
                f"Request {index + 1}/{REQUEST_COUNT}: "
                f"{'PASS' if result['success'] else 'FAIL'}"
            )

        final = http_request(client)
        completed = True
        after = {
            "http_available": final["success"],
            "http_status": final["http_status"],
            "response_seconds": final["response_seconds"],
            "bounded_requests_sent": REQUEST_COUNT,
            "successful_requests": successes,
            "failed_requests": REQUEST_COUNT - successes,
            "mean_request_seconds": (
                sum(durations) / len(durations) if durations else None
            ),
        }
        notes = (
            "Bounded sequential HTTP availability test in an isolated "
            "Mininet topology. No external targets or firewall changes. "
            "This is not a DDoS simulation or proof of attack detection."
        )

        print("\n===== HTTP VALIDATION RESULT =====")
        print(json.dumps(
            {"before_metrics": before, "after_metrics": after},
            indent=2,
        ))

    finally:
        print("Stopping and cleaning up Mininet...")
        net.stop()

    if not completed:
        print("Test did not complete; no success record will be submitted.")
        return 1

    payload = {
        "scenario": "Mininet bounded HTTP availability test",
        "source_ip": "10.0.0.1",
        "before": before,
        "after": after,
        "simulation_executed": True,
        "notes": notes,
    }

    try:
        status, body = submit_validation(payload)
        print("\n===== VALIDATION API =====")
        print("HTTP status:", status)
        print(body)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        print("Test completed, but API submission failed:", exc)
        return 2

    return 0 if after["http_available"] else 1


if __name__ == "__main__":
    if sys.platform != "linux":
        raise SystemExit("This test requires Linux.")
    raise SystemExit(main())
