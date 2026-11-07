import json
import re
import sys
import urllib.error
import urllib.request

from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.topo import Topo


API_URL = "http://127.0.0.1:8001/api/twin/validations"


class StandaloneSwitch(OVSSwitch):
    """Use a standalone virtual switch without a controller."""

    def __init__(self, name, **params):
        params["failMode"] = "standalone"
        super().__init__(name, **params)


class ConnectivityTopology(Topo):
    def build(self):
        client = self.addHost("client", ip="10.0.0.1/24")
        server = self.addHost("server", ip="10.0.0.2/24")
        switch = self.addSwitch("s1")

        self.addLink(client, switch)
        self.addLink(server, switch)


def submit_validation(payload):
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        API_URL,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urllib.request.urlopen(request, timeout=10) as response:
        return response.status, response.read().decode("utf-8")


def main():
    net = Mininet(
        topo=ConnectivityTopology(),
        controller=None,
        switch=StandaloneSwitch,
        autoSetMacs=True,
    )

    simulation_ran = False
    ping_output = ""
    ping_exit_code = None
    received = 0

    try:
        print("Starting isolated Mininet topology...")
        net.start()

        client = net.get("client")

        print("Testing client -> server connectivity...")
        ping_output = client.cmd(
            "ping -c 2 -W 1 10.0.0.2; echo PING_EXIT:$?"
        )

        match = re.search(r"PING_EXIT:(\d+)", ping_output)
        if match is None:
            raise RuntimeError(
                "Could not determine the ping exit code.\n" + ping_output
            )

        ping_exit_code = int(match.group(1))
        received_match = re.search(r"\d+\s+packets transmitted,\s+"
                                   r"(\d+)\s+(?:packets )?received",
                                   ping_output)
        if received_match:
            received = int(received_match.group(1))

        simulation_ran = True
        passed = ping_exit_code == 0

        print("\n===== CONNECTIVITY RESULT =====")
        print("Result:", "PASS" if passed else "FAIL")
        print("Ping exit code:", ping_exit_code)
        print("Packets received:", received)
        print(ping_output)

    finally:
        print("Stopping and cleaning up Mininet...")
        net.stop()

    if not simulation_ran:
        print("No validation submitted: the connectivity test did not complete.")
        return 1

    passed = ping_exit_code == 0

    payload = {
        "scenario": "Mininet client-to-server connectivity test",
        "source_ip": "10.0.0.1",
        "before": {
            "connectivity": "not_tested",
        },
        "after": {
            "connectivity": "reachable" if passed else "unreachable",
            "ping_exit_code": ping_exit_code,
            "packets_transmitted": 2,
            "packets_received": received,
        },
        "simulation_executed": True,
        "notes": (
            f"Actual Mininet connectivity test: "
            f"{'PASS' if passed else 'FAIL'}. "
            "Firewall execution was not requested or performed."
        ),
    }

    try:
        status, response_body = submit_validation(payload)
        print("\n===== VALIDATION API =====")
        print("HTTP status:", status)
        print(response_body)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        print("\nThe Mininet test ran, but the result could not be")
        print("submitted to the API. Check that the backend is running.")
        print("Error:", exc)
        return 2

    return 0 if passed else 1


if __name__ == "__main__":
    if sys.platform != "linux":
        raise SystemExit("This Mininet test requires Linux.")
    raise SystemExit(main())
