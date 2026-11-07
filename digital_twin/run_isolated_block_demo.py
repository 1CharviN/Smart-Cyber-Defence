import time
from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.topo import Topo

CLIENT = "10.0.0.1"
SERVER = "10.0.0.2"
ATTACKER = "10.0.0.3"
PORT = 8080

RULE = (
    f"iptables -I INPUT 1 -s {ATTACKER} "
    f"-p tcp --dport {PORT} -j DROP"
)
REMOVE_RULE = (
    f"iptables -D INPUT -s {ATTACKER} "
    f"-p tcp --dport {PORT} -j DROP"
)

class LabTopology(Topo):
    def build(self):
        client = self.addHost("client", ip=f"{CLIENT}/24")
        server = self.addHost("server", ip=f"{SERVER}/24")
        attacker = self.addHost("attacker", ip=f"{ATTACKER}/24")
        switch = self.addSwitch("s1", failMode="standalone")
        for host in (client, server, attacker):
            self.addLink(host, switch)

def http(host):
    return host.cmd(
        f"curl --connect-timeout 2 --max-time 3 -sS "
        f"-o /dev/null -w '%{{http_code}}' "
        f"http://{SERVER}:{PORT}/"
    ).strip()

net = Mininet(topo=LabTopology(), controller=None, switch=OVSSwitch)
rule_added = False
server = None
server_pid = ""

try:
    print("Starting isolated three-host Mininet lab...")
    net.start()
    client = net.get("client")
    attacker = net.get("attacker")
    server = net.get("server")

    server_pid = server.cmd(
        f"python3 -m http.server {PORT} --bind {SERVER} "
        f">/tmp/isolated_block_http.log 2>&1 & echo $!"
    ).strip().splitlines()[-1]
    time.sleep(1)

    print("\n[1] Baseline: both hosts should reach the server")
    client_before = http(client)
    attacker_before = http(attacker)
    print(f"Legitimate client HTTP status: {client_before}")
    print(f"Attacker test host HTTP status: {attacker_before}")

    if client_before != "200" or attacker_before != "200":
        raise RuntimeError("Baseline failed; refusing to apply a rule.")

    print("\n[2] Apply temporary DROP rule inside virtual server")
    result = server.cmd(f"{RULE} && echo RULE_APPLIED || echo RULE_FAILED")
    print(result.strip())
    if "RULE_APPLIED" not in result:
        raise RuntimeError("Could not apply the lab-only rule.")
    rule_added = True

    time.sleep(0.5)
    print("\n[3] Verify traffic while the rule is active")
    attacker_blocked = http(attacker)
    client_still_works = http(client)
    print(f"Attacker test host HTTP result: {attacker_blocked or 'BLOCKED / NO HTTP RESPONSE'}")
    print(f"Legitimate client HTTP status: {client_still_works}")

    if attacker_blocked == "200":
        print("RESULT: BLOCK NOT VERIFIED")
    elif client_still_works == "200":
        print("RESULT: LAB BLOCK VERIFIED; LEGITIMATE CLIENT STILL WORKS")
    else:
        print("RESULT: INCONCLUSIVE — legitimate client also failed")

finally:
    if rule_added and server is not None:
        print("\n[4] Remove temporary lab rule")
        print(server.cmd(f"{REMOVE_RULE} && echo RULE_REMOVED || echo RULE_REMOVE_FAILED").strip())
        time.sleep(0.5)
        if http(net.get("attacker")) == "200":
            print("Rollback verified: attacker test host can reach server again.")
        else:
            print("WARNING: restored connectivity not verified; inspect lab before continuing.")

    if server is not None and server_pid:
        server.cmd(f"kill {server_pid} 2>/dev/null || true")
    net.stop()
    print("Mininet lab stopped.")
