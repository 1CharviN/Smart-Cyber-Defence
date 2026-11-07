from datetime import datetime, timezone

from scapy.all import IP, IPv6, TCP, UDP


def extract_packet_features(packet):
    """
    Extract network-level information from a Scapy packet.

    Only IPv4/IPv6 traffic with TCP or UDP is intended
    for the ML flow pipeline.
    """

    features = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": None,
        "destination_ip": None,
        "source_port": None,
        "destination_port": None,
        "protocol": None,
        "packet_size": 0,
        "tcp_flags": None,
    }

    # ---------------------------------------------------------
    # IPv4
    # ---------------------------------------------------------
    if packet.haslayer(IP):

        ip_packet = packet[IP]

        features["source_ip"] = ip_packet.src
        features["destination_ip"] = ip_packet.dst

        # Use IP-layer length for ML flow statistics.
        features["packet_size"] = len(ip_packet)

    # ---------------------------------------------------------
    # IPv6
    # ---------------------------------------------------------
    elif packet.haslayer(IPv6):

        ipv6_packet = packet[IPv6]

        features["source_ip"] = ipv6_packet.src
        features["destination_ip"] = ipv6_packet.dst

        # Use IPv6-layer length.
        features["packet_size"] = len(ipv6_packet)

    # ---------------------------------------------------------
    # TCP
    # ---------------------------------------------------------
    if packet.haslayer(TCP):

        features["protocol"] = "TCP"
        features["source_port"] = packet[TCP].sport
        features["destination_port"] = packet[TCP].dport
        features["tcp_flags"] = str(packet[TCP].flags)

    # ---------------------------------------------------------
    # UDP
    # ---------------------------------------------------------
    elif packet.haslayer(UDP):

        features["protocol"] = "UDP"
        features["source_port"] = packet[UDP].sport
        features["destination_port"] = packet[UDP].dport

    return features