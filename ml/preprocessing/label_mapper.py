def normalize_label(label: str) -> str:
    label = str(label).strip()

    if label == "BENIGN":
        return "NORMAL"

    if label == "DDoS":
        return "DDOS"

    if label == "PortScan":
        return "PORT_SCAN"

    if label in {
        "FTP-Patator",
        "SSH-Patator",
        "Web Attack � Brute Force",
    }:
        return "BRUTE_FORCE"

    return "IGNORE"