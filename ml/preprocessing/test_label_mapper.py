from label_mapper import normalize_label


test_labels = [
    "BENIGN",
    "DDoS",
    "PortScan",
    "FTP-Patator",
    "SSH-Patator",
    "Web Attack � Brute Force",
    "Web Attack � Sql Injection",
    "Web Attack � XSS",
    "DoS Hulk",
    "Bot",
    "Infiltration",
    "Heartbleed",
]


for label in test_labels:
    print(f"{label:35} -> {normalize_label(label)}")