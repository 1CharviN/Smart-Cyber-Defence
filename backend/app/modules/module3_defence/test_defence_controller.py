from defence_controller import DefenceController


def print_result(title, result):

    print("\n")
    print("=" * 70)
    print(title)
    print("=" * 70)

    print(
        f"Source IP : "
        f"{result['source_ip']}"
    )

    print(
        f"Action    : "
        f"{result['action']}"
    )

    print(
        f"Approved  : "
        f"{result['approved']}"
    )

    print(
        f"Executed  : "
        f"{result['executed']}"
    )

    print(
        f"Mode      : "
        f"{result['mode']}"
    )

    print(
        f"Reason    : "
        f"{result['reason']}"
    )

    print("\nFirewall commands:")

    if result["commands"]:

        for command in result["commands"]:
            print(
                f"  {command}"
            )

    else:

        print(
            "  None"
        )


def main():

    print("=" * 70)
    print(
        "MODULE 3 DEFENCE CONTROLLER TEST"
    )
    print("=" * 70)

    controller = DefenceController(
        confidence_threshold=0.80,

        protected_ips={
            "192.168.1.2",
        },

        dry_run=True,
    )

    # ---------------------------------------------------------
    # TEST 1 — Known attack
    # ---------------------------------------------------------

    ddos_detection = {

        "source_ip": "10.0.0.50",

        "destination_ip": "10.0.0.10",

        "attack_type": "DDOS",

        "rf_confidence": 0.99,

        "anomaly": True,

        "anomaly_score": -0.08,

        "severity": "HIGH",

        "threat_signal": True,
    }

    result = controller.process_detection(
        ddos_detection
    )

    print_result(
        "TEST 1 — DDOS → BLOCK",
        result,
    )

    # ---------------------------------------------------------
    # TEST 2 — Unknown anomaly
    # ---------------------------------------------------------

    anomaly_detection = {

        "source_ip": "10.0.0.70",

        "destination_ip": "10.0.0.10",

        "attack_type": "UNKNOWN_ANOMALY",

        "rf_confidence": 0.50,

        "anomaly": True,

        "anomaly_score": -0.12,

        "severity": "MEDIUM",

        "threat_signal": True,
    }

    result = controller.process_detection(
        anomaly_detection
    )

    print_result(
        "TEST 2 — UNKNOWN ANOMALY → RATE LIMIT",
        result,
    )

    # ---------------------------------------------------------
    # TEST 3 — Protected IP
    # ---------------------------------------------------------

    protected_detection = {

        "source_ip": "192.168.1.2",

        "destination_ip": "10.0.0.10",

        "attack_type": "DDOS",

        "rf_confidence": 0.99,

        "anomaly": True,

        "anomaly_score": -0.08,

        "severity": "HIGH",

        "threat_signal": True,
    }

    result = controller.process_detection(
        protected_detection
    )

    print_result(
        "TEST 3 — PROTECTED IP → NO ACTION",
        result,
    )

    # ---------------------------------------------------------
    # TEST 4 — Normal traffic
    # ---------------------------------------------------------

    normal_detection = {

        "source_ip": "10.0.0.60",

        "destination_ip": "10.0.0.10",

        "attack_type": "NORMAL",

        "rf_confidence": 0.99,

        "anomaly": False,

        "anomaly_score": 0.16,

        "severity": "LOW",

        "threat_signal": False,
    }

    result = controller.process_detection(
        normal_detection
    )

    print_result(
        "TEST 4 — NORMAL → MONITOR",
        result,
    )

    print("\n")
    print("=" * 70)
    print(
        "DEFENCE CONTROLLER TEST COMPLETE"
    )
    print("=" * 70)

    print("\nIMPORTANT:")
    print(
        "No firewall command was executed."
    )

    print(
        "The system remains in DRY_RUN mode."
    )


if __name__ == "__main__":
    main()