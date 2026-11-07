from decision_engine import (
    DefenceDecisionEngine,
)

from defence_logger import (
    DefenceLogger,
)


def test_detection(
    detector,
    logger,
    name,
    detection,
):
    print("\n" + "=" * 70)
    print(name)
    print("=" * 70)

    action = detector.evaluate(
        detection
    )

    event = logger.log(
        action,
        detection,
    )

    print(
        f"Source IP : "
        f"{action.source_ip}"
    )

    print(
        f"Attack    : "
        f"{detection.get('attack_type')}"
    )

    print(
        f"Confidence: "
        f"{detection.get('rf_confidence', 0) * 100:.2f}%"
    )

    print(
        f"Action    : "
        f"{action.action}"
    )

    print(
        f"Approved  : "
        f"{action.approved}"
    )

    print(
        f"Executed  : "
        f"{action.executed}"
    )

    print(
        f"Reason    : "
        f"{action.reason}"
    )

    print(
        "\nD3 log saved:"
    )

    print(event)


def main():

    print("=" * 70)
    print("MODULE 3 DEFENCE DECISION ENGINE TEST")
    print("=" * 70)

    detector = DefenceDecisionEngine(
        confidence_threshold=0.80,

        protected_ips={
            "192.168.1.2",
        },

        dry_run=True,
    )

    logger = DefenceLogger()

    # ---------------------------------------------------------
    # TEST 1
    # Known attack from unprotected IP.
    # ---------------------------------------------------------

    test_detection(
        detector,
        logger,
        "TEST 1 — DDOS",
        {
            "source_ip": "10.0.0.50",
            "attack_type": "DDOS",
            "rf_confidence": 0.99,
            "anomaly": True,
            "anomaly_score": -0.08,
            "severity": "HIGH",
            "threat_signal": True,
        },
    )

    # ---------------------------------------------------------
    # TEST 2
    # Known attack from protected IP.
    # ---------------------------------------------------------

    test_detection(
        detector,
        logger,
        "TEST 2 — PROTECTED IP",
        {
            "source_ip": "192.168.1.2",
            "attack_type": "DDOS",
            "rf_confidence": 0.99,
            "anomaly": True,
            "anomaly_score": -0.08,
            "severity": "HIGH",
            "threat_signal": True,
        },
    )

    # ---------------------------------------------------------
    # TEST 3
    # Normal traffic.
    # ---------------------------------------------------------

    test_detection(
        detector,
        logger,
        "TEST 3 — NORMAL",
        {
            "source_ip": "10.0.0.60",
            "attack_type": "NORMAL",
            "rf_confidence": 0.99,
            "anomaly": False,
            "anomaly_score": 0.16,
            "severity": "LOW",
            "threat_signal": False,
        },
    )

    # ---------------------------------------------------------
    # TEST 4
    # Unknown anomaly.
    # ---------------------------------------------------------

    test_detection(
        detector,
        logger,
        "TEST 4 — UNKNOWN ANOMALY",
        {
            "source_ip": "10.0.0.70",
            "attack_type": "UNKNOWN_ANOMALY",
            "rf_confidence": 0.50,
            "anomaly": True,
            "anomaly_score": -0.12,
            "severity": "MEDIUM",
            "threat_signal": True,
        },
    )

    print("\n" + "=" * 70)
    print(
        "MODULE 3 TEST COMPLETE"
    )
    print("=" * 70)

    print(
        "\nIMPORTANT:"
    )

    print(
        "Firewall was NOT modified."
    )

    print(
        "System is operating in DRY_RUN mode."
    )


if __name__ == "__main__":
    main()