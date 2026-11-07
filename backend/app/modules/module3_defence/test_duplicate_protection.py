from decision_engine import DefenceDecisionEngine


def main():

    print("=" * 70)
    print(
        "DUPLICATE BLOCK PROTECTION TEST"
    )
    print("=" * 70)

    engine = DefenceDecisionEngine(
        confidence_threshold=0.80,
        protected_ips={
            "192.168.1.2"
        },
        dry_run=True,
        block_cooldown_seconds=300,
    )

    detection = {

        "source_ip": "10.0.0.50",

        "attack_type": "DDOS",

        "rf_confidence": 0.99,

        "anomaly": True,

        "anomaly_score": -0.08,

        "severity": "HIGH",

        "threat_signal": True,
    }

    print("\nFirst detection:")

    first = engine.evaluate(
        detection
    )

    print(
        f"Action : {first.action}"
    )

    print(
        f"Reason : {first.reason}"
    )

    print("\nSecond detection immediately:")

    second = engine.evaluate(
        detection
    )

    print(
        f"Action : {second.action}"
    )

    print(
        f"Reason : {second.reason}"
    )

    print("\n" + "=" * 70)

    if (
        first.action == "BLOCK_IP"
        and second.action == "MONITOR"
    ):

        print(
            "DUPLICATE BLOCK PROTECTION: PASS"
        )

    else:

        print(
            "DUPLICATE BLOCK PROTECTION: CHECK"
        )

    print("=" * 70)


if __name__ == "__main__":
    main()