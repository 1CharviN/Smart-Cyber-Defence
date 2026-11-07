from firewall_manager import FirewallManager


def main():

    print("=" * 70)
    print("FIREWALL MANAGER DRY-RUN TEST")
    print("=" * 70)

    firewall = FirewallManager()

    # ---------------------------------------------------------
    # Test 1 — BLOCK_IP
    # ---------------------------------------------------------

    print("\n")
    print("=" * 70)
    print("TEST 1 — BLOCK IP")
    print("=" * 70)

    source_ip = "10.0.0.50"

    commands = firewall.build_command(
        "BLOCK_IP",
        source_ip,
    )

    print(
        f"\nSource IP: {source_ip}"
    )

    print("\nGenerated command:")

    for command in commands:
        print(
            f"  {command}"
        )

    # ---------------------------------------------------------
    # Test 2 — RATE_LIMIT
    # ---------------------------------------------------------

    print("\n")
    print("=" * 70)
    print("TEST 2 — RATE LIMIT")
    print("=" * 70)

    source_ip = "10.0.0.70"

    commands = firewall.build_command(
        "RATE_LIMIT",
        source_ip,
    )

    print(
        f"\nSource IP: {source_ip}"
    )

    print("\nGenerated commands:")

    for command in commands:
        print(
            f"  {command}"
        )

    # ---------------------------------------------------------
    # Test 3 — INVALID IP
    # ---------------------------------------------------------

    print("\n")
    print("=" * 70)
    print("TEST 3 — INVALID IP")
    print("=" * 70)

    try:

        firewall.build_command(
            "BLOCK_IP",
            "not-an-ip",
        )

        print(
            "ERROR: Invalid IP was accepted."
        )

    except ValueError as exc:

        print(
            f"Correctly rejected: {exc}"
        )

    # ---------------------------------------------------------
    # Test 4 — NORMAL / MONITOR
    # ---------------------------------------------------------

    print("\n")
    print("=" * 70)
    print("TEST 4 — MONITOR")
    print("=" * 70)

    commands = firewall.build_command(
        "MONITOR",
        "10.0.0.60",
    )

    print(
        f"\nGenerated commands: {commands}"
    )

    print(
        "\nNo firewall command should be "
        "generated for MONITOR."
    )

    print("\n")
    print("=" * 70)
    print("FIREWALL MANAGER TEST COMPLETE")
    print("=" * 70)

    print(
        "\nIMPORTANT:"
    )

    print(
        "No firewall command was executed."
    )

    print(
        "This test only generated commands."
    )


if __name__ == "__main__":
    main()