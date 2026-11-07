import ipaddress


class FirewallManager:
    """
    Generates Linux iptables commands for defensive actions.

    IMPORTANT:
    This version NEVER executes the command.

    It is a dry-run command generator and validator.
    """

    def __init__(self, interface=None):
        self.interface = interface

    def _validate_ip(self, source_ip):
        """
        Validate IPv4 or IPv6 address.
        """

        if not source_ip:
            raise ValueError(
                "Source IP is missing."
            )

        try:
            ipaddress.ip_address(
                source_ip
            )

        except ValueError as exc:
            raise ValueError(
                f"Invalid IP address: {source_ip}"
            ) from exc

    def build_block_command(
        self,
        source_ip,
    ):
        """
        Build an iptables rule that blocks
        traffic from the source IP.
        """

        self._validate_ip(
            source_ip
        )

        # IPv4 example:
        #
        # iptables -A INPUT -s 10.0.0.50 -j DROP
        #
        # IPv6 requires ip6tables and will be
        # handled separately.
        address = ipaddress.ip_address(
            source_ip
        )

        if address.version == 4:

            return (
                "iptables "
                f"-A INPUT "
                f"-s {source_ip} "
                "-j DROP"
            )

        return (
            "ip6tables "
            f"-A INPUT "
            f"-s {source_ip} "
            "-j DROP"
        )

    def build_rate_limit_commands(
        self,
        source_ip,
        packets_per_second=20,
        burst=40,
    ):
        """
        Build a simple two-rule Linux rate-limit
        policy for a source IP.

        The first rule permits traffic up to the
        configured limit.

        The second rule drops the remaining traffic.

        This is intended for the isolated Linux lab.
        """

        self._validate_ip(
            source_ip
        )

        address = ipaddress.ip_address(
            source_ip
        )

        if address.version == 4:
            tool = "iptables"
        else:
            tool = "ip6tables"

        allow_rule = (
            f"{tool} "
            "-A INPUT "
            f"-s {source_ip} "
            "-m limit "
            f"--limit {packets_per_second}/second "
            f"--limit-burst {burst} "
            "-j ACCEPT"
        )

        drop_rule = (
            f"{tool} "
            "-A INPUT "
            f"-s {source_ip} "
            "-j DROP"
        )

        return [
            allow_rule,
            drop_rule,
        ]

    def build_command(
        self,
        action,
        source_ip,
    ):
        """
        Convert a DefenceAction into one or more
        Linux firewall commands.
        """

        if action == "BLOCK_IP":

            return [
                self.build_block_command(
                    source_ip
                )
            ]

        if action == "RATE_LIMIT":

            return self.build_rate_limit_commands(
                source_ip
            )

        return []