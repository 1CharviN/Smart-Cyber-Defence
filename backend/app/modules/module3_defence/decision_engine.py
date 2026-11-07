import ipaddress
import time

from defence_action import DefenceAction


class DefenceDecisionEngine:
    """
    Module 3 Autonomous Defence Decision Engine.

    This version is still DRY-RUN ONLY.

    It decides what defensive action SHOULD happen,
    but does not modify the firewall itself.
    """

    KNOWN_ATTACKS = {
        "DDOS",
        "PORT_SCAN",
        "BRUTE_FORCE",
    }

    def __init__(
        self,
        confidence_threshold=0.80,
        protected_ips=None,
        dry_run=True,
        emergency_disable=False,
        block_cooldown_seconds=300,
        unknown_anomaly_action="RATE_LIMIT",
    ):

        self.confidence_threshold = (
            confidence_threshold
        )

        self.dry_run = dry_run

        self.emergency_disable = (
            emergency_disable
        )

        self.block_cooldown_seconds = (
            block_cooldown_seconds
        )

        self.unknown_anomaly_action = (
            unknown_anomaly_action
        )

        # -----------------------------------------------------
        # Protected / allowlisted IP addresses.
        # These should never be automatically blocked.
        # -----------------------------------------------------

        self.protected_ips = set(
            protected_ips or []
        )

        # -----------------------------------------------------
        # Stores recent automatic block decisions.
        #
        # IP -> expiry timestamp
        #
        # This prevents repeated BLOCK_IP decisions for
        # the same source during the cooldown period.
        # -----------------------------------------------------

        self.blocked_until = {}

    def _is_valid_ip(self, ip):
        """
        Check whether a value is a valid IPv4/IPv6 address.
        """

        if not ip:
            return False

        try:
            ipaddress.ip_address(
                ip
            )

            return True

        except ValueError:
            return False

    def _block_is_active(self, source_ip):
        """
        Check whether this IP is currently inside
        the automatic-block cooldown period.
        """

        expiry = self.blocked_until.get(
            source_ip
        )

        if expiry is None:
            return False

        now = time.time()

        if now >= expiry:

            # Expired.
            del self.blocked_until[
                source_ip
            ]

            return False

        return True

    def _register_block(self, source_ip):
        """
        Record when an automatic block decision was made.
        """

        self.blocked_until[
            source_ip
        ] = (
            time.time()
            + self.block_cooldown_seconds
        )

    def evaluate(self, detection):
        """
        Convert a Module 2 detection result into
        a proposed Module 3 defensive action.
        """

        source_ip = detection.get(
            "source_ip"
        )

        attack_type = detection.get(
            "attack_type",
            "NORMAL",
        )

        confidence = float(
            detection.get(
                "rf_confidence",
                0.0,
            )
        )

        threat_signal = bool(
            detection.get(
                "threat_signal",
                False,
            )
        )

        anomaly = bool(
            detection.get(
                "anomaly",
                False,
            )
        )

        anomaly_score = float(
            detection.get(
                "anomaly_score",
                0.0,
            )
        )

        severity = detection.get(
            "severity",
            "LOW",
        )

        # -----------------------------------------------------
        # SAFETY CHECK 1
        #
        # Emergency disable.
        # -----------------------------------------------------

        if self.emergency_disable:

            return DefenceAction(
                action="NO_ACTION",
                source_ip=source_ip,
                reason=(
                    "Emergency disable is active"
                ),
                approved=False,
                executed=False,
            )

        # -----------------------------------------------------
        # SAFETY CHECK 2
        #
        # Invalid or missing source IP.
        # -----------------------------------------------------

        if not self._is_valid_ip(
            source_ip
        ):

            return DefenceAction(
                action="NO_ACTION",
                source_ip=source_ip,
                reason=(
                    "Invalid or missing source IP"
                ),
                approved=False,
                executed=False,
            )

        # -----------------------------------------------------
        # SAFETY CHECK 3
        #
        # Protected / allowlisted IP.
        # -----------------------------------------------------

        if source_ip in self.protected_ips:

            return DefenceAction(
                action="NO_ACTION",
                source_ip=source_ip,
                reason=(
                    "Source IP is protected "
                    "or allowlisted"
                ),
                approved=False,
                executed=False,
            )

        # -----------------------------------------------------
        # SAFETY CHECK 4
        #
        # No threat signal.
        # -----------------------------------------------------

        if not threat_signal:

            return DefenceAction(
                action="MONITOR",
                source_ip=source_ip,
                reason=(
                    "No threat signal from Module 2"
                ),
                approved=False,
                executed=False,
            )

        # -----------------------------------------------------
        # SAFETY CHECK 5
        #
        # Prevent repeated block decisions.
        # -----------------------------------------------------

        if self._block_is_active(
            source_ip
        ):

            return DefenceAction(
                action="MONITOR",
                source_ip=source_ip,
                reason=(
                    "Source IP is already under "
                    "an active defence cooldown"
                ),
                approved=False,
                executed=False,
            )

        # -----------------------------------------------------
        # KNOWN ATTACK
        #
        # Random Forest identified:
        # DDOS / PORT_SCAN / BRUTE_FORCE
        # -----------------------------------------------------

        if attack_type in self.KNOWN_ATTACKS:

            if confidence < self.confidence_threshold:

                return DefenceAction(
                    action="MONITOR",
                    source_ip=source_ip,
                    reason=(
                        f"{attack_type} detected, "
                        f"but RF confidence "
                        f"{confidence * 100:.2f}% "
                        f"is below the "
                        f"{self.confidence_threshold * 100:.0f}% "
                        f"threshold"
                    ),
                    approved=False,
                    executed=False,
                )

            reason = (
                f"Known attack detected: "
                f"{attack_type}; "
                f"RF confidence "
                f"{confidence * 100:.2f}%; "
                f"severity={severity}"
            )

            # Register the decision so the same IP
            # isn't repeatedly selected for blocking.
            self._register_block(
                source_ip
            )

            if self.dry_run:

                return DefenceAction(
                    action="BLOCK_IP",
                    source_ip=source_ip,
                    reason=reason,
                    approved=True,
                    executed=False,
                )

            # Actual firewall execution will be added
            # only after the Linux lab is ready.
            return DefenceAction(
                action="BLOCK_IP",
                source_ip=source_ip,
                reason=reason,
                approved=True,
                executed=False,
            )

        # -----------------------------------------------------
        # UNKNOWN ANOMALY
        #
        # Isolation Forest detected abnormal behaviour
        # while Random Forest did not identify a known attack.
        #
        # IMPORTANT:
        # Do NOT immediately block.
        # -----------------------------------------------------

        if attack_type == "UNKNOWN_ANOMALY":

            reason = (
                "Unknown anomaly detected by "
                "Isolation Forest; "
                f"anomaly score={anomaly_score:.6f}"
            )

            if (
                self.unknown_anomaly_action
                == "RATE_LIMIT"
            ):

                return DefenceAction(
                    action="RATE_LIMIT",
                    source_ip=source_ip,
                    reason=reason,
                    approved=True,
                    executed=False,
                )

            return DefenceAction(
                action="MONITOR",
                source_ip=source_ip,
                reason=reason,
                approved=False,
                executed=False,
            )

        # -----------------------------------------------------
        # FALLBACK
        # -----------------------------------------------------

        return DefenceAction(
            action="MONITOR",
            source_ip=source_ip,
            reason=(
                "Threat requires monitoring"
            ),
            approved=False,
            executed=False,
        )