from decision_engine import DefenceDecisionEngine
from firewall_manager import FirewallManager


class DefenceController:
    """
    Coordinates the Module 3 decision engine and
    firewall command generator.

    IMPORTANT:
    This controller does NOT execute firewall commands.
    It only generates and returns the commands that
    would be executed in the controlled Linux lab.
    """

    def __init__(
        self,
        confidence_threshold=0.80,
        protected_ips=None,
        dry_run=True,
    ):

        self.decision_engine = (
            DefenceDecisionEngine(
                confidence_threshold=confidence_threshold,
                protected_ips=protected_ips,
                dry_run=dry_run,
            )
        )

        self.firewall_manager = (
            FirewallManager()
        )

        self.dry_run = dry_run

    def process_detection(
        self,
        detection,
    ):
        """
        Process a Module 2 detection result and
        generate the corresponding firewall command.
        """

        # -----------------------------------------------------
        # Step 1:
        # Ask the decision engine what to do.
        # -----------------------------------------------------

        defence_action = (
            self.decision_engine.evaluate(
                detection
            )
        )

        # -----------------------------------------------------
        # Step 2:
        # If action is not approved, no firewall
        # command should be generated.
        # -----------------------------------------------------

        if not defence_action.approved:

            return {
                "action": defence_action.action,
                "source_ip": defence_action.source_ip,
                "reason": defence_action.reason,
                "approved": False,
                "executed": False,
                "commands": [],
                "mode": "DRY_RUN",
            }

        # -----------------------------------------------------
        # Step 3:
        # Generate the appropriate firewall command(s).
        # -----------------------------------------------------

        commands = (
            self.firewall_manager.build_command(
                defence_action.action,
                defence_action.source_ip,
            )
        )

        # -----------------------------------------------------
        # Step 4:
        # Never execute anything here.
        # -----------------------------------------------------

        return {
            "action": defence_action.action,
            "source_ip": defence_action.source_ip,
            "reason": defence_action.reason,
            "approved": True,
            "executed": False,
            "commands": commands,
            "mode": "DRY_RUN",
        }