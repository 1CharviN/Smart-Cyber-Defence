from dataclasses import dataclass
from typing import Optional


@dataclass
class DefenceAction:
    """
    Represents a proposed defensive action.

    action:
        MONITOR
        BLOCK_IP
        RATE_LIMIT
        NO_ACTION

    command:
        The firewall command that would be executed
        in the Linux lab environment.

    executed:
        False during dry-run mode.
    """

    action: str
    source_ip: Optional[str]
    reason: str

    approved: bool
    executed: bool

    command: Optional[str] = None