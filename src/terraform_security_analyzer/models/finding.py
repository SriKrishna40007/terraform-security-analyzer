from dataclasses import dataclass


@dataclass(slots=True)
class Finding:
    """
    Represents a security finding discovered during analysis.
    """

    rule_id: str
    severity: str
    title: str
    resource: str
    recommendation: str