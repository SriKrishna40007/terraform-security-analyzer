from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class TerraformResource:
    """
    Represents a Terraform resource discovered in a configuration.
    """

    resource_type: str
    resource_name: str
    attributes: dict[str, Any] = field(default_factory=dict)