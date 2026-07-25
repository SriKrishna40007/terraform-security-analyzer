from abc import ABC, abstractmethod

from terraform_security_analyzer.models.finding import Finding
from terraform_security_analyzer.models.terraform_resource import TerraformResource


class Rule(ABC):
    """
    Base interface for all security rules.
    """

    @abstractmethod
    def evaluate(
        self,
        resource: TerraformResource,
    ) -> list[Finding]:
        """
        Analyze a Terraform resource and return zero or more findings.
        """
        pass