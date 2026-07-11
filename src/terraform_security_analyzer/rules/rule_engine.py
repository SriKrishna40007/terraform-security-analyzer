from terraform_security_analyzer.models.finding import Finding
from terraform_security_analyzer.models.terraform_resource import TerraformResource
from terraform_security_analyzer.rules.rule import Rule
from terraform_security_analyzer.rules.ssh_open_to_world_rule import (
    SSHOpenToWorldRule,
)


class RuleEngine:
    """
    Executes all registered security rules.
    """

    def __init__(self):

        self.rules: list[Rule] = [
            SSHOpenToWorldRule(),
        ]

    def evaluate(
        self,
        resources: list[TerraformResource],
    ) -> list[Finding]:

        findings: list[Finding] = []

        for resource in resources:

            for rule in self.rules:

                findings.extend(
                    rule.evaluate(resource)
                )

        return findings