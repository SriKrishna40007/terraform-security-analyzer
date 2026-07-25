from terraform_security_analyzer.models.finding import Finding
from terraform_security_analyzer.models.terraform_resource import TerraformResource
from terraform_security_analyzer.rules.rule import Rule


class PublicRDSRule(Rule):
    """
    Detect publicly accessible RDS instances.
    """

    def evaluate(
        self,
        resource: TerraformResource,
    ) -> list[Finding]:

        findings: list[Finding] = []

        if resource.resource_type != "aws_db_instance":
            return findings

        publicly_accessible = resource.attributes.get(
            "publicly_accessible",
            False,
        )

        if publicly_accessible is True:

            findings.append(
                Finding(
                    rule_id="AWS004",
                    severity="HIGH",
                    title="Public RDS Instance",
                    resource=resource.resource_name,
                    recommendation=(
                        "Disable public accessibility for production databases."
                    ),
                )
            )

        return findings