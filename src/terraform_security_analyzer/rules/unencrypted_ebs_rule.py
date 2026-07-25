from terraform_security_analyzer.models.finding import Finding
from terraform_security_analyzer.models.terraform_resource import TerraformResource
from terraform_security_analyzer.rules.rule import Rule


class UnencryptedEBSRule(Rule):
    """
    Detect unencrypted EBS volumes.
    """

    def evaluate(
        self,
        resource: TerraformResource,
    ) -> list[Finding]:

        findings: list[Finding] = []

        if resource.resource_type != "aws_ebs_volume":
            return findings

        encrypted = resource.attributes.get("encrypted", False)

        if encrypted is False:

            findings.append(
                Finding(
                    rule_id="AWS005",
                    severity="HIGH",
                    title="Unencrypted EBS Volume",
                    resource=resource.resource_name,
                    recommendation=(
                        "Enable encryption for all EBS volumes."
                    ),
                )
            )

        return findings