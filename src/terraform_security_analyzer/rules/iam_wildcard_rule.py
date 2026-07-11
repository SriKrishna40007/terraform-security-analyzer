from terraform_security_analyzer.models.finding import Finding
from terraform_security_analyzer.models.terraform_resource import TerraformResource
from terraform_security_analyzer.rules.rule import Rule


class IAMWildcardRule(Rule):
    """
    Detect IAM policies that allow wildcard permissions.
    """

    def evaluate(
        self,
        resource: TerraformResource,
    ) -> list[Finding]:

        findings: list[Finding] = []

        if resource.resource_type != "aws_iam_policy":
            return findings

        policy = str(resource.attributes.get("policy", ""))

        if (
            'Action = "*"' in policy
            and 'Resource = "*"' in policy
        ):

            findings.append(
                Finding(
                    rule_id="AWS003",
                    severity="HIGH",
                    title="IAM Wildcard Permission",
                    resource=resource.resource_name,
                    recommendation=(
                        "Avoid wildcard permissions. Follow the Principle of Least Privilege."
                    ),
                )
            )

        return findings