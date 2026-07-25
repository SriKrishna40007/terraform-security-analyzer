from terraform_security_analyzer.models.finding import Finding
from terraform_security_analyzer.models.terraform_resource import TerraformResource
from terraform_security_analyzer.rules.rule import Rule


class SSHOpenToWorldRule(Rule):
    """
    Detects Security Groups that expose SSH (22) to the Internet.
    """

    def evaluate(
        self,
        resource: TerraformResource,
    ) -> list[Finding]:
        """
        Evaluate a Terraform resource for publicly accessible SSH.
        """

        findings: list[Finding] = []

        # Only evaluate Security Groups
        if resource.resource_type != "aws_security_group":
            return findings

        # Check every ingress rule
        for ingress in resource.attributes.get("ingress", []):

            # Remove quotes added by python-hcl2
            cidr_blocks = [
                cidr.strip('"')
                for cidr in ingress.get("cidr_blocks", [])
            ]

            if (
                ingress.get("from_port") == 22
                and ingress.get("to_port") == 22
                and "0.0.0.0/0" in cidr_blocks
            ):
                findings.append(
                    Finding(
                        rule_id="AWS001",
                        severity="HIGH",
                        title="SSH Open to Internet",
                        resource=resource.resource_name,
                        recommendation=(
                            "Restrict SSH access to trusted IP addresses instead of 0.0.0.0/0."
                        ),
                    )
                )

        return findings