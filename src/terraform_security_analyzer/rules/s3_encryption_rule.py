from terraform_security_analyzer.models.finding import Finding
from terraform_security_analyzer.models.terraform_resource import TerraformResource
from terraform_security_analyzer.rules.rule import Rule


class S3EncryptionRule(Rule):
    """
    Detect S3 buckets without server-side encryption.
    """

    def evaluate(
        self,
        resource: TerraformResource,
    ) -> list[Finding]:

        findings: list[Finding] = []

        if (
            resource.resource_type
            != "aws_s3_bucket_server_side_encryption_configuration"
        ):
            return findings

        rules = resource.attributes.get("rule", [])

        if not rules:

            findings.append(
                Finding(
                    rule_id="AWS007",
                    severity="HIGH",
                    title="S3 Encryption Disabled",
                    resource=resource.resource_name,
                    recommendation=(
                        "Enable server-side encryption using AES256 or AWS KMS."
                    ),
                )
            )

        return findings