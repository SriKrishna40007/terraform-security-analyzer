from terraform_security_analyzer.models.finding import Finding
from terraform_security_analyzer.models.terraform_resource import TerraformResource
from terraform_security_analyzer.rules.rule import Rule


class S3VersioningRule(Rule):
    """
    Detect S3 buckets where versioning is disabled or suspended.
    """

    def evaluate(
        self,
        resource: TerraformResource,
    ) -> list[Finding]:

        findings: list[Finding] = []

        if resource.resource_type != "aws_s3_bucket_versioning":
            return findings

        versioning = resource.attributes.get(
            "versioning_configuration",
            [],
        )

        for config in versioning:

            status = config.get("status", "").strip('"')

            if status in ("Disabled", "Suspended"):

                findings.append(
                    Finding(
                        rule_id="AWS006",
                        severity="MEDIUM",
                        title="S3 Versioning Disabled",
                        resource=resource.resource_name,
                        recommendation=(
                            "Enable S3 Versioning to protect against accidental deletion or overwrite."
                        ),
                    )
                )

        return findings