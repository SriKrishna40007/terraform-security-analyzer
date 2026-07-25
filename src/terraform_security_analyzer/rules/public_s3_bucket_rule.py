from terraform_security_analyzer.models.finding import Finding
from terraform_security_analyzer.models.terraform_resource import TerraformResource
from terraform_security_analyzer.rules.rule import Rule


class PublicS3BucketRule(Rule):
    """
    Detects publicly accessible S3 buckets.
    """

    def evaluate(
        self,
        resource: TerraformResource,
    ) -> list[Finding]:

        findings: list[Finding] = []

        if resource.resource_type != "aws_s3_bucket":
            return findings

        acl = resource.attributes.get("acl", "").strip('"')

        if acl in ("public-read", "public-read-write"):

            findings.append(
                Finding(
                    rule_id="AWS002",
                    severity="HIGH",
                    title="Public S3 Bucket",
                    resource=resource.resource_name,
                    recommendation=(
                        "Use private ACLs or S3 Block Public Access."
                    ),
                )
            )

        return findings