from terraform_security_analyzer.models.terraform_resource import (
    TerraformResource,
)
from terraform_security_analyzer.rules.public_s3_bucket_rule import (
    PublicS3BucketRule,
)


def test_detect_public_s3_bucket():

    resource = TerraformResource(
        resource_type="aws_s3_bucket",
        resource_name="logs",
        attributes={
            "acl": '"public-read"',
        },
    )

    rule = PublicS3BucketRule()

    findings = rule.evaluate(resource)

    assert len(findings) == 1
    assert findings[0].rule_id == "AWS002"