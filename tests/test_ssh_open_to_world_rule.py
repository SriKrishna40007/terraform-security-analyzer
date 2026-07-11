from terraform_security_analyzer.models.terraform_resource import (
    TerraformResource,
)
from terraform_security_analyzer.rules.ssh_open_to_world_rule import (
    SSHOpenToWorldRule,
)


def test_detect_open_ssh():

    resource = TerraformResource(
        resource_type="aws_security_group",
        resource_name="web",
        attributes={
            "ingress": [
                {
                    "from_port": 22,
                    "to_port": 22,
                    "protocol": "tcp",
                    "cidr_blocks": ["0.0.0.0/0"],
                }
            ]
        },
    )

    rule = SSHOpenToWorldRule()

    findings = rule.evaluate(resource)

    assert len(findings) == 1

    assert findings[0].rule_id == "AWS001"

    assert findings[0].severity == "HIGH"