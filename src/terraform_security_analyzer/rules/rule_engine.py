from terraform_security_analyzer.models.finding import Finding
from terraform_security_analyzer.models.terraform_resource import TerraformResource

from terraform_security_analyzer.rules.rule import Rule
from terraform_security_analyzer.rules.ssh_open_to_world_rule import (
    SSHOpenToWorldRule,
)
from terraform_security_analyzer.rules.public_s3_bucket_rule import (
    PublicS3BucketRule,
)
from terraform_security_analyzer.rules.iam_wildcard_rule import (
    IAMWildcardRule,
)
from terraform_security_analyzer.rules.public_rds_rule import (
    PublicRDSRule,
)
from terraform_security_analyzer.rules.unencrypted_ebs_rule import (
    UnencryptedEBSRule,
)
from terraform_security_analyzer.rules.s3_versioning_rule import (
    S3VersioningRule,
)
from terraform_security_analyzer.rules.s3_encryption_rule import (
    S3EncryptionRule,
)
class RuleEngine:
    """
    Executes all registered security rules.
    """

    def __init__(self):

        self.rules= [
            SSHOpenToWorldRule(),
            PublicS3BucketRule(),
            IAMWildcardRule(),
            PublicRDSRule(),
            UnencryptedEBSRule(),
            S3VersioningRule(),
            S3EncryptionRule(),
        ]
        

    def evaluate(
        self,
        resources: list[TerraformResource],
    ) -> list[Finding]:

        findings: list[Finding] = []

        for resource in resources:
            for rule in self.rules:
                findings.extend(rule.evaluate(resource))

        return findings