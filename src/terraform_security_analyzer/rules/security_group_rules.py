from terraform_security_analyzer.models.terraform_resource import TerraformResource


class SecurityGroupRules:
    """
    Security rules for AWS Security Groups.
    """

    def check_ssh_open_to_world(
        self,
        resource: TerraformResource,
    ) -> bool:
        """
        Returns True if SSH is open to the Internet.
        """

        if resource.resource_type != "aws_security_group":
            return False

        ingress_rules = resource.attributes.get("ingress", [])

        for rule in ingress_rules:

            from_port = rule.get("from_port")
            cidr_blocks = rule.get("cidr_blocks", [])

            cidr_blocks = [
                cidr.strip('"')
                for cidr in cidr_blocks
            ]

            if (
                from_port == 22
                and "0.0.0.0/0" in cidr_blocks
            ):
                return True

        return False