from terraform_security_analyzer.models.terraform_resource import TerraformResource


class ResourceExtractor:
    """
    Converts parsed Terraform dictionaries into TerraformResource objects.
    """

    def extract(self, parsed_data: dict) -> list[TerraformResource]:
        """
        Extract Terraform resources from parsed HCL data.
        """

        resources = []

        for resource_block in parsed_data.get("resource", []):

            for resource_type, resource_values in resource_block.items():

                resource_type = resource_type.strip('"')

                for resource_name, attributes in resource_values.items():

                    resource_name = resource_name.strip('"')

                    resources.append(
                        TerraformResource(
                            resource_type=resource_type,
                            resource_name=resource_name,
                            attributes=attributes,
                        )
                    )

        return resources