from terraform_security_analyzer.extractor.resource_extractor import (
    ResourceExtractor,
)


def test_extract_resource():

    parsed = {
        "resource": [
            {
                '"aws_s3_bucket"': {
                    '"logs"': {
                        "acl": '"private"',
                    }
                }
            }
        ]
    }

    extractor = ResourceExtractor()

    resources = extractor.extract(parsed)

    assert len(resources) == 1
    assert resources[0].resource_type == "aws_s3_bucket"
    assert resources[0].resource_name == "logs"