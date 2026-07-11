import json

from terraform_security_analyzer.models.finding import Finding


class JSONReport:
    """
    Generates a JSON report from findings.
    """

    def generate(
        self,
        findings: list[Finding],
        output_file: str = "report.json",
    ) -> None:

        report = []

        for finding in findings:

            report.append(
                {
                    "rule_id": finding.rule_id,
                    "severity": finding.severity,
                    "title": finding.title,
                    "resource": finding.resource,
                    "recommendation": finding.recommendation,
                }
            )

        with open(output_file, "w", encoding="utf-8") as file:
            json.dump(
                report,
                file,
                indent=4,
            )