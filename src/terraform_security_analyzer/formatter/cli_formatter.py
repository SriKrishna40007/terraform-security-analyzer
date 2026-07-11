from terraform_security_analyzer.models.finding import Finding


class CLIFormatter:
    """
    Formats security findings for terminal output.
    """

    def format(
        self,
        findings: list[Finding],
    ) -> str:
        """
        Convert findings into a human-readable report.
        """

        if not findings:
            return "✓ No security findings detected."

        lines = []

        lines.append("=" * 60)
        lines.append("Terraform Security Analyzer")
        lines.append("=" * 60)
        lines.append("")

        for finding in findings:

            lines.append(f"Rule ID        : {finding.rule_id}")
            lines.append(f"Severity       : {finding.severity}")
            lines.append(f"Title          : {finding.title}")
            lines.append(f"Resource       : {finding.resource}")
            lines.append(
                f"Recommendation : {finding.recommendation}"
            )
            lines.append("-" * 60)

        return "\n".join(lines)