from terraform_security_analyzer.models.finding import Finding


class CLIFormatter:
    """
    Formats security findings for terminal output.
    """

    def format(
        self,
        findings: list[Finding],
        security_score: int,
    ) -> str:
        """
        Convert findings into a human-readable report.
        """

        lines = []

        lines.append("=" * 60)
        lines.append("Terraform Security Analyzer")
        lines.append("=" * 60)
        lines.append(f"Security Score : {security_score}/100")
        lines.append("")

        if not findings:
            lines.append("✓ No security findings detected.")
            return "\n".join(lines)

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