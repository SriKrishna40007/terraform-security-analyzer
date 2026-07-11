from terraform_security_analyzer.models.finding import Finding


class SecurityScoreCalculator:
    """
    Calculates an overall security score.
    """

    def calculate(
        self,
        findings: list[Finding],
    ) -> int:

        score = 100

        for finding in findings:

            if finding.severity == "HIGH":
                score -= 20

            elif finding.severity == "MEDIUM":
                score -= 10

            elif finding.severity == "LOW":
                score -= 5

        return max(score, 0)