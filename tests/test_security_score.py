from terraform_security_analyzer.models.finding import Finding
from terraform_security_analyzer.scoring.security_score import (
    SecurityScoreCalculator,
)


def test_security_score():

    findings = [
        Finding(
            rule_id="AWS001",
            severity="HIGH",
            title="SSH",
            resource="web",
            recommendation="Fix",
        ),
        Finding(
            rule_id="AWS006",
            severity="MEDIUM",
            title="Versioning",
            resource="bucket",
            recommendation="Enable",
        ),
    ]

    calculator = SecurityScoreCalculator()

    score = calculator.calculate(findings)

    assert score == 70