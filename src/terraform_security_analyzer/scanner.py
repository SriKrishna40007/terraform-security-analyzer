from pathlib import Path

from terraform_security_analyzer.extractor.resource_extractor import (
    ResourceExtractor,
)
from terraform_security_analyzer.formatter.cli_formatter import (
    CLIFormatter,
)
from terraform_security_analyzer.parser.hcl_parser import (
    HCLParser,
)
from terraform_security_analyzer.reports.json_report import (
    JSONReport,
)
from terraform_security_analyzer.rules.rule_engine import (
    RuleEngine,
)
from terraform_security_analyzer.scoring.security_score import (
    SecurityScoreCalculator,
)


class TerraformScanner:
    """
    Public SDK entry point for Terraform Security Analyzer.
    """

    def __init__(self) -> None:
        self.parser = HCLParser()
        self.extractor = ResourceExtractor()
        self.rule_engine = RuleEngine()
        self.score_calculator = SecurityScoreCalculator()
        self.report_generator = JSONReport()
        self.formatter = CLIFormatter()

    def scan(self, file_path: Path) -> dict:
        """
        Analyze a Terraform configuration file and return the analysis result.
        """

        parsed_data = self.parser.parse_file(file_path)

        resources = self.extractor.extract(parsed_data)

        findings = self.rule_engine.evaluate(resources)

        security_score = self.score_calculator.calculate(findings)

        self.report_generator.generate(findings)

        report = self.formatter.format(
            findings=findings,
            security_score=security_score,
        )

        return {
            "findings": findings,
            "security_score": security_score,
            "report": report,
        }