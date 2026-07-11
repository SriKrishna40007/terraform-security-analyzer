from pathlib import Path

import typer

from terraform_security_analyzer.extractor.resource_extractor import (
    ResourceExtractor,
)
from terraform_security_analyzer.formatter.cli_formatter import (
    CLIFormatter,
)
from terraform_security_analyzer.parser.hcl_parser import HCLParser
from terraform_security_analyzer.rules.rule_engine import RuleEngine
from terraform_security_analyzer.scoring.security_score import (
    SecurityScoreCalculator,
)

app = typer.Typer(
    help="Production-ready Terraform Security Analyzer"
)


@app.command()
def version():
    """
    Display the current version.
    """
    typer.echo("Terraform Security Analyzer v0.1.0")


@app.command()
def scan(file_path: str):
    """
    Scan a Terraform configuration file.
    """

    parser = HCLParser()
    extractor = ResourceExtractor()
    engine = RuleEngine()
    formatter = CLIFormatter()
    score_calculator = SecurityScoreCalculator()

    parsed_data = parser.parse_file(Path(file_path))

    resources = extractor.extract(parsed_data)

    findings = engine.evaluate(resources)

    security_score = score_calculator.calculate(findings)

    report = formatter.format(
        findings=findings,
        security_score=security_score,
    )

    typer.echo(report)


if __name__ == "__main__":
    app()