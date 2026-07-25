from pathlib import Path

import typer

from terraform_security_analyzer.scanner import TerraformScanner

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

    scanner = TerraformScanner()

    result = scanner.scan(Path(file_path))

    typer.echo(result["report"])


if __name__ == "__main__":
    app()