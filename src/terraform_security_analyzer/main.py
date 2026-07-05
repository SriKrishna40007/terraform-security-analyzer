from pathlib import Path

import typer

from terraform_security_analyzer.parser.hcl_parser import HCLParser

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

    terraform_data = parser.parse_file(Path(file_path))

    typer.echo("✅ Terraform parsed successfully.")
    typer.echo(terraform_data)


if __name__ == "__main__":
    app()