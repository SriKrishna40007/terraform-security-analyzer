from pathlib import Path

import hcl2


class HCLParser:
    """
    Parses Terraform HCL files into Python dictionaries.
    """

    def parse_file(self, file_path: Path) -> dict:
        """
        Parse a Terraform (.tf) file.

        Args:
            file_path: Path to the Terraform file.

        Returns:
            Parsed Terraform configuration as a dictionary.

        Raises:
            FileNotFoundError:
                If the file does not exist.

            ValueError:
                If the file cannot be parsed.
        """

        if not file_path.exists():
            raise FileNotFoundError(
                f"Terraform file not found: {file_path}"
            )

        try:
            with file_path.open("r", encoding="utf-8") as terraform_file:
                return hcl2.load(terraform_file)

        except Exception as error:
            raise ValueError(
                f"Failed to parse Terraform file: {file_path}"
            ) from error