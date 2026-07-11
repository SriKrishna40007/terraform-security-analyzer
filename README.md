# Terraform Security Analyzer

A production-ready Terraform Security Analyzer built with Python.

The project scans Terraform configurations, detects AWS security misconfigurations, calculates a security score, and generates JSON reports.

---

## Features

- CLI Application
- Plugin-based Rule Engine
- Terraform HCL Parsing
- Resource Extraction
- Security Score Calculation
- JSON Report Generation
- Docker Support
- Unit Tests
- GitHub Actions CI

---

## Supported Security Rules

| Rule | Description |
|------|-------------|
| AWS001 | SSH Open to Internet |
| AWS002 | Public S3 Bucket |
| AWS003 | IAM Wildcard Permissions |
| AWS004 | Public RDS Instance |
| AWS005 | Unencrypted EBS Volume |
| AWS006 | S3 Versioning Disabled |
| AWS007 | S3 Encryption Disabled |

---

## Architecture

```

CLI

↓

Parser

↓

Resource Extractor

↓

Rule Engine

↓

Security Rules

↓

Security Score

↓

Formatter

↓

JSON Report

```

---

## Project Structure

```

src/
terraform_security_analyzer/

extractor/
formatter/
models/
parser/
reports/
rules/
scoring/

tests/

examples/

```

## Installation

```bash
git clone <repository>

cd terraform-security-analyzer

uv sync