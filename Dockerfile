FROM python:3.13-slim

WORKDIR /app

RUN pip install --no-cache-dir uv

COPY pyproject.toml ./
COPY README.md ./

RUN uv sync --no-install-project --group dev

COPY . .

RUN uv sync --group dev

ENTRYPOINT ["uv", "run", "tfscan"]