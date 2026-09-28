FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY threat_research ./threat_research
RUN pip install --no-cache-dir .

ENV PYTHONUNBUFFERED=1 THREAT_RESEARCH_DB=/data/intel.sqlite3
CMD ["python", "-m", "threat_research.cli", "serve-live"]
