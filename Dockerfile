FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY pyproject.toml README.md ./
COPY src ./src
COPY configs ./configs
COPY dashboard ./dashboard
COPY tests ./tests
RUN pip install -e .

ENV MCD_CONFIG=/app/configs/system.yaml REDIS_URL=redis://redis:6379/0
CMD ["python", "-m", "mcd.runtime.launch", "--role", "local"]
