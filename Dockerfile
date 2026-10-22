# INTENTIONALLY VULNERABLE lab image. Never deploy.
# TODO(hardening): pin the base image by digest once Docker is available to resolve it.
FROM python:3.13-slim
RUN useradd --create-home lab
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN pip install --no-cache-dir uv==0.8.0 && uv sync --frozen --no-dev --no-install-project
COPY agent ./agent
COPY services ./services
COPY fixes ./fixes
COPY attacks ./attacks
COPY data ./data
RUN chown -R lab /app
USER lab
ENV PATH="/app/.venv/bin:$PATH"
CMD ["python", "-m", "agent"]
