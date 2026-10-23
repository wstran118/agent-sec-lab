# INTENTIONALLY VULNERABLE lab image. Never deploy.
# Base image pinned by digest (python:3.13-slim, resolved from the registry 2026-10-22; Dependabot keeps it current).
# NOTE: the image build itself has not been run yet (no Docker daemon was available).
FROM python:3.13-slim@sha256:57b29a7c050c4e679e4bea572e14b3965cf4b5839de2da49d55e49ffc4024f39
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
