# INTENTIONALLY VULNERABLE lab image. Never deploy.
# Base image pinned by digest (python:3.13-slim, resolved from the registry 2026-10-22; Dependabot keeps it current).
# NOTE: the image build itself has not been run yet (no Docker daemon was available).
FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928
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
