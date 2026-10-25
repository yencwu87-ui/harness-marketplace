# One image for every track: Python 3.12, Node 22, jq, git, Claude Code CLI, uv.
# Used by VS Code Dev Containers, GitHub Codespaces, and environments/docker/run-sandboxed.sh.
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      git jq curl ca-certificates make bubblewrap socat \
    && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

RUN npm install -g @anthropic-ai/claude-code && pip install --no-cache-dir uv

# Non-root user: the agent can only touch what you mount into /workspace.
RUN useradd -m -s /bin/bash dev
USER dev
WORKDIR /workspace
