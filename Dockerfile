# syntax=docker/dockerfile:1

# --- stage 1: build the sandbox pack for THIS image's arch --------------------
# The pack (standalone Python + agent packages + nmap/nuclei/... + nuclei-templates)
# is baked into the image so the running bridge needs NO runtime download and no
# ad-hoc external URL. buildx builds this per target arch, so build_pack produces the
# matching linux-x86_64 / linux-aarch64 pack automatically.
FROM python:3.12-slim AS packbuild
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
ENV PATH=/root/.local/bin:$PATH
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
COPY sandbox_pack/ /sandbox_pack/
RUN uv run --python 3.12 python /sandbox_pack/build_pack.py \
        --out /opt/strobes-pack --python-version 3.12

# --- stage 2: runtime ---------------------------------------------------------
FROM python:3.12-slim

LABEL maintainer="Strobes <support@strobes.co>"
LABEL description="Strobes Shell Bridge Agent (with baked-in sandbox pack)"

WORKDIR /app

# Minimal OS deps only — the security tooling comes from the baked pack, not apt.
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    git \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
COPY strobes_shell_agent/ strobes_shell_agent/
COPY tests/ tests/

RUN pip install --no-cache-dir .

# Bake the pack in and point the bridge at it (find_pack uses STROBES_PACK_DIR/<triple>).
COPY --from=packbuild /opt/strobes-pack /opt/strobes-pack
ENV STROBES_PACK_DIR=/opt/strobes-pack

# Default working directory for commands
WORKDIR /workspace

ENTRYPOINT ["strobes-shell-agent"]
CMD ["connect"]
