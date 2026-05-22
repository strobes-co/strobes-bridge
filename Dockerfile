FROM python:3.12-slim

LABEL maintainer="Strobes <support@strobes.co>"
LABEL description="Strobes Shell Bridge Agent"

WORKDIR /app

# Install common security/pentest tools available in slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    git \
    jq \
    nmap \
    dnsutils \
    net-tools \
    iputils-ping \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
COPY strobes_shell_agent/ strobes_shell_agent/
COPY tests/ tests/

RUN pip install --no-cache-dir .

# Default working directory for commands
WORKDIR /workspace

ENTRYPOINT ["strobes-shell-agent"]
CMD ["connect"]
