FROM kalilinux/kali-rolling@sha256:49d174981a2a211e76acdde22a2e4978ea19bc0433487292cd9ad865da24ee42

ENV DEBIAN_FRONTEND=noninteractive

# Update and install attack tools
RUN apt-get update && apt-get install -y \
    nmap \
    hydra \
    sqlmap \
    curl \
    wget \
    netcat-openbsd \
    dnsutils \
    iputils-ping \
    arping \
    hping3 \
    traceroute \
    tcpdump \
    openssl \
    iproute2 \
    jq \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create working directories
RUN mkdir -p /scripts /wordlists /results

# Copy scripts and wordlists
COPY scripts/ /scripts/
COPY wordlists/ /wordlists/

# Make scripts executable
RUN chmod +x /scripts/*.sh

# Set working directory
WORKDIR /scripts

# Default command
CMD ["/bin/bash"]

