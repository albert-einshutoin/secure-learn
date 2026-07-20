FROM kalilinux/kali-rolling@sha256:b3d7855dd35daa5e56a6806e9c34cb91c954d9a8a97b78c3352438732a61a079

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

