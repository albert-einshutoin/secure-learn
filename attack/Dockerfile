FROM kalilinux/kali-rolling@sha256:dea2bdf0e8c0ca1deb51b7a6253f481acae3ca9c2f1e2371077e6af55e5b2721

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

