FROM kalilinux/kali-rolling

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

