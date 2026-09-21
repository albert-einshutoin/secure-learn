FROM jasonish/suricata:8.0.7@sha256:7ca2546f7f2735f621b981b6a5ec84fb962984636f7629a1a2fa6a324d4b6840

# Copy custom configuration and rules.
# The upstream image declares /etc/suricata and /var/lib/suricata as VOLUMEs,
# so lab-owned config and rules live under /opt to avoid stale anonymous data.
COPY suricata.yaml /opt/soc-lab/suricata.yaml
COPY suricata-ips.yaml /opt/soc-lab/suricata-ips.yaml
COPY rules/ /opt/soc-lab/rules/

# Create log directory
RUN mkdir -p /var/log/suricata

# Set permissions
RUN chmod 644 /opt/soc-lab/suricata.yaml
RUN chmod 644 /opt/soc-lab/suricata-ips.yaml
RUN find /opt/soc-lab/rules -type d -exec chmod 755 {} + \
  && find /opt/soc-lab/rules -type f -exec chmod 644 {} +

CMD ["-c", "/opt/soc-lab/suricata.yaml", "-i", "eth0"]

