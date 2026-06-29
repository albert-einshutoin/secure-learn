FROM jasonish/suricata:7.0

# Copy custom configuration and rules
COPY suricata.yaml /etc/suricata/suricata.yaml
COPY suricata-ips.yaml /etc/suricata/suricata-ips.yaml
COPY rules/ /var/lib/suricata/rules/

# Create log directory
RUN mkdir -p /var/log/suricata

# Set permissions
RUN chmod 644 /etc/suricata/suricata.yaml
RUN chmod 644 /etc/suricata/suricata-ips.yaml
RUN find /var/lib/suricata/rules -type d -exec chmod 755 {} + \
  && find /var/lib/suricata/rules -type f -exec chmod 644 {} +

CMD ["-c", "/etc/suricata/suricata.yaml", "-i", "eth0"]

