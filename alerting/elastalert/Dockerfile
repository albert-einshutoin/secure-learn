FROM jertel/elastalert2:latest

USER root

# Copy configuration
COPY config.yaml /opt/elastalert/config.yaml
COPY rules/ /opt/elastalert/rules/

# Create log directory
RUN mkdir -p /var/log/elastalert

# Set permissions
RUN chmod 644 /opt/elastalert/config.yaml
RUN chmod -R 644 /opt/elastalert/rules/
RUN chown -R elastalert:elastalert /opt/elastalert /var/log/elastalert

WORKDIR /opt/elastalert

USER elastalert

CMD ["python", "-m", "elastalert.elastalert", "--config", "/opt/elastalert/config.yaml"]

