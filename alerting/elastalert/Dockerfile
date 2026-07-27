FROM jertel/elastalert2@sha256:e3df603867eeab32e3aae4e1dacf6bb35f0834d41b80dab8bdc11d8d787563fe

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

