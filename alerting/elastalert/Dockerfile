FROM jertel/elastalert2@sha256:d5d43dadb669668dc4f673291e2d8e60ce4c01aab5f0da744f3d0ac13ee38f63

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

