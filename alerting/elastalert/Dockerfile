FROM jertel/elastalert2@sha256:0241ce5bf67bb8afd6766ec8a49b613058a1796f6c5013f8cd0254398684dd84

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

