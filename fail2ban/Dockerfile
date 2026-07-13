FROM crazymax/fail2ban@sha256:7cd8a427a44675397398a8dace2a3d755e62c72527f8730e4fd37697731a9321

# Copy configuration files
COPY jail.local /etc/fail2ban/jail.local
COPY filter.d/ /etc/fail2ban/filter.d/
COPY action.d/ /etc/fail2ban/action.d/

# Set timezone
ENV TZ=UTC

# Ensure proper permissions
RUN chmod 644 /etc/fail2ban/jail.local
RUN chmod -R 644 /etc/fail2ban/filter.d/
RUN chmod -R 644 /etc/fail2ban/action.d/

