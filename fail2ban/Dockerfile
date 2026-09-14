FROM crazymax/fail2ban@sha256:a23171aff23e536c5a7ed03a367249f71d2488d59f7a68b385f044bbc02e21e1

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

