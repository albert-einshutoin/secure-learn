FROM crazymax/fail2ban@sha256:2bc26b68f373ce6e52bbd181de2937a6694f72b74ddf15bbd1b25e90553dcda3

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

