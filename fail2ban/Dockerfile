FROM crazymax/fail2ban:latest

# Copy configuration files
COPY jail.local /etc/fail2ban/jail.local
COPY filter.d/ /etc/fail2ban/filter.d/
COPY action.d/ /etc/fail2ban/action.d/

# Set timezone
ENV TZ=Asia/Tokyo

# Ensure proper permissions
RUN chmod 644 /etc/fail2ban/jail.local
RUN chmod -R 644 /etc/fail2ban/filter.d/
RUN chmod -R 644 /etc/fail2ban/action.d/

