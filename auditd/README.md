# Auditd Configuration for SOC-Lab

## Overview

Auditd is the Linux Audit daemon that records security-relevant events on the system.
This configuration is designed for scenarios S5 (File Tampering) and S6 (Privilege Escalation).

## Important Notes

### Docker Limitations

Auditd requires access to the Linux kernel's audit subsystem, which is **not available inside Docker containers** without special privileges.

### Recommended Setup

1. **Run Auditd on the Host OS** (Recommended)
   ```bash
   # Install auditd
   sudo apt-get install auditd audispd-plugins
   
   # Copy rules
   sudo cp audit.rules /etc/audit/rules.d/soc-lab.rules
   
   # Restart auditd
   sudo systemctl restart auditd
   ```

2. **Configure Filebeat on Host** to collect audit logs
   ```yaml
   filebeat.inputs:
     - type: log
       enabled: true
       paths:
         - /var/log/audit/audit.log
       tags: ["auditd"]
   ```

### Alternative: Falco (Container-friendly)

For container environments, consider using [Falco](https://falco.org/) instead:

```yaml
# docker-compose.yml addition
falco:
  image: falcosecurity/falco:latest
  privileged: true
  volumes:
    - /var/run/docker.sock:/host/var/run/docker.sock
    - /dev:/host/dev
    - /proc:/host/proc:ro
    - /boot:/host/boot:ro
    - /lib/modules:/host/lib/modules:ro
    - /usr:/host/usr:ro
```

## Useful Commands

```bash
# View audit logs
sudo ausearch -k passwd_changes
sudo ausearch -k privilege_escalation

# Search by file
sudo ausearch -f /etc/passwd

# Search by user
sudo ausearch -ua 1000

# Generate report
sudo aureport --summary
sudo aureport --file
sudo aureport --auth
```

## Key Mappings

| Key | Purpose | Scenario |
|-----|---------|----------|
| passwd_changes | /etc/passwd modifications | S5 |
| shadow_changes | /etc/shadow modifications | S5 |
| sudoers_changes | sudoers file modifications | S5/S6 |
| privilege_escalation | setuid/setgid syscalls | S6 |
| sudo_usage | sudo command execution | S6 |
| su_usage | su command execution | S6 |

