#!/bin/sh
set -eu

mkdir -p /var/log/app

# Named volumes hide the Dockerfile-time ownership. Fixing ownership at
# container start keeps app logs writable while the Node process still runs
# without root privileges.
chown -R appuser:appgroup /var/log/app

exec su-exec appuser:appgroup "$@"
