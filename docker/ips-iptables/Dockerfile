FROM alpine:3.22

# Install once while building so starting IPS mode never needs outbound package
# access. The runtime retains only iptables and Alpine's package dependencies.
RUN apk add --no-cache iptables
