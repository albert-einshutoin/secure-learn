FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce

# Install once while building so starting IPS mode never needs outbound package
# access. The runtime retains only iptables and Alpine's package dependencies.
RUN apk add --no-cache iptables=1.8.11-r1
