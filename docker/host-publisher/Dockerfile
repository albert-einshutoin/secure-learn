FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce

LABEL org.opencontainers.image.title="Secure Learn host publisher" \
      org.opencontainers.image.description="Minimal non-root TCP publisher for isolated lab networks"

RUN apk add --no-cache socat=1.8.1.3-r0 \
    && addgroup -S -g 65532 publisher \
    && adduser -S -D -H -u 65532 -G publisher publisher

USER 65532:65532
ENTRYPOINT ["/usr/bin/socat"]
