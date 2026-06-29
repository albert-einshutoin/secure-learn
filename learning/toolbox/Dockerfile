FROM alpine:3.20

RUN apk add --no-cache \
  bash \
  bind-tools \
  curl \
  iproute2 \
  iputils \
  jq \
  lsof \
  netcat-openbsd \
  openssl \
  postgresql-client \
  procps \
  redis \
  strace \
  tcpdump \
  util-linux \
  && addgroup -g 10002 -S learner \
  && adduser -S learner -u 10002 -G learner

USER learner
WORKDIR /home/learner

CMD ["sleep", "infinity"]
