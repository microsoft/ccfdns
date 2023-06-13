# syntax=docker/dockerfile:1
# FROM node:12-alpine
FROM alpine:3.16.0

RUN apk add --no-cache python3 g++ curl libcurl openssl python3 py3-pip py3-openssl ovmf openssh-client

RUN apk update \
  && apk add --no-cache --upgrade sudo bash sed mc htop openssh-server \
  && apk add --no-cache --upgrade iputils paris-traceroute perl-net-telnet bind-tools iperf nmap \
  && rm -rf /var/lib/{cache,log}/ \
  && rm -rf /var/lib/apt/lists/*.lz4 \
  && rm -rf /var/log/* \
  && rm -rf /tmp/* /var/tmp/* \
  && rm -rf /usr/share/doc/ \
  && rm -rf /usr/share/man/ \
  && rm -rf /var/cache/apk/* \
  && ssh-keygen -A

# For VSCode
# RUN apk add gcompat libstdc++ curl bash git musl libgcc

COPY authorized_keys /root/.ssh/
RUN chmod 0700 /root/.ssh/
RUN chmod 0600 /root/.ssh/authorized_keys

WORKDIR /app
COPY run.sh .
COPY service.py .
COPY requirements.txt .
RUN chmod +x /app/run.sh
COPY service.cpp .

EXPOSE 22/tcp
CMD ["/app/run.sh"]