ARG UBUNTU_VERSION=24.04
FROM ubuntu:${UBUNTU_VERSION}

# EOL releases (12.04/14.04/16.04) are served from old-releases.ubuntu.com;
# fall back to it when the default archive no longer carries this release.
RUN apt-get update || \
    (sed -i -e 's|http://[a-z.]*archive.ubuntu.com/ubuntu|http://old-releases.ubuntu.com/ubuntu|g' \
            -e 's|http://security.ubuntu.com/ubuntu|http://old-releases.ubuntu.com/ubuntu|g' \
        /etc/apt/sources.list && apt-get update)

RUN apt-get install -y wget iptables telnet socat openssh-server ca-certificates
RUN apt-get install -y netcat || true
RUN apt-get install -y netcat-traditional || true  # 24.04

ARG OPENPORT_VERSION=unset

# --no-check-certificate fallback: the CA store / openssl of EOL releases
# cannot validate the current openport.io certificate chain.
RUN wget https://openport.io/static/releases/openport_${OPENPORT_VERSION}-1_amd64.deb || \
    wget --no-check-certificate https://openport.io/static/releases/openport_${OPENPORT_VERSION}-1_amd64.deb

# apt on 12.04/14.04 cannot install a local .deb; use dpkg + -f there.
RUN apt-get install -y ./openport_${OPENPORT_VERSION}-1_amd64.deb || \
    (dpkg -i openport_${OPENPORT_VERSION}-1_amd64.deb || apt-get install -y -f)
