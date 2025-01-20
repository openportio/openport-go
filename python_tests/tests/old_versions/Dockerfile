ARG UBUNTU_VERSION=24.04
FROM ubuntu:${UBUNTU_VERSION}

RUN apt-get update && apt-get install -y wget iptables telnet socat openssh-server
RUN apt-get install -y netcat || true
RUN apt-get install -y netcat-traditional || true  # 24.04

ARG OPENPORT_VERSION=unset

RUN wget https://openport.io/static/releases/openport_${OPENPORT_VERSION}-1_amd64.deb
RUN apt-get install -y ./openport_${OPENPORT_VERSION}-1_amd64.deb


