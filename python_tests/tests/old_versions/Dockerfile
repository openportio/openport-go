FROM ubuntu:22.04

ARG OPENPORT_VERSION=unset

RUN apt-get update
RUN apt-get install -y wget iptables netcat telnet socat
RUN wget https://openport.io/static/releases/openport_${OPENPORT_VERSION}-1_amd64.deb
RUN apt-get install -y ./openport_${OPENPORT_VERSION}-1_amd64.deb


