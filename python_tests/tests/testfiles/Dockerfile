FROM ubuntu:21.10
RUN apt-get update
RUN apt-get install -y net-tools wget curl
RUN wget openport.io/static/releases/openport_1.3.0-1_amd64.deb
RUN wget openport.io/static/releases/openport_2.0.2-1_amd64.deb

RUN dpkg -i openport_1.3.0-1_amd64.deb

