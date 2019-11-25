FROM ubuntu:16.04
MAINTAINER JanDeBleser

ENV LANG C.UTF-8

RUN apt-get update; apt-get install -y software-properties-common python-software-properties
RUN add-apt-repository ppa:gophers/archive
RUN apt-get update
RUN apt-get install -y golang-1.10-go git
RUN mkdir /root/.openport/
RUN ssh-keygen -q -t rsa -N '' -f /root/.openport/id_rsa

WORKDIR /apps/sshserver

ENV PATH=$PATH:/usr/lib/go-1.10/bin
ENV GOPATH=/apps/
ENV GOBIN=$GOPATH/bin
RUN go version
ADD OpenportClient.go /apps/sshserver/
RUN go get
