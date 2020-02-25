ARG FROMIMAGE=python:3.6.10-stretch
FROM $FROMIMAGE
WORKDIR /apps/distribution
RUN apt-get update && apt-get install -y \
sudo \
build-essential \
autoconf \
automake \
autotools-dev \
dh-make \
debhelper \
devscripts \
fakeroot \
xutils \
lintian \
pbuilder \
python3-dev \
python3-pip \
python3-virtualenv \
libsqlite3-dev \
libffi-dev \
libssl-dev \
git \
&& rm -rf /var/lib/apt/lists/*
RUN useradd docker
COPY ./requirements.dist.txt /apps/distribution/
RUN pip install -r requirements.dist.txt
#RUN pip install git+https://github.com/openportio/openport
