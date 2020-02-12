ARG FROMIMAGE=python:2.7.17-stretch
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
python-dev \
python-pip \
python-virtualenv \
libsqlite3-dev \
&& apt-get -y install \
python-dev \
libffi-dev \
libssl-dev \
git \
&& rm -rf /var/lib/apt/lists/*
RUN useradd docker
RUN pip install setuptools==19.2
COPY ./requirements.dist.txt /apps/distribution/
RUN pip install -r requirements.dist.txt
RUN pip install git+https://github.com/openportio/openport
