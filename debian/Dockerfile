FROM debian:stretch-20200514
RUN apt-get update && \
    apt-get install -y build-essential autoconf automake autotools-dev dh-make debhelper devscripts fakeroot xutils \
        lintian pbuilder && \
    rm -rf /var/lib/apt/lists/*
