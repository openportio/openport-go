# Toolchain for building the UNSIGNED mac installer on Linux (no Apple
# tooling): xar writes the flat .pkg, mkbom its Bom, libdmg-hfsplus turns an
# hfsplus image into a UDZO .dmg, and makefat merges the darwin binaries into
# one universal binary. Everything is built from source at a pinned commit on
# the runner (same reasoning as Dockerfile-goreleaser: only docker is
# guaranteed there, and no downloaded prebuilt binaries).
#
# Same base pin as Dockerfile-goreleaser; bump them together.
FROM golang:1.27.3-bookworm

# genisoimage builds the dmg's filesystem image (-apple hybrid; hfsprogs is
# not in bookworm), cpio the pkg payload.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake autoconf automake libtool pkg-config git \
        libssl-dev zlib1g-dev libxml2-dev libbz2-dev \
        genisoimage cpio \
    && rm -rf /var/lib/apt/lists/*

# xar: the osxcross fork, the one that still builds against OpenSSL 3.
RUN git clone https://github.com/tpoechtrager/xar /tmp/xar \
    && git -C /tmp/xar checkout 5fa4675419cfec60ac19a9c7f7c2d0e7c831a497 \
    && cd /tmp/xar/xar \
    && ./autogen.sh --prefix=/usr/local \
    && make -j"$(nproc)" && make install \
    && rm -rf /tmp/xar

# bomutils: mkbom, the Bom writer the flat pkg needs.
RUN git clone https://github.com/hogliux/bomutils /tmp/bomutils \
    && git -C /tmp/bomutils checkout c247002e2f49878bab32dd0fcf805810ae0992cb \
    && make -C /tmp/bomutils -j"$(nproc)" \
    && make -C /tmp/bomutils install \
    && rm -rf /tmp/bomutils

# libdmg-hfsplus: `dmg dmg` converts the genisoimage output into a compressed
# UDZO dmg. The fanquake fork is the maintained one (Bitcoin's deterministic
# mac builds used genisoimage + this tool for exactly this).
RUN git clone https://github.com/fanquake/libdmg-hfsplus /tmp/libdmg \
    && git -C /tmp/libdmg checkout 1cc791e4173da9cb0b0cc16c5a1aaa25d5eb5efa \
    && cmake -S /tmp/libdmg -B /tmp/libdmg/build \
    && make -C /tmp/libdmg/build -j"$(nproc)" dmg-bin \
    && install -m755 /tmp/libdmg/build/dmg/dmg /usr/local/bin/ \
    && rm -rf /tmp/libdmg

# makefat: merges the darwin amd64 + arm64 binaries into one universal binary.
ENV GOBIN=/usr/local/bin
RUN go install github.com/randall77/makefat@1b91746796b794d1ea6b5d6c3c8c0f0b8ad1c93a \
    && go clean -cache -modcache

WORKDIR /repo
