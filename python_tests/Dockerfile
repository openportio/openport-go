FROM openport-go-amd64 AS builder

FROM python:3.12.7-bullseye
WORKDIR /apps/openport
COPY requirements.txt /apps/openport/
RUN pip install -r requirements.txt
ENV BUILD_OPENPORT_EXE=0
ENV OPENPORT_EXE=/openport-amd64
ENV TOXI_PROXY_HOST=toxiproxy
ENV OPENPORT_TEST_HOST=openport-test
ENV SOCKS_PROXY=proxy-no-password

COPY --from=builder /openport-amd64 /openport-amd64
RUN chown $UID:$GID /apps/openport -R
USER $UID:$GID

ADD . /apps/openport
CMD python -m pytest --junit-xml /test-results/results.xml --ignore tests/old_versions/ tests || true