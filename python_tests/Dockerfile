FROM openport-go-amd64 as builder

FROM python:3.10.8-bullseye
WORKDIR /apps/openport
COPY requirements.txt /apps/openport/
RUN pip install -r requirements.txt
ENV BUILD_OPENPORT_EXE=0
ENV OPENPORT_EXE=/openport-amd64
ENV TOXI_PROXY_HOST=toxiproxy
ENV OPENPORT_TEST_HOST=openport-test
ENV SOCKS_PROXY=proxy-no-password

COPY --from=builder /openport-amd64 /openport-amd64

ADD . /apps/openport
CMD python tests/run_tests.py
