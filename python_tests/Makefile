INTERACTIVE:=$(shell [ -t 0 ] && echo "-t")

build:
	../docker_compile.sh
	docker build -f Dockerfile -t openport-test .

test: build
	docker-compose -f docker-compose/docker-compose-test.yaml up --build --abort-on-container-exit

bash-test:
	docker run -it -v $$(pwd):/apps/openport openport-test bash

build-docker:
	docker build -t jandebleser/openport .

run-proxy-test:
	docker-compose -f ./docker-compose/proxy-test.yaml run openport

run-proxy-test-go:
	docker-compose -f ./docker-compose/proxy-test.yaml run openport-go

run-proxy-test-go-no-password:
	docker-compose -f ./docker-compose/proxy-test-no-password.yaml run openport-go
