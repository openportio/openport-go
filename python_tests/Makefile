build:
	../docker_compile.sh
	docker build -f Dockerfile -t openport-test .

test: build
	INTERACTIVE:=$(shell [ -t 0 ] && echo "-t")
	docker run -i $INTERACTIVE -v $$(pwd):/apps/openport -v $$(pwd)/../test-results/:/test-results/ openport-test

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
