INTERACTIVE:=$(shell [ -t 0 ] && echo "-t")

build:
	../docker_compile.sh
	docker build -f Dockerfile -t openport-test .

test: build
	GID=$(id -g) docker compose -f docker-compose/docker-compose-test.yaml up --build --abort-on-container-exit

bash-test:
	docker run -it -v $$(pwd):/apps/openport openport-test bash

build-docker:
	docker build -t jandebleser/openport .

run-proxy-test:
	docker compose -f ./docker-compose/proxy-test.yaml run openport

run-proxy-test-go:
	docker compose -f ./docker-compose/proxy-test.yaml run openport-go

run-proxy-test-go-no-password:
	docker compose -f ./docker-compose/proxy-test-no-password.yaml run openport-go

start_dev_servers:
	docker compose -f ./docker-compose/docker-compose-test.yaml up proxy-no-password toxiproxy

update_requirements:
	pip freeze > requirements.txt
	pip uninstall -r requirements.txt -y
	pip install -r requirements.in
	pip freeze > requirements.txt

install:
	pip install -r requirements.in

install_frozen:
	pip install -r requirements.txt