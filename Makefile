create-deb-full:
	./debian/docker-build-image.sh
	./debian/docker-create-exe.sh
	./debian/docker-create-deb.sh

docker-deb-bash:
	docker run -it -v $$(pwd):/apps/distribution/ jandebleser/openport-distribution bash

