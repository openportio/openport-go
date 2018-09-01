#!/bin/bash
set -ex

docker run -it -v $(pwd)/..:/apps/distribution/ jandebleser/openport-distribution ./debian/docker/create_deb.sh

#docker exec -it docker-openport sudo -u docker ./scripts/create_exes.sh --no-gui
#docker exec -it docker-openport ./scripts/dist/openport/openport --list  # creates openport/alembic/versions/*.pyc files
#docker exec -it docker-openport bash -ex ./scripts/distribution/debian/createdeb.sh --no-gui
#docker exec -it docker-openport bash -c "dpkg -i ./scripts/distribution/debian/*.deb"
#docker exec -it docker-openport openport 22
