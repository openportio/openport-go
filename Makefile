update_all_deps:
	cd src/ && go get -u ./...
	cd src/ && go mod tidy
	cd src/ && go mod vendor

