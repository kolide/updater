

deps:
	go get -u github.com/golang/dep/cmd/dep
	dep ensure

generate:
	go get -u github.com/jteeuwen/go-bindata/...
	go-bindata -o test/bindata.go -pkg test test/data test/kolide/...

test: generate
	go test -v github.com/kolide/updater/tuf github.com/kolide/updater
