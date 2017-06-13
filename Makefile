

generate:
	go get -u github.com/jteeuwen/go-bindata/...
	go-bindata -o test/bindata.go -pkg test test/data/

test: generate
	go test github.com/kolide/updater
