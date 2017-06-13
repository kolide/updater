

generate:
	go get -u github.com/jteeuwen/go-bindata/...
	go-bindata -o test/bindata.go -pkg test test/data/

test: generate
	go test -v github.com/kolide/updater/tuf
