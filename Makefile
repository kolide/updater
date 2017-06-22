

deps:
	go get -u github.com/golang/dep/cmd/dep
	dep ensure

generate:
	go get -u github.com/jteeuwen/go-bindata/...
	go-bindata -o test/bindata.go -pkg test test/data test/kolide/...

test: generate
	go test -race -cover -v $(go list ./... | grep -v /vendor/)
