

deps:
	go get -u github.com/golang/dep/cmd/dep
	dep ensure

generate:
	go get -u github.com/jteeuwen/go-bindata/...
	go-bindata -o test/bindata.go -pkg test test/data test/kolide/... test/delegation/... test/mirror/...

test: generate
	go test -race -cover -v $(shell go list ./... | grep -v /vendor/)
