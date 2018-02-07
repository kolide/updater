deps:
	go get -u github.com/golang/dep/cmd/dep
	go get -u github.com/kolide/go-bindata/...
	dep ensure
	go-bindata -o test/bindata.go -pkg test test/data test/kolide/... test/delegation/... test/mirror/...

test:
	go test -race -cover -v $(shell go list ./... | grep -v /vendor/)
