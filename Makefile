default: test

test: export CGO_ENABLED = 0
test:
	@go test -tags netgo --count 1 -v ./...

race: export CGO_ENABLED = 1
race:
	go test -tags netgo -race --count 1 ./...

# curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.64.6
lint:
	@golangci-lint run

.PHONY: test race lint
