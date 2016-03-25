.PHONY: test
test: lint
	go test -v -short

.PHONY: test-all
test-all: lint
	go test -v

.PHONY: lint
lint:
	go vet