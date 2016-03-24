.PHONY: test
test:
	go test -v -short

.PHONY: test-all
test-all:
	go test -v