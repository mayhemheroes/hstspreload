PROJECT = github.com/chromium/hstspreload/...

.PHONY: test
test: lint
	go test ${PROJECT}

.PHONY: test-verbose
test-verbose: lint
	go test -v ${PROJECT}

.PHONY: build
build:
	go build ${PROJECT}

.PHONY: lint
lint:
	go vet ${PROJECT}
	golint ${PROJECT}

.PHONY: pre-commit
pre-commit: lint build test

.PHONY: travis
travis: lint build test-verbose
