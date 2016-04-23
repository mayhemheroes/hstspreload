PROJECT = github.com/chromium/hstspreload/...

.PHONY: test
test: lint
	go test ${PROJECT}

.PHONY: build
build:
	go build ${PROJECT}

.PHONY: lint
lint:
	go vet ${PROJECT}

.PHONY: pre-commit
pre-commit: lint build test

.PHONY: travis
travis: pre-commit
