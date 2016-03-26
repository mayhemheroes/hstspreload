.PHONY: test
test: lint
	go test

.PHONY: test-build
test-build:
	go build -o /dev/null ./cmd/hstspreload/
	go build -o /dev/null ./cmd/transport_security_state_static_generate/
	go build -o /dev/null ./hstspreload.appspot.com/

# Travis CI can't pipe to /dev/null
.PHONY: test-build-travis
test-build-travis:
	go build -o temp1 ./cmd/hstspreload/
	go build -o temp2 ./cmd/transport_security_state_static_generate/
	go build -o temp3 ./hstspreload.appspot.com/

.PHONY: lint
lint:
	go vet

.PHONY: hooks
hooks: .git/hooks/pre-commit