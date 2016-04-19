.PHONY: test
test: lint
	go test github.com/chromium/hstspreload
	go test github.com/chromium/hstspreload/chromiumpreload

.PHONY: test-travis
test-travis: lint
	go test github.com/chromium/hstspreload -v
	go test github.com/chromium/hstspreload/chromiumpreload -v

.PHONY: test-build
test-build:
	go build -o /dev/null github.com/chromium/hstspreload/cmd/hstspreload/
	go build -o /dev/null github.com/chromium/hstspreload/cmd/transport_security_state_static_generate/
	go build -o /dev/null github.com/chromium/hstspreload/hstspreload.appspot.com/

# Travis CI can't pipe to /dev/null
.PHONY: test-build-travis
test-build-travis:
	go build -o temp1 github.com/chromium/hstspreload/cmd/hstspreload/
	go build -o temp2 github.com/chromium/hstspreload/cmd/transport_security_state_static_generate/
	go build -o temp3 github.com/chromium/hstspreload/hstspreload.appspot.com/

.PHONY: lint
lint:
	go vet

.PHONY: hooks
hooks: .git/hooks/pre-commit