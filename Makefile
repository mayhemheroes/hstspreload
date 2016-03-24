.PHONY: test
test:
	go test -v

.PHONY: test-external-domains
test-external-domains:
	DOMAIN_TEST=TEST_EXTRNAL_DOMAINS go test -v