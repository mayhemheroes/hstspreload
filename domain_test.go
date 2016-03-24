package hstspreload

import (
	"os"
	"testing"
)

func testCheckDomainCaseExpectingSuccess(t *testing.T, domain string) {
	err := CheckDomain(domain)

	if err != nil {
		t.Errorf("Domain (%s) should succeed. Error encountered: [%s]", domain, err)
		return
	}
}
func testCheckDomainCaseExpectingError(t *testing.T, domain string, errorString string) {
	err := CheckDomain(domain)

	if err == nil {
		t.Errorf("Domain check should fail with an error.")
		return
	}

	if errorString != err.Error() {
		t.Errorf(`Domain check did not fail with the correct error.
Expected error: [%s]
Actual error: [%s]`, errorString, err)
	}
}

func TestCheckDomain(t *testing.T) {
	DOMAIN_TEST := os.Getenv("DOMAIN_TEST")
	if DOMAIN_TEST != "TEST_EXTRNAL_DOMAINS" {
		// We don't have a way to mock external domains.
		// Skip these tests to support performant, deterministic, and offline testing.
		return
	}

	testCheckDomainCaseExpectingSuccess(
		t,
		"wikipedia.org",
	)

	testCheckDomainCaseExpectingError(
		t,
		"example.notadomain",
		"Cannot connect to host (example.notadomain). Error: [Get https://example.notadomain: dial tcp: lookup example.notadomain: no such host]",
	)

	testCheckDomainCaseExpectingError(
		t,
		"gmail.com",
		"Must have the `preload` directive.",
	)

	testCheckDomainCaseExpectingError(
		t,
		"example.com",
		"No HSTS headers are present on the response.",
	)
}
