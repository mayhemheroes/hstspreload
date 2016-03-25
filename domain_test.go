package hstspreload

import (
	"testing"
)

// Avoid hitting the network for short tests.
// This gives us performant, deterministic, and offline testing.
func skipIfShort(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping domain test.")
	}
}

func TestCheckDomainWithValidHSTS(t *testing.T) {
	skipIfShort(t)
	expectIssuesEmpty(t, CheckDomain("wikipedia.org"))
}

func TestCheckDomainWithoutHSTS(t *testing.T) {
	skipIfShort(t)
	expectIssuesEqual(t, CheckDomain("example.com"),
		NewIssues().AddError("Response error: No HSTS headers are present on the response."))
}

func TestCheckDomainBogusDomain(t *testing.T) {
	skipIfShort(t)
	expectIssuesEqual(t, CheckDomain("example.notadomain"),
		NewIssues().AddError("Domain error: Cannot connect to host (example.notadomain). Error: [Get https://example.notadomain: dial tcp: lookup example.notadomain: no such host]"))
}
