package hstspreload

import (
	"testing"
)

func TestCheckDomain(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping domain tests for performant, deterministic, and offline testing.")
	}

	expectIssuesEmpty(t, "Domain: wikipedia.org", CheckDomain("wikipedia.org"))

	expectIssuesEqual(t, "Domain: example.notadomain", CheckDomain("example.notadomain"),
		NewIssues().AddError("Cannot connect to host (example.notadomain). Error: [Get https://example.notadomain: dial tcp: lookup example.notadomain: no such host]"))

	expectIssuesEqual(t, "Domain: example.com", CheckDomain("example.com"),
		NewIssues().AddError("No HSTS headers are present on the response."))
}
