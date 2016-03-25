package hstspreload

import (
	"fmt"
	"net/http"
)

// Checks whether the domain passes HSTS preload requirements for Chromium.
// This includes:
//
//   - Serving a single HSTS header that passes header requirements.
//   - Using TLS settings that will not cause new problems for
//     Chromium/Chrome users.
//     - Example of a new problem: a missing intermediate certificate
//       will turn an error page from overrideable to non-overridable on
//       some mobile devices.
//
// To interpret the result, see the list of conventions in the
// documentation for `Issues`.
//
// Example usage:
//
//     issues := CheckDomain("wikipedia.org")
func CheckDomain(host string) Issues {
	issues := NewIssues()

	response, err := http.Get("https://" + host)
	if err != nil {
		// cannot continue => return early
		return issues.addError(fmt.Sprintf("Domain error: Cannot connect to host (%s). Error: [%s]", host, err))
	}

	// TODO: Verify chain conditions, check subdomains, handle redirects, etc.

	return combineIssues(issues, CheckResponse(response))
}
