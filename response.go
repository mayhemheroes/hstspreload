package hstspreload

import (
	"net/http"
)

// CheckResponse checks whether an resp has a single HSTS header that
// passes the preload requirements.
//
// To interpret the result, see the list of conventions in the
// documentation for Issues.
func CheckResponse(resp http.Response) Issues {
	issues := NewIssues()

	key := http.CanonicalHeaderKey("Strict-Transport-Security")
	hstsHeaders := resp.Header[key]

	switch {
	case len(hstsHeaders) == 0:
		return issues.addErrorf("Response error: No HSTS headers are present on the response.")

	case len(hstsHeaders) > 1:
		// TODO: Give feedback on the first(last?) HSTS header?
		return issues.addErrorf("Response error: Multiple HSTS headers (number of HSTS headers: %d).", len(hstsHeaders))
	}

	return combineIssues(issues, CheckHeaderString(hstsHeaders[0]))
}
