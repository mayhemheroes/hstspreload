package hstspreload

import (
	"net/http"
)

func checkSingleHeader(resp http.Response) (header string, issues Issues) {
	key := http.CanonicalHeaderKey("Strict-Transport-Security")
	hstsHeaders := resp.Header[key]

	switch {
	case len(hstsHeaders) == 0:
		return "", issues.addErrorf("Response error: No HSTS header is present on the response.")

	case len(hstsHeaders) > 1:
		// TODO: Give feedback on the first(last?) HSTS header?
		return "", issues.addErrorf("Response error: Multiple HSTS headers (number of HSTS headers: %d).", len(hstsHeaders))
	}

	return hstsHeaders[0], issues
}

// PreloadableResponse checks whether an resp has a single HSTS header that
// passes the preload requirements.
//
// To interpret the result, see the list of conventions in the
// documentation for Issues.
func PreloadableResponse(resp http.Response) Issues {
	header, issues := checkSingleHeader(resp)
	if len(issues.Errors) > 0 {
		return issues
	}

	return combineIssues(issues, PreloadableHeaderString(header))
}

// RemovableResponse checks whether an resp has a single HSTS header that
// matches the requirements for removal from the HSTS preload list.
//
// To interpret the result, see the list of conventions in the
// documentation for Issues.
func RemovableResponse(resp http.Response) Issues {
	header, issues := checkSingleHeader(resp)
	if len(issues.Errors) > 0 {
		return issues
	}

	return combineIssues(issues, RemovableHeaderString(header))
}
