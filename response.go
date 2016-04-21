package hstspreload

import (
	"net/http"
)

func checkSingleHeader(resp http.Response) (header *string, issues Issues) {
	key := http.CanonicalHeaderKey("Strict-Transport-Security")
	hstsHeaders := resp.Header[key]

	switch {
	case len(hstsHeaders) == 0:
		return nil, issues.addErrorf("Response error: No HSTS header is present on the response.")

	case len(hstsHeaders) > 1:
		// TODO: Give feedback on the first(last?) HSTS header?
		return nil, issues.addErrorf("Response error: Multiple HSTS headers (number of HSTS headers: %d).", len(hstsHeaders))
	}

	return &hstsHeaders[0], issues
}

// PreloadableResponse checks whether an resp has a single HSTS header that
// passes the preload requirements.
//
// Iff a single HSTS header was received, `header` contains its value, else
// `header` is `nil`.
// To interpret `issues`, see the list of conventions in the
// documentation for Issues.
func PreloadableResponse(resp http.Response) (header *string, issues Issues) {
	header, issues = checkSingleHeader(resp)
	if len(issues.Errors) > 0 {
		return nil, issues
	}

	return header, combineIssues(issues, PreloadableHeaderString(*header))
}

// RemovableResponse checks whether an resp has a single HSTS header that
// matches the requirements for removal from the HSTS preload list.
//
// Iff a single HSTS header was received, `header` contains its value, else
// `header` is `nil`.
// To interpret `issues`, see the list of conventions in the
// documentation for Issues.
func RemovableResponse(resp http.Response) (header *string, issues Issues) {
	header, issues = checkSingleHeader(resp)
	if len(issues.Errors) > 0 {
		return nil, issues
	}

	return header, combineIssues(issues, RemovableHeaderString(*header))
}
