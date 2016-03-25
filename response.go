package hstspreload

import (
	"fmt"
	"net/http"
)

func CheckResponse(response *http.Response) Issues {
	issues := NewIssues()

	key := http.CanonicalHeaderKey("Strict-Transport-Security")
	hstsHeaders := response.Header[key]

	switch {
	case len(hstsHeaders) == 0:
		return issues.addError("Response error: No HSTS headers are present on the response.")

	case len(hstsHeaders) > 1:
		// TODO: Give feedback on the first(last?) HSTS header?
		return issues.addError(fmt.Sprintf("Response error: Multiple HSTS headers (number of HSTS headers: %d).", len(hstsHeaders)))
	}

	return CombineIssues(issues, CheckHeaderString(hstsHeaders[0]))
}
