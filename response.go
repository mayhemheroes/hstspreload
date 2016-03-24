package hstspreload

import (
	"fmt"
	"net/http"
)

func CheckResponse(response *http.Response) Issues {
	issues := NewIssues()

	key := http.CanonicalHeaderKey("Strict-Transport-Security")
	hstsHeaders := response.Header[key]

	if len(hstsHeaders) == 0 {
		return issues.AddError("No HSTS headers are present on the response.")
	} else if len(hstsHeaders) > 1 {
		return issues.AddError(fmt.Sprintf("Multiple HSTS headers (number of HSTS headers: %d).", len(hstsHeaders)))
	}

	return CombineIssues(issues, CheckHeaderString(hstsHeaders[0]))
}
