package hstspreload

import (
	"fmt"
	"net/http"
)

func CheckDomain(host string) Issues {
	issues := NewIssues()

	response, err := http.Get("https://" + host)
	if err != nil {
		// cannot continue => return early
		return issues.addError(fmt.Sprintf("Domain error: Cannot connect to host (%s). Error: [%s]", host, err))
	}

	// TODO: Verify chain conditions, check subdomains, handle redirects, etc.

	return CombineIssues(issues, CheckResponse(response))
}
