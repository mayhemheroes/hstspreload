package hstspreload

import (
	"fmt"
	"net/http"
)

func CheckDomain(host string) error {
	response, err := http.Get("https://" + host)
	if err != nil {
		return fmt.Errorf("Cannot connect to host (%s). Error: [%s]", host, err)
	}

  // TODO: Verify chain conditions, check subdomains, handle redirects, etc.

	return CheckResponse(response)
}
