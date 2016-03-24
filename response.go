package hstspreload

import (
	"fmt"
	"net/http"
)

func CheckResponse(response *http.Response) error {
	key := http.CanonicalHeaderKey("Strict-Transport-Security")
	hstsHeaders := response.Header[key]

	if len(hstsHeaders) == 0 {
		return fmt.Errorf("No HSTS headers are present on the response.")
	} else if len(hstsHeaders) > 1 {
		return fmt.Errorf("Multiple HSTS headers (number of HSTS headers: %d).", len(hstsHeaders))
	}

	return CheckHeaderString(hstsHeaders[0])
}
