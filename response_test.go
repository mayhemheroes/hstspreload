package hstspreload

import (
	"net/http"
	"testing"
)

func TestCheckResponseGoodHeader(t *testing.T) {
	var response http.Response
	response.Header = http.Header{}

	key := http.CanonicalHeaderKey("Strict-Transport-Security")
	response.Header.Add(key, "max-age=10886400; includeSubDomains; preload")

	expectIssuesEmpty(t, CheckResponse(&response))
}

func TestCheckResponseMissingPreload(t *testing.T) {
	var response http.Response
	response.Header = http.Header{}

	key := http.CanonicalHeaderKey("Strict-Transport-Security")
	response.Header.Add(key, "includeSubdomains; max-age=100")

	expectIssuesEqual(t, CheckResponse(&response),
		NewIssues().AddError("Must have the `preload` directive."),
	)
}

func TestCheckResponseMissingIncludeSubDomains(t *testing.T) {
	var response http.Response
	response.Header = http.Header{}

	key := http.CanonicalHeaderKey("Strict-Transport-Security")
	response.Header.Add(key, "preload; max-age=100")

	expectIssuesEqual(t, CheckResponse(&response),
		NewIssues().AddError("Must have the `includeSubDomains` directive."),
	)
}

func TestCheckResponseWithoutHSTSHeaders(t *testing.T) {
	var response http.Response
	response.Header = http.Header{}

	expectIssuesEqual(t, CheckResponse(&response),
		NewIssues().AddError("No HSTS headers are present on the response."),
	)
}

func TestCheckResponseMultipleHSTSHeaders(t *testing.T) {
	var response http.Response
	response.Header = http.Header{}

	key := http.CanonicalHeaderKey("Strict-Transport-Security")
	response.Header.Add(key, "max-age=10")
	response.Header.Add(key, "max-age=20")

	expectIssuesEqual(t, CheckResponse(&response),
		NewIssues().AddError("Multiple HSTS headers (number of HSTS headers: 2)."),
	)
}
