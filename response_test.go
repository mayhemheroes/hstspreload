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

func TestCheckResponseMultipleErrors(t *testing.T) {
	var response http.Response
	response.Header = http.Header{}

	key := http.CanonicalHeaderKey("Strict-Transport-Security")
	response.Header.Add(key, "includeSubdomains; max-age=100")

	expectIssuesEqual(t, CheckResponse(&response),
		Issues{
			errors: []string{
				"Header must contain the `preload` directive.",
				"The max-age must be at least 10886400 seconds (== 18 weeks), but the header only had max-age=100.",
			},
			warnings: []string{},
		},
	)
}

func TestCheckResponseMissingIncludeSubDomains(t *testing.T) {
	var response http.Response
	response.Header = http.Header{}

	key := http.CanonicalHeaderKey("Strict-Transport-Security")
	response.Header.Add(key, "preload; max-age=10886400")

	expectIssuesEqual(t, CheckResponse(&response),
		NewIssues().AddError("Header must contain the `includeSubDomains` directive."),
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
