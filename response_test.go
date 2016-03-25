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

func TestCheckResponseEmpty(t *testing.T) {
	var response http.Response
	response.Header = http.Header{}

	key := http.CanonicalHeaderKey("Strict-Transport-Security")
	response.Header.Add(key, "")

	expectIssuesEqual(t, CheckResponse(&response),
		Issues{
			Errors: []string{
				"Header requirement error: Header must contain the `includeSubDomains` directive.",
				"Header requirement error: Header must contain the `preload` directive.",
				"Header requirement error: Header must contain a valid `max-age` directive.",
			},
			Warnings: []string{"Syntax warning: Header is empty."},
		},
	)
}

func TestCheckResponseMultipleErrors(t *testing.T) {
	var response http.Response
	response.Header = http.Header{}

	key := http.CanonicalHeaderKey("Strict-Transport-Security")
	response.Header.Add(key, "includeSubDomains; max-age=100")

	expectIssuesEqual(t, CheckResponse(&response),
		Issues{
			Errors: []string{
				"Header requirement error: Header must contain the `preload` directive.",
				"Header requirement error: The max-age must be at least 10886400 seconds (== 18 weeks), but the header only had max-age=100.",
			},
			Warnings: []string{},
		},
	)
}

func TestCheckResponseMissingIncludeSubDomains(t *testing.T) {
	var response http.Response
	response.Header = http.Header{}

	key := http.CanonicalHeaderKey("Strict-Transport-Security")
	response.Header.Add(key, "preload; max-age=10886400")

	expectIssuesEqual(t, CheckResponse(&response),
		NewIssues().addError("Header requirement error: Header must contain the `includeSubDomains` directive."),
	)
}

func TestCheckResponseWithoutHSTSHeaders(t *testing.T) {
	var response http.Response
	response.Header = http.Header{}

	expectIssuesEqual(t, CheckResponse(&response),
		NewIssues().addError("Response error: No HSTS headers are present on the response."),
	)
}

func TestCheckResponseMultipleHSTSHeaders(t *testing.T) {
	var response http.Response
	response.Header = http.Header{}

	key := http.CanonicalHeaderKey("Strict-Transport-Security")
	response.Header.Add(key, "max-age=10")
	response.Header.Add(key, "max-age=20")

	expectIssuesEqual(t, CheckResponse(&response),
		NewIssues().addError("Response error: Multiple HSTS headers (number of HSTS headers: 2)."),
	)
}
