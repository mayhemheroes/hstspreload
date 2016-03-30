package hstspreload

import (
	"fmt"
	"net/http"
	"testing"
)

func ExampleCheckResponse() {
	resp, err := http.Get("localhost:8080")
	if err != nil {
		issues := CheckResponse(*resp)
		fmt.Printf("%v", issues)
	}
}

func TestCheckResponseGoodHeader(t *testing.T) {
	var resp http.Response
	resp.Header = http.Header{}

	key := http.CanonicalHeaderKey("Strict-Transport-Security")
	resp.Header.Add(key, "max-age=10886400; includeSubDomains; preload")

	expectIssuesEmpty(t, CheckResponse(resp))
}

func TestCheckResponseEmpty(t *testing.T) {
	var resp http.Response
	resp.Header = http.Header{}

	key := http.CanonicalHeaderKey("Strict-Transport-Security")
	resp.Header.Add(key, "")

	expectIssuesEqual(t, CheckResponse(resp),
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
	var resp http.Response
	resp.Header = http.Header{}

	key := http.CanonicalHeaderKey("Strict-Transport-Security")
	resp.Header.Add(key, "includeSubDomains; max-age=100")

	expectIssuesEqual(t, CheckResponse(resp),
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
	var resp http.Response
	resp.Header = http.Header{}

	key := http.CanonicalHeaderKey("Strict-Transport-Security")
	resp.Header.Add(key, "preload; max-age=10886400")

	expectIssuesEqual(t, CheckResponse(resp),
		NewIssues().addErrorf("Header requirement error: Header must contain the `includeSubDomains` directive."),
	)
}

func TestCheckResponseWithoutHSTSHeaders(t *testing.T) {
	var resp http.Response
	resp.Header = http.Header{}

	expectIssuesEqual(t, CheckResponse(resp),
		NewIssues().addErrorf("Response error: No HSTS header is present on the response."),
	)
}

func TestCheckResponseMultipleHSTSHeaders(t *testing.T) {
	var resp http.Response
	resp.Header = http.Header{}

	key := http.CanonicalHeaderKey("Strict-Transport-Security")
	resp.Header.Add(key, "max-age=10")
	resp.Header.Add(key, "max-age=20")

	expectIssuesEqual(t, CheckResponse(resp),
		NewIssues().addErrorf("Response error: Multiple HSTS headers (number of HSTS headers: 2)."),
	)
}
