package hstspreload

import (
	"fmt"
	"net/http"
	"testing"
)

func ExamplePreloadableResponse() {
	resp, err := http.Get("localhost:8080")
	if err != nil {
		issues := PreloadableResponse(*resp)
		fmt.Printf("%v", issues)
	}
}

func TestPreloadableResponseGoodHeader(t *testing.T) {
	var resp http.Response
	resp.Header = http.Header{}

	key := http.CanonicalHeaderKey("Strict-Transport-Security")
	resp.Header.Add(key, "max-age=10886400; includeSubDomains; preload")

	expectIssuesEmpty(t, PreloadableResponse(resp))
}

func TestPreloadableResponseEmpty(t *testing.T) {
	var resp http.Response
	resp.Header = http.Header{}

	key := http.CanonicalHeaderKey("Strict-Transport-Security")
	resp.Header.Add(key, "")

	expectIssuesEqual(t, PreloadableResponse(resp),
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

func TestPreloadableResponseMultipleErrors(t *testing.T) {
	var resp http.Response
	resp.Header = http.Header{}

	key := http.CanonicalHeaderKey("Strict-Transport-Security")
	resp.Header.Add(key, "includeSubDomains; max-age=100")

	expectIssuesEqual(t, PreloadableResponse(resp),
		Issues{
			Errors: []string{
				"Header requirement error: Header must contain the `preload` directive.",
				"Header requirement error: The max-age must be at least 10886400 seconds (== 18 weeks), but the header currently only has max-age=100.",
			},
			Warnings: []string{},
		},
	)
}

func TestPreloadableResponseMissingIncludeSubDomains(t *testing.T) {
	var resp http.Response
	resp.Header = http.Header{}

	key := http.CanonicalHeaderKey("Strict-Transport-Security")
	resp.Header.Add(key, "preload; max-age=10886400")

	expectIssuesEqual(t, PreloadableResponse(resp),
		NewIssues().addErrorf("Header requirement error: Header must contain the `includeSubDomains` directive."),
	)
}

func TestPreloadableResponseWithoutHSTSHeaders(t *testing.T) {
	var resp http.Response
	resp.Header = http.Header{}

	expectIssuesEqual(t, PreloadableResponse(resp),
		NewIssues().addErrorf("Response error: No HSTS header is present on the response."),
	)
}

func TestPreloadableResponseMultipleHSTSHeaders(t *testing.T) {
	var resp http.Response
	resp.Header = http.Header{}

	key := http.CanonicalHeaderKey("Strict-Transport-Security")
	resp.Header.Add(key, "max-age=10")
	resp.Header.Add(key, "max-age=20")

	expectIssuesEqual(t, PreloadableResponse(resp),
		NewIssues().addErrorf("Response error: Multiple HSTS headers (number of HSTS headers: 2)."),
	)
}
