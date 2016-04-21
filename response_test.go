package hstspreload

import (
	"fmt"
	"net/http"
	"testing"
)

func ExamplePreloadableResponse() {
	resp, err := http.Get("localhost:8080")
	if err != nil {
		header, issues := PreloadableResponse(*resp)
		fmt.Printf("Header: %s", header)
		fmt.Printf("Issues: %v", issues)
	}
}

func TestPreloadableResponseGoodHeader(t *testing.T) {
	var resp http.Response
	resp.Header = http.Header{}

	key := http.CanonicalHeaderKey("Strict-Transport-Security")
	sentHeader := "max-age=10886400; includeSubDomains; preload"
	resp.Header.Add(key, sentHeader)

	header, issues := PreloadableResponse(resp)
	if header != sentHeader {
		t.Errorf("Unexpected header response: %s", sentHeader)
	}
	expectIssuesEmpty(t, issues)
}

func TestPreloadableResponseEmpty(t *testing.T) {
	var resp http.Response
	resp.Header = http.Header{}

	key := http.CanonicalHeaderKey("Strict-Transport-Security")
	sentHeader := ""
	resp.Header.Add(key, sentHeader)

	header, issues := PreloadableResponse(resp)
	if header != sentHeader {
		t.Errorf("Unexpected header response: %s", sentHeader)
	}
	expectIssuesEqual(t, issues,
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
	sentHeader := "includeSubDomains; max-age=100"
	resp.Header.Add(key, sentHeader)

	header, issues := PreloadableResponse(resp)

	if header != sentHeader {
		t.Errorf("Unexpected header response: %s", sentHeader)
	}
	expectIssuesEqual(t, issues,
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
	sentHeader := "preload; max-age=10886400"
	resp.Header.Add(key, sentHeader)

	header, issues := PreloadableResponse(resp)

	if header != sentHeader {
		t.Errorf("Unexpected header response: %s", sentHeader)
	}
	expectIssuesEqual(t, issues,
		NewIssues().addErrorf("Header requirement error: Header must contain the `includeSubDomains` directive."),
	)
}

func TestPreloadableResponseWithoutHSTSHeaders(t *testing.T) {
	var resp http.Response
	resp.Header = http.Header{}

	_, issues := PreloadableResponse(resp)

	expectIssuesEqual(t, issues,
		NewIssues().addErrorf("Response error: No HSTS header is present on the response."),
	)
}

func TestPreloadableResponseMultipleHSTSHeaders(t *testing.T) {
	var resp http.Response
	resp.Header = http.Header{}

	key := http.CanonicalHeaderKey("Strict-Transport-Security")
	resp.Header.Add(key, "max-age=10")
	resp.Header.Add(key, "max-age=20")

	_, issues := PreloadableResponse(resp)

	expectIssuesEqual(t, issues,
		NewIssues().addErrorf("Response error: Multiple HSTS headers (number of HSTS headers: 2)."),
	)
}
