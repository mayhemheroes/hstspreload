package hstspreload

import (
	"fmt"
	"net/http"
	"testing"
)

/******** Helper functions tests. ********/

func expectNil(t *testing.T, actual *string) {
	if actual != nil {
		t.Errorf("Expected nil.")
	}
}
func expectString(t *testing.T, actual *string, expected string) {
	if actual == nil {
		t.Errorf("Expected `%s`, actual was nil.", expected)
	} else if *actual != expected {
		t.Errorf("Strings are not equal. Actual: `%s` Expected: `%s`", *actual, expected)
	}
}

/******** Response tests. ********/

func ExamplePreloadableResponse() {
	resp, err := http.Get("localhost:8080")
	if err != nil {
		header, issues := PreloadableResponse(*resp)
		fmt.Printf("Header: %s", *header)
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
	expectString(t, header, sentHeader)
	expectIssuesEmpty(t, issues)
}

func TestPreloadableResponseEmpty(t *testing.T) {
	var resp http.Response
	resp.Header = http.Header{}

	key := http.CanonicalHeaderKey("Strict-Transport-Security")
	sentHeader := ""
	resp.Header.Add(key, sentHeader)

	header, issues := PreloadableResponse(resp)
	expectString(t, header, sentHeader)
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

	expectString(t, header, sentHeader)
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

	expectString(t, header, sentHeader)
	expectIssuesEqual(t, issues,
		NewIssues().addErrorf("Header requirement error: Header must contain the `includeSubDomains` directive."),
	)
}

func TestPreloadableResponseWithoutHSTSHeaders(t *testing.T) {
	var resp http.Response
	resp.Header = http.Header{}

	header, issues := PreloadableResponse(resp)
	expectNil(t, header)

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

	header, issues := PreloadableResponse(resp)
	expectNil(t, header)

	expectIssuesEqual(t, issues,
		NewIssues().addErrorf("Response error: Multiple HSTS headers (number of HSTS headers: 2)."),
	)
}

func TestRemovableResponseNoHeader(t *testing.T) {
	var resp http.Response
	resp.Header = http.Header{}

	header, issues := RemovableResponse(resp)
	expectNil(t, header)

	expectIssuesEqual(t, issues,
		NewIssues().addErrorf("Response error: No HSTS header is present on the response."),
	)
}

func TestRemovableResponseNoPreload(t *testing.T) {
	var resp http.Response
	resp.Header = http.Header{}

	key := http.CanonicalHeaderKey("Strict-Transport-Security")
	sentHeader := "max-age=15768000; includeSubDomains"
	resp.Header.Add(key, sentHeader)

	header, issues := RemovableResponse(resp)
	expectString(t, header, sentHeader)

	expectIssuesEmpty(t, issues)
}

func TestRemovableResponsePreload(t *testing.T) {
	var resp http.Response
	resp.Header = http.Header{}

	key := http.CanonicalHeaderKey("Strict-Transport-Security")
	sentHeader := "max-age=15768000; includeSubDomains; preload"
	resp.Header.Add(key, sentHeader)

	header, issues := RemovableResponse(resp)
	expectString(t, header, sentHeader)

	expectIssuesEqual(t, issues,
		Issues{
			Errors:   []string{"Header requirement error: For preload list removal, the header must not contain the `preload` directive."},
			Warnings: []string{},
		},
	)
}

func TestRemovableResponsePreloadOnly(t *testing.T) {
	var resp http.Response
	resp.Header = http.Header{}

	key := http.CanonicalHeaderKey("Strict-Transport-Security")
	sentHeader := "preload"
	resp.Header.Add(key, sentHeader)

	header, issues := RemovableResponse(resp)
	expectString(t, header, sentHeader)

	expectIssuesEqual(t, issues,
		Issues{
			Errors: []string{
				"Header requirement error: For preload list removal, the header must not contain the `preload` directive.",
				"Header requirement error: Header must contain a valid `max-age` directive.",
			},
			Warnings: []string{},
		},
	)
}
