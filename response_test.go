package hstspreload

import (
	"fmt"
	"net/http"
	"testing"
)

const (
	headerStringsShouldBeEqual = `Did not receive expected header.
			Actual: "%v"
			Expected: "%v"`
)

/******** Examples. ********/

func ExamplePreloadableResponse() {
	resp, err := http.Get("localhost:8080")
	if err != nil {
		header, issues := PreloadableResponse(resp)
		fmt.Printf("Header: %s", *header)
		fmt.Printf("Issues: %v", issues)
	}
}

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

var responseTests = []struct {
	function       func(resp *http.Response) (header *string, issues Issues)
	description    string
	hstsHeaders    []string
	expectedIssues Issues
}{

	/******** PreloadableResponse() ********/

	{
		PreloadableResponse,
		"good header",
		[]string{"max-age=10886400; includeSubDomains; preload"},
		Issues{},
	},
	{
		PreloadableResponse,
		"missing preload",
		[]string{"max-age=10886400; includeSubDomains"},
		Issues{Errors: []string{"Header requirement error: Header must contain the `preload` directive."}},
	},
	{
		PreloadableResponse,
		"missing includeSubDomains",
		[]string{"preload; max-age=10886400"},
		Issues{Errors: []string{"Header requirement error: Header must contain the `includeSubDomains` directive."}},
	},
	{
		PreloadableResponse,
		"single header, multiple errors",
		[]string{"includeSubDomains; max-age=100"},
		Issues{
			Errors: []string{
				"Header requirement error: Header must contain the `preload` directive.",
				"Header requirement error: The max-age must be at least 10886400 seconds (== 18 weeks), but the header currently only has max-age=100.",
			},
		},
	},
	{
		PreloadableResponse,
		"empty header",
		[]string{""},
		Issues{
			Errors: []string{
				"Header requirement error: Header must contain the `includeSubDomains` directive.",
				"Header requirement error: Header must contain the `preload` directive.",
				"Header requirement error: Header must contain a valid `max-age` directive.",
			},
			Warnings: []string{"Syntax warning: Header is empty."},
		},
	},
	{
		PreloadableResponse,
		"missing header",
		[]string{},
		Issues{Errors: []string{"Response error: No HSTS header is present on the response."}},
	},
	{
		PreloadableResponse,
		"multiple headers",
		[]string{"max-age=10", "max-age=20", "max-age=30"},
		Issues{Errors: []string{"Response error: Multiple HSTS headers (number of HSTS headers: 3)."}},
	},

	/******** RemovableResponse() ********/

	{
		RemovableResponse,
		"no preload",
		[]string{"max-age=15768000; includeSubDomains"},
		Issues{},
	},
	{
		RemovableResponse,
		"preload present",
		[]string{"max-age=15768000; includeSubDomains; preload"},
		Issues{Errors: []string{"Header requirement error: For preload list removal, the header must not contain the `preload` directive."}},
	},
	{
		RemovableResponse,
		"preload only",
		[]string{"preload"},
		Issues{
			Errors: []string{
				"Header requirement error: For preload list removal, the header must not contain the `preload` directive.",
				"Header requirement error: Header must contain a valid `max-age` directive.",
			},
		},
	},
}

func TestPreloabableResponseAndRemovableResponse(t *testing.T) {
	for _, tt := range responseTests {

		resp := &http.Response{}
		resp.Header = http.Header{}

		key := http.CanonicalHeaderKey("Strict-Transport-Security")
		for _, h := range tt.hstsHeaders {
			resp.Header.Add(key, h)
		}

		header, issues := tt.function(resp)

		if len(tt.hstsHeaders) == 1 {
			if header == nil {
				t.Errorf("[%s] Did not receive exactly one HSTS header", tt.description)
			} else if *header != tt.hstsHeaders[0] {
				t.Errorf("[%s] "+headerStringsShouldBeEqual, tt.description, *header, tt.hstsHeaders[0])
			}
		} else {
			if header != nil {
				t.Errorf("[%s] Did not expect a header, but received `%s`", tt.description, *header)
			}
		}

		if !issuesEqual(issues, tt.expectedIssues) {
			t.Errorf("[%s] "+issuesShouldBeEqual, tt.description, issues, tt.expectedIssues)
		}
	}
}
