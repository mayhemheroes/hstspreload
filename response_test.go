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

	err := CheckResponse(&response)

	if err != nil {
		t.Errorf("Header check should succeed. Error encountered: [%s]", err)
		return
	}
}

func testCheckResponseCaseExpectingError(t *testing.T, response http.Response, errorString string) {
	err := CheckResponse(&response)

	if err == nil {
		t.Errorf("Header check should fail with an error.")
		return
	}

	if errorString != err.Error() {
		t.Errorf(`Header check did not fail with the correct error.
Expected error: [%s]
Actual error: [%s]`, errorString, err)
	}
}

func TestCheckResponseMissingIncludeSubDomains(t *testing.T) {
	var response http.Response
	response.Header = http.Header{}

	key := http.CanonicalHeaderKey("Strict-Transport-Security")
	response.Header.Add(key, "preload; max-age=100")

	testCheckResponseCaseExpectingError(
		t,
		response,
		"Must have the `includeSubDomains` directive.",
	)
}

func TestCheckResponseWithoutHSTSHeaders(t *testing.T) {
	var response http.Response
	response.Header = http.Header{}

	testCheckResponseCaseExpectingError(
		t,
		response,
		"No HSTS headers are present on the response.",
	)
}

func TestCheckResponseMultipleHSTSHeaders(t *testing.T) {
	var response http.Response
	response.Header = http.Header{}

	key := http.CanonicalHeaderKey("Strict-Transport-Security")
	response.Header.Add(key, "max-age=10")
	response.Header.Add(key, "max-age=20")

	testCheckResponseCaseExpectingError(
		t,
		response,
		"Multiple HSTS headers (number of HSTS headers: 2).",
	)
}
