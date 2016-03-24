package hstspreload

import (
	"testing"
)

func TestHeadersEqual(t *testing.T) {
	if !headersEqual(
		HSTSHeader{preload: false, includeSubDomains: true, maxAgePresent: true, maxAgeSeconds: 12345},
		HSTSHeader{preload: false, includeSubDomains: true, maxAgePresent: true, maxAgeSeconds: 12345},
	) {
		t.Errorf("HSTSHeader structs should be considered equal if all values match.")
	}

	if headersEqual(
		HSTSHeader{preload: false, includeSubDomains: true, maxAgePresent: true, maxAgeSeconds: 12345},
		HSTSHeader{preload: true, includeSubDomains: true, maxAgePresent: true, maxAgeSeconds: 12345},
	) {
		t.Errorf("HSTSHeader structs should be considered non-equal if preload values don't match.")
	}

	if !headersEqual(
		HSTSHeader{preload: false, includeSubDomains: true, maxAgePresent: false, maxAgeSeconds: 9999},
		HSTSHeader{preload: false, includeSubDomains: true, maxAgePresent: false, maxAgeSeconds: 2},
	) {
		t.Errorf("HSTSHeader struct comparison should ignore maxAgeSeconds if maxAgePresent is false.")
	}
}

/******** Testing ParseHeaderString() ********/

func testParseHeaderStringCase(t *testing.T, headerString string, hstsHeader HSTSHeader) bool {
	parsedHSTSHeader, err := ParseHeaderString(headerString)

	if err != nil {
		t.Errorf("Parsing header [%s] failed with error [%s].", headerString, err)
		return false
	}

	if !headersEqual(parsedHSTSHeader, hstsHeader) {
		t.Errorf(`Header [%s] did not match expected value after parsing.
			Expected: %v,
			Actual: %v`, headerString, hstsHeader, parsedHSTSHeader)
		return false
	}

	return true
}

func TestParseHeaderStringBlank(t *testing.T) {
	expected := HSTSHeader{
		preload:           false,
		includeSubDomains: false,
		maxAgePresent:     false,
		maxAgeSeconds:     BOGUS_MAX_AGE,
	}

	if !testParseHeaderStringCase(t,
		"", expected) {
		t.Errorf("Blank header should parse successfully.")
	}
}

func TestParseHeaderStringMissingPreload(t *testing.T) {
	expected := HSTSHeader{
		preload:           false,
		includeSubDomains: true,
		maxAgePresent:     true,
		maxAgeSeconds:     1337,
	}

	if !testParseHeaderStringCase(t,
		"includeSubDomains; max-age=1337", expected) {
		t.Errorf("Header missing preload directive should parse successfully.")
	}
}

func TestParseHeaderStringMissingIncludeSubDomains(t *testing.T) {
	expected := HSTSHeader{
		preload:           true,
		includeSubDomains: false,
		maxAgePresent:     true,
		maxAgeSeconds:     1337,
	}

	if !testParseHeaderStringCase(t,
		"preload; max-age=1337", expected) {
		t.Errorf("Header missing includeSubDomains directive should parse successfully.")
	}
}
func TestParseHeaderStringMissingMaxAge(t *testing.T) {
	expected := HSTSHeader{
		preload:           true,
		includeSubDomains: true,
		maxAgePresent:     false,
		maxAgeSeconds:     BOGUS_MAX_AGE,
	}

	if !testParseHeaderStringCase(t,
		"preload; includeSubDomains", expected) {
		t.Errorf("Header missing max-age directive should parse successfully.")
	}
}

func TestParseHeaderStringFull(t *testing.T) {
	expected := HSTSHeader{
		preload:           true,
		includeSubDomains: true,
		maxAgePresent:     true,
		maxAgeSeconds:     10886400,
	}

	if !testParseHeaderStringCase(t,
		"max-age=10886400; includeSubDomains; preload", expected) {
		t.Errorf("Header with all values present should parse successfully.")
	}
}

func TestParseHeaderStringAnyOrder(t *testing.T) {
	expected := HSTSHeader{
		preload:           true,
		includeSubDomains: true,
		maxAgePresent:     true,
		maxAgeSeconds:     4321,
	}

	if !testParseHeaderStringCase(t,
		"includeSubDomains; preload; max-age=4321", expected) {
		t.Errorf("Header parsing should allow any order of directives.")
	}
}

func TestParseHeaderStringCaseInsensitive(t *testing.T) {
	expected := HSTSHeader{
		preload:           false,
		includeSubDomains: true,
		maxAgePresent:     true,
		maxAgeSeconds:     10,
	}

	if !testParseHeaderStringCase(t,
		"inCLUDESUBDomaINs; max-AGe=10", expected) {
		t.Errorf("Header parsing should ignore case.")
	}
}

func TestParseHeaderStringTrailingSemicolon(t *testing.T) {
	expected := HSTSHeader{
		preload:           true,
		includeSubDomains: true,
		maxAgePresent:     true,
		maxAgeSeconds:     10886400,
	}

	if !testParseHeaderStringCase(t,
		"max-age=10886400; includeSubDomains; preload;", expected) {
		t.Errorf("Header trailing semicolon should parse successfully.")
		// TODO: This should actually issue a warning.
	}
}

func TestParseHeaderStringExtraDirectives(t *testing.T) {
	expected := HSTSHeader{
		preload:           true,
		includeSubDomains: true,
		maxAgePresent:     true,
		maxAgeSeconds:     10886400,
	}

	if !testParseHeaderStringCase(t,
		"max-age=10886400; extra; includeSubDomains; directives; preload", expected) {
		t.Errorf("Header with extra directives should parse successfully.")
	}
}

func TestParseHeaderStringExtraWhitespace(t *testing.T) {
	expected := HSTSHeader{
		preload:           true,
		includeSubDomains: true,
		maxAgePresent:     true,
		maxAgeSeconds:     10886400,
	}

	if !testParseHeaderStringCase(t,
		"   max-age=10886400  ;     includeSubDomains    ;     preload      ", expected) {
		t.Errorf("Header with extra whitespace should parse successfully.")
	}
}

func testParseHeaderStringCaseExpectingError(t *testing.T, headerString string, errorString string) {
	_, err := ParseHeaderString(headerString)

	if err == nil {
		t.Errorf("Parsing the header [%s] should fail with an error.", headerString)
		return
	}

	if errorString != err.Error() {
		t.Errorf(`Parsing did not fail with the correct error.
Expected error: [%s]
Actual error: [%s]`, errorString, err)
	}
}

func TestParseHeaderStringCaseBadMaxAgeNoValue(t *testing.T) {
	testParseHeaderStringCaseExpectingError(
		t,
		"max-age",
		"The max-age directive name is present without a value.")
}

// Motivated by https://crbug.com/596561
func TestParseHeaderStringCaseBadMaxAgeMinus(t *testing.T) {
	testParseHeaderStringCaseExpectingError(
		t,
		"max-age=-101",
		"Could not parse max-age value [-101].")
}

// Motivated by https://crbug.com/596561
func TestParseHeaderStringCaseBadMaxAgePlus(t *testing.T) {
	testParseHeaderStringCaseExpectingError(
		t,
		"max-age=+101",
		"Could not parse max-age value [+101].")
}

func testCheckHeaderStringCaseExpectingSuccess(t *testing.T, headerString string) {
	_, err := ParseHeaderString(headerString)

	if err != nil {
		t.Errorf("Expected header [%s] to pass the check.", headerString)
	}
}

/******** Testing CheckHeaderString ********/

func testCheckHeaderStringCaseExpectingError(t *testing.T, headerString string, errorString string) {
	err := CheckHeaderString(headerString)

	if err == nil {
		t.Errorf("Header [%s] check should fail with an error.", headerString)
		return
	}

	if errorString != err.Error() {
		t.Errorf(`Header check did not fail with the correct error.
Expected error: [%s]
Actual error: [%s]`, errorString, err)
	}
}

func TestCheckHeaderString(t *testing.T) {
	testCheckHeaderStringCaseExpectingSuccess(t,
		"includeSubDomains; preload; max-age=10886400")
	testCheckHeaderStringCaseExpectingSuccess(t,
		"includeSubDomains; max-age=10886400; preload; extraDirective")
	testCheckHeaderStringCaseExpectingSuccess(t,
		"PRELoad; max-age=10886400; IncludeSubDOMAIns")
	testCheckHeaderStringCaseExpectingSuccess(t,
		"includeSubDomains; preload; max-age=12345678")
	testCheckHeaderStringCaseExpectingSuccess(t,
		"max-age=12345678; preload; includeSubDomains")

	testCheckHeaderStringCaseExpectingError(t,
		"includeSubDomains",
		"Must have the `preload` directive.",
	)

	testCheckHeaderStringCaseExpectingError(t,
		"preload",
		"Must have the `includeSubDomains` directive.",
	)

	testCheckHeaderStringCaseExpectingError(t,
		"includeSubDomains; preload",
		"Must have the `max-age` directive.",
	)

	testCheckHeaderStringCaseExpectingError(t,
		"includeSubDomains; preload; max-age",
		"Error parsing HSTS header.",
	)

	testCheckHeaderStringCaseExpectingError(t,
		"includeSubDomains; preload; max-age=0",
		"The max-age must be at least 10886400 seconds (== 18 weeks). The header had max-age=0",
	)

	testCheckHeaderStringCaseExpectingError(t,
		"includeSubDomains; preload; max-age=100",
		"The max-age must be at least 10886400 seconds (== 18 weeks). The header had max-age=100",
	)

	testCheckHeaderStringCaseExpectingError(t,
		"max-age=200; preload; includeSubDomains",
		"The max-age must be at least 10886400 seconds (== 18 weeks). The header had max-age=200",
	)

}
