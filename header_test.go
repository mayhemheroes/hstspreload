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

func testParseHeaderStringCase(t *testing.T /*testCase string,*/, headerString string, hstsHeader HSTSHeader) bool {
	parsedHSTSHeader, issues := ParseHeaderString(headerString)

	expectIssuesEmpty(t, issues)

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

func testParseHeaderStringCaseExpectingError(t *testing.T /*testCase,*/, headerString string, errorString string) {
	_, issues := ParseHeaderString(headerString)

	expectIssuesEqual(t, issues, NewIssues().AddError(errorString))

	// 	if err == nil {
	// 		t.Errorf("Parsing the header [%s] should fail with an error.", headerString)
	// 		return
	// 	}

	// 	if errorString != err.Error() {
	// 		t.Errorf(`Parsing did not fail with the correct error.
	// Expected error: [%s]
	// Actual error: [%s]`, errorString, err)
	// 	}
}

func TestParseHeaderStringCaseBadMaxAgeNoValue(t *testing.T) {
	testParseHeaderStringCaseExpectingError(
		t,
		"max-age",
		"A max-age directive name is present without a value.")
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

func testCheckHeaderStringCaseExpectingSuccess(t *testing.T /*testCase,*/, headerString string) {
	_, issues := ParseHeaderString(headerString)
	expectIssuesEmpty(t, issues)
}

/******** Testing CheckHeaderString ********/

// func testCheckHeaderStringCaseExpectingError(t *testing.T, headerString string, errorString string) {
// 	issues := CheckHeaderString(headerString)

// 	expectIssuesEmpty(t, "")

// 	if err == nil {
// 		t.Errorf("Header [%s] check should fail with an error.", headerString)
// 		return
// 	}

// 	if errorString != err.Error() {
// 		t.Errorf(`Header check did not fail with the correct error.
// Expected error: [%s]
// Actual error: [%s]`, errorString, err)
// 	}
// }

func TestCheckHeaderStringGoodHeader(t *testing.T) {
	testCheckHeaderStringCaseExpectingSuccess(t,
		"includeSubDomains; preload; max-age=10886400")
}

func TestCheckHeaderStringExtraDirective(t *testing.T) {
	testCheckHeaderStringCaseExpectingSuccess(t,
		"includeSubDomains; max-age=10886400; preload; extraDirective")
}

func TestCheckHeaderStringCaseInsensitive(t *testing.T) {
	testCheckHeaderStringCaseExpectingSuccess(t,
		"PRELoad; max-age=10886400; IncludeSubDOMAIns")
}

func TestCheckHeaderStringLargerMaxAge(t *testing.T) {
	testCheckHeaderStringCaseExpectingSuccess(t,
		"includeSubDomains; preload; max-age=12345678")
}

func TestCheckHeaderStringReordered(t *testing.T) {
	testCheckHeaderStringCaseExpectingSuccess(t,
		"max-age=12345678; preload; includeSubDomains")
}

func TestCheckHeaderStringEmpty(t *testing.T) {
	expectIssuesEqual(t,
		CheckHeaderString(""),
		NewIssues().AddError("Must have the `includeSubDomains` directive."),
	)
}

func TestCheckHeaderStringMissingPreload(t *testing.T) {
	expectIssuesEqual(t,
		CheckHeaderString("includeSubDomains"),
		NewIssues().AddError("Must have the `preload` directive."),
	)
}

func TestCheckHeaderStringMissingIncludeSubdomains(t *testing.T) {
	expectIssuesEqual(t,
		CheckHeaderString("preload"),
		NewIssues().AddError("Must have the `includeSubDomains` directive."),
	)
}

func TestCheckHeaderString(t *testing.T) {
	expectIssuesEqual(t,
		CheckHeaderString("includeSubDomains; preload"),
		NewIssues().AddError("Must have the `max-age` directive."),
	)
}

// TODO: improve message for this
func TestCheckHeaderStringMaxAgeWithoutValue(t *testing.T) {
	expectIssuesEqual(t,
		CheckHeaderString("includeSubDomains; preload; max-age"),
		NewIssues().AddError("A max-age directive name is present without a value.").AddError("Must have the `max-age` directive."),
	)
}

func TestCheckHeaderStringMaxAge0(t *testing.T) {
	expectIssuesEqual(t,
		CheckHeaderString("includeSubDomains; preload; max-age=0"),
		NewIssues().AddError("The max-age must be at least 10886400 seconds (== 18 weeks), but the header had max-age=0."),
	)
}

func TestCheckHeaderStringMaxAge100(t *testing.T) {
	expectIssuesEqual(t,
		CheckHeaderString("includeSubDomains; preload; max-age=100"),
		NewIssues().AddError("The max-age must be at least 10886400 seconds (== 18 weeks), but the header had max-age=100."),
	)
}

func TestCheckHeaderStringMaxAge200(t *testing.T) {
	expectIssuesEqual(t,
		CheckHeaderString("max-age=200; preload; includeSubDomains"),
		NewIssues().AddError("The max-age must be at least 10886400 seconds (== 18 weeks), but the header had max-age=200."),
	)
}
