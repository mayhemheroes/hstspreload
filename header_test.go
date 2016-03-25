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
	_, issues := ParseHeaderString(headerString)

	expectIssuesEmpty(t, issues)

	return true
}

func expectHeadersEqual(t *testing.T, expected HSTSHeader, actual HSTSHeader) {
	if !headersEqual(actual, expected) {
		t.Errorf(`Header did not match expected value after parsing.
			Actual: %v
			Expected: %v`, actual, expected)
	}
}

func TestParseHeaderStringBlank(t *testing.T) {
	hstsHeader, issues := ParseHeaderString("")
	expectIssuesEmpty(t, issues)
	expectHeadersEqual(t, hstsHeader, HSTSHeader{
		preload:           false,
		includeSubDomains: false,
		maxAgePresent:     false,
		maxAgeSeconds:     BOGUS_MAX_AGE,
	})
}

func TestParseHeaderStringMissingPreload(t *testing.T) {
	hstsHeader, issues := ParseHeaderString("includeSubDomains; max-age=1337")
	expectIssuesEmpty(t, issues)
	expectHeadersEqual(t, hstsHeader, HSTSHeader{
		preload:           false,
		includeSubDomains: true,
		maxAgePresent:     true,
		maxAgeSeconds:     1337,
	})
}

func TestParseHeaderStringMissingIncludeSubDomains(t *testing.T) {
	hstsHeader, issues := ParseHeaderString("preload; max-age=1337")
	expectIssuesEmpty(t, issues)
	expectHeadersEqual(t, hstsHeader, HSTSHeader{
		preload:           true,
		includeSubDomains: false,
		maxAgePresent:     true,
		maxAgeSeconds:     1337,
	})
}

func TestParseHeaderStringMissingMaxAge(t *testing.T) {
	hstsHeader, issues := ParseHeaderString("preload; includeSubDomains")
	expectIssuesEmpty(t, issues)
	expectHeadersEqual(t, hstsHeader, HSTSHeader{
		preload:           true,
		includeSubDomains: true,
		maxAgePresent:     false,
		maxAgeSeconds:     BOGUS_MAX_AGE,
	})
}

func TestParseHeaderStringFull(t *testing.T) {
	hstsHeader, issues := ParseHeaderString("max-age=10886400; includeSubDomains; preload")
	expectIssuesEmpty(t, issues)
	expectHeadersEqual(t, hstsHeader, HSTSHeader{
		preload:           true,
		includeSubDomains: true,
		maxAgePresent:     true,
		maxAgeSeconds:     10886400,
	})
}

func TestParseHeaderStringAnyOrder(t *testing.T) {
	hstsHeader, issues := ParseHeaderString("includeSubDomains; preload; max-age=4321")
	expectIssuesEmpty(t, issues)
	expectHeadersEqual(t, hstsHeader, HSTSHeader{
		preload:           true,
		includeSubDomains: true,
		maxAgePresent:     true,
		maxAgeSeconds:     4321,
	})
}

func TestParseHeaderStringCaseInsensitive(t *testing.T) {
	hstsHeader, issues := ParseHeaderString("inCLUDESUBDomaINs; max-AGe=10")
	expectIssuesEmpty(t, issues)
	expectHeadersEqual(t, hstsHeader, HSTSHeader{
		preload:           false,
		includeSubDomains: true,
		maxAgePresent:     true,
		maxAgeSeconds:     10,
	})
}

func TestParseHeaderStringTrailingSemicolon(t *testing.T) {
	hstsHeader, issues := ParseHeaderString("max-age=10886400; includeSubDomains; preload;")
	expectIssuesEmpty(t, issues)
	expectHeadersEqual(t, hstsHeader, HSTSHeader{
		preload:           true,
		includeSubDomains: true,
		maxAgePresent:     true,
		maxAgeSeconds:     10886400,
	})
}

func TestParseHeaderStringExtraDirectives(t *testing.T) {
	hstsHeader, issues := ParseHeaderString("max-age=10886400; extra; includeSubDomains; directives; preload")
	expectIssuesEmpty(t, issues)
	expectHeadersEqual(t, hstsHeader, HSTSHeader{
		preload:           true,
		includeSubDomains: true,
		maxAgePresent:     true,
		maxAgeSeconds:     10886400,
	})
}

func TestParseHeaderStringExtraWhitespace(t *testing.T) {
	hstsHeader, issues := ParseHeaderString("   max-age=10886400  ;     includeSubDomains    ;     preload      ")
	expectIssuesEmpty(t, issues)
	expectHeadersEqual(t, hstsHeader, HSTSHeader{
		preload:           true,
		includeSubDomains: true,
		maxAgePresent:     true,
		maxAgeSeconds:     10886400,
	})
}

func TestParseHeaderStringCaseBadMaxAgeNoValue(t *testing.T) {
	_, issues := ParseHeaderString("max-age")
	expectIssuesEqual(t, issues,
		NewIssues().AddError("A max-age directive name is present without an associated value."))
}

// Motivated by https://crbug.com/596561
func TestParseHeaderStringCaseBadMaxAgeMinus(t *testing.T) {
	_, issues := ParseHeaderString("max-age=-101")
	expectIssuesEqual(t, issues,
		NewIssues().AddError("Could not parse max-age value [-101]."))
}

// Motivated by https://crbug.com/596561
func TestParseHeaderStringCaseBadMaxAgePlus(t *testing.T) {
	_, issues := ParseHeaderString("max-age=+101")
	expectIssuesEqual(t, issues,
		NewIssues().AddError("Could not parse max-age value [+101]."))
}

func TestCheckHeaderStringGoodHeader(t *testing.T) {
	_, issues := ParseHeaderString("includeSubDomains; preload; max-age=10886400")
	expectIssuesEmpty(t, issues)
}

func TestCheckHeaderStringExtraDirective(t *testing.T) {
	_, issues := ParseHeaderString("includeSubDomains; max-age=10886400; preload; extraDirective")
	expectIssuesEmpty(t, issues)
}

func TestCheckHeaderStringCaseInsensitive(t *testing.T) {
	_, issues := ParseHeaderString("PRELoad; max-age=10886400; IncludeSubDOMAIns")
	expectIssuesEmpty(t, issues)
}

func TestCheckHeaderStringLargerMaxAge(t *testing.T) {
	_, issues := ParseHeaderString("includeSubDomains; preload; max-age=12345678")
	expectIssuesEmpty(t, issues)
}

func TestCheckHeaderStringReordered(t *testing.T) {
	_, issues := ParseHeaderString("max-age=12345678; preload; includeSubDomains")
	expectIssuesEmpty(t, issues)
}

func TestCheckHeaderStringEmpty(t *testing.T) {
	expectIssuesEqual(t,
		CheckHeaderString(""),
		Issues{
			errors: []string{
				"Header must contain the `includeSubDomains` directive.",
				"Header must contain the `preload` directive.",
				"Header must contain a valid `max-age` directive.",
			},
			warnings: []string{},
		},
	)
}

func TestCheckHeaderStringMissingPreload(t *testing.T) {
	expectIssuesEqual(t,
		CheckHeaderString("includeSubDomains; max-age=10886400"),
		NewIssues().AddError("Header must contain the `preload` directive."),
	)
}

func TestCheckHeaderStringMissingIncludeSubdomains(t *testing.T) {
	expectIssuesEqual(t,
		CheckHeaderString("preload; max-age=10886400"),
		NewIssues().AddError("Header must contain the `includeSubDomains` directive."),
	)
}

func TestCheckHeaderStringMissingMaxAge(t *testing.T) {
	expectIssuesEqual(t,
		CheckHeaderString("includeSubDomains; preload"),
		NewIssues().AddError("Header must contain a valid `max-age` directive."),
	)
}

// TODO: improve message for this
func TestCheckHeaderStringMaxAgeWithoutValue(t *testing.T) {
	expectIssuesEqual(t,
		CheckHeaderString("includeSubDomains; preload; max-age"),
		Issues{
			errors: []string{
				"A max-age directive name is present without an associated value.",
				"Header must contain a valid `max-age` directive.",
			},
			warnings: []string{},
		},
	)
}

func TestCheckHeaderStringMaxAge0(t *testing.T) {
	// Give information about what to do if you want to remove HSTS.
	expectIssuesEqual(t,
		CheckHeaderString("includeSubDomains; preload; max-age=0"),
		NewIssues().AddError("The max-age must be at least 10886400 seconds (== 18 weeks), but the header only had max-age=0."),
	)
}

func TestCheckHeaderStringMaxAge100(t *testing.T) {
	expectIssuesEqual(t,
		CheckHeaderString("includeSubDomains; preload; max-age=100"),
		NewIssues().AddError("The max-age must be at least 10886400 seconds (== 18 weeks), but the header only had max-age=100."),
	)
}

func TestCheckHeaderStringMaxAge10886399(t *testing.T) {
	expectIssuesEqual(t,
		CheckHeaderString("max-age=10886399; preload; includeSubDomains"),
		NewIssues().AddError("The max-age must be at least 10886400 seconds (== 18 weeks), but the header only had max-age=10886399."),
	)
}
