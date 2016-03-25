package hstspreload

import (
	"testing"
)

func TestHeadersEqual(t *testing.T) {
	if !headersEqual(
		HSTSHeader{
			preload:           false,
			includeSubDomains: true,
			maxAgePresent:     true,
			maxAgeSeconds:     12345,
		},
		HSTSHeader{
			preload:           false,
			includeSubDomains: true,
			maxAgePresent:     true,
			maxAgeSeconds:     12345,
		},
	) {
		t.Errorf("HSTSHeader structs should be considered equal if all values match.")
	}

	if headersEqual(
		HSTSHeader{
			preload:           false,
			includeSubDomains: true,
			maxAgePresent:     true,
			maxAgeSeconds:     12345,
		},
		HSTSHeader{
			preload:           true,
			includeSubDomains: true,
			maxAgePresent:     true,
			maxAgeSeconds:     12345,
		},
	) {
		t.Errorf("HSTSHeader structs should be considered non-equal if preload values don't match.")
	}

	if !headersEqual(
		HSTSHeader{
			preload:           false,
			includeSubDomains: true,
			maxAgePresent:     false,
			maxAgeSeconds:     9999,
		},
		HSTSHeader{
			preload:           false,
			includeSubDomains: true,
			maxAgePresent:     false,
			maxAgeSeconds:     2,
		},
	) {
		t.Errorf("HSTSHeader struct comparison should ignore maxAgeSeconds if maxAgePresent is false.")
	}
}

func expectHeadersEqual(t *testing.T, expected HSTSHeader, actual HSTSHeader) {
	if !headersEqual(actual, expected) {
		t.Errorf(`Header did not match expected value after parsing.
			Actual: %v
			Expected: %v`, actual, expected)
	}
}

/******** ParseHeaderString() without issues. ********/

func TestParseHeaderStringWithoutPreload(t *testing.T) {
	hstsHeader, issues := ParseHeaderString("includeSubDomains; max-age=1337")
	expectIssuesEmpty(t, issues)
	expectHeadersEqual(t, hstsHeader, HSTSHeader{
		preload:           false,
		includeSubDomains: true,
		maxAgePresent:     true,
		maxAgeSeconds:     1337,
	})
}

func TestParseHeaderStringWithoutIncludeSubDomains(t *testing.T) {
	hstsHeader, issues := ParseHeaderString("preload; max-age=1337")
	expectIssuesEmpty(t, issues)
	expectHeadersEqual(t, hstsHeader, HSTSHeader{
		preload:           true,
		includeSubDomains: false,
		maxAgePresent:     true,
		maxAgeSeconds:     1337,
	})
}

func TestParseHeaderStringWithoutMaxAge(t *testing.T) {
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

func TestParseHeaderStringLargerMaxAge(t *testing.T) {
	hstsHeader, issues := ParseHeaderString("includeSubDomains; preload; max-age=12345678")
	expectIssuesEmpty(t, issues)
	expectHeadersEqual(t, hstsHeader, HSTSHeader{
		preload:           true,
		includeSubDomains: true,
		maxAgePresent:     true,
		maxAgeSeconds:     12345678,
	})
}

func TestParseHeaderStringReordered(t *testing.T) {
	hstsHeader, issues := ParseHeaderString("max-age=10886400; preload; includeSubDomains")
	expectIssuesEmpty(t, issues)
	expectHeadersEqual(t, hstsHeader, HSTSHeader{
		preload:           true,
		includeSubDomains: true,
		maxAgePresent:     true,
		maxAgeSeconds:     10886400,
	})
}

func TestParseHeaderStringReorderedWithoutPreload(t *testing.T) {
	hstsHeader, issues := ParseHeaderString("max-age=10886400; includeSubDomains")
	expectIssuesEmpty(t, issues)
	expectHeadersEqual(t, hstsHeader, HSTSHeader{
		preload:           false,
		includeSubDomains: true,
		maxAgePresent:     true,
		maxAgeSeconds:     10886400,
	})
}

/******** ParseHeaderString() with warnings only. ********/

func TestParseHeaderStringEmpty(t *testing.T) {
	hstsHeader, issues := ParseHeaderString("")
	expectIssuesEqual(t, issues,
		NewIssues().addWarning("Syntax warning: Header is empty."))
	expectHeadersEqual(t, hstsHeader, HSTSHeader{
		preload:           false,
		includeSubDomains: false,
		maxAgePresent:     false,
		maxAgeSeconds:     BOGUS_MAX_AGE,
	})
}

func TestParseHeaderStringCaseInsensitive(t *testing.T) {
	hstsHeader, issues := ParseHeaderString("inCLUDESUBDomaINs; max-AGe=12345678")
	expectIssuesEqual(t, issues,
		NewIssues().addWarning("Syntax warning: Header contains the token `inCLUDESUBDomaINs`. The recommended capitalization is `includeSubDomains`."))
	expectHeadersEqual(t, hstsHeader, HSTSHeader{
		preload:           false,
		includeSubDomains: true,
		maxAgePresent:     true,
		maxAgeSeconds:     12345678,
	})
}

func TestParseHeaderStringRepeatedPreload(t *testing.T) {
	hstsHeader, issues := ParseHeaderString("preload; includeSubDomains; preload; max-age=12345678; preload")
	expectIssuesEqual(t, issues,
		NewIssues().addWarning("Syntax warning: Header contains a repeated directive: `preload`"))
	expectHeadersEqual(t, hstsHeader, HSTSHeader{
		preload:           true,
		includeSubDomains: true,
		maxAgePresent:     true,
		maxAgeSeconds:     12345678,
	})
}

func TestParseHeaderStringSingleExtraDirective(t *testing.T) {
	hstsHeader, issues := ParseHeaderString("includeSubDomains; max-age=12345678; preload; extraDirective")
	expectIssuesEqual(t, issues,
		NewIssues().addWarning("Syntax warning: Header contains an unknown directive: `extraDirective`"))
	expectHeadersEqual(t, hstsHeader, HSTSHeader{
		preload:           true,
		includeSubDomains: true,
		maxAgePresent:     true,
		maxAgeSeconds:     12345678,
	})
}

func TestParseHeaderStringMultipleExtraDirectives(t *testing.T) {
	hstsHeader, issues := ParseHeaderString("max-age=12345678; extra; includeSubDomains; directives; preload")
	expectIssuesEqual(t, issues,
		Issues{
			Errors: []string{},
			Warnings: []string{
				"Syntax warning: Header contains an unknown directive: `extra`",
				"Syntax warning: Header contains an unknown directive: `directives`",
			},
		})
	expectHeadersEqual(t, hstsHeader, HSTSHeader{
		preload:           true,
		includeSubDomains: true,
		maxAgePresent:     true,
		maxAgeSeconds:     12345678,
	})
}

func TestParseHeaderStringSemicolonOnly(t *testing.T) {
	hstsHeader, issues := ParseHeaderString(";")
	expectIssuesEqual(t, issues,
		NewIssues().addWarning("Syntax warning: Header includes an empty directive or extra semicolon."))
	expectHeadersEqual(t, hstsHeader, HSTSHeader{
		preload:           false,
		includeSubDomains: false,
		maxAgePresent:     false,
		maxAgeSeconds:     BOGUS_MAX_AGE,
	})
}

func TestParseHeaderStringTrailingSemicolon(t *testing.T) {
	hstsHeader, issues := ParseHeaderString("max-age=10886400; includeSubDomains; preload;")
	expectIssuesEqual(t, issues,
		NewIssues().addWarning("Syntax warning: Header includes an empty directive or extra semicolon."))
	expectHeadersEqual(t, hstsHeader, HSTSHeader{
		preload:           true,
		includeSubDomains: true,
		maxAgePresent:     true,
		maxAgeSeconds:     10886400,
	})
}

func TestParseHeaderStringPrefixedBySemicolon(t *testing.T) {
	hstsHeader, issues := ParseHeaderString("; max-age=10886400; includeSubDomains; preload")
	expectIssuesEqual(t, issues,
		NewIssues().addWarning("Syntax warning: Header includes an empty directive or extra semicolon."))
	expectHeadersEqual(t, hstsHeader, HSTSHeader{
		preload:           true,
		includeSubDomains: true,
		maxAgePresent:     true,
		maxAgeSeconds:     10886400,
	})
}

/******** ParseHeaderString() with only errors. ********/

func TestParseHeaderStringBadMaxAgeNoValue(t *testing.T) {
	_, issues := ParseHeaderString("max-age")
	expectIssuesEqual(t, issues,
		NewIssues().addError("Syntax error: A max-age directive name is present without an associated value."))
}

// Motivated by https://crbug.com/596561
func TestParseHeaderStringBadMaxAgeMinus(t *testing.T) {
	_, issues := ParseHeaderString("max-age=-101")
	expectIssuesEqual(t, issues,
		NewIssues().addError("Syntax error: Could not parse max-age value [-101]."))
}

// Motivated by https://crbug.com/596561
func TestParseHeaderStringBadMaxAgePlus(t *testing.T) {
	_, issues := ParseHeaderString("max-age=+101")
	expectIssuesEqual(t, issues,
		NewIssues().addError("Syntax error: Could not parse max-age value [+101]."))
}

/******** ParseHeaderString() with warnings and errors. ********/

func TestParseHeaderStringMaxAgeWithoutValueAndTrailingSemicolon(t *testing.T) {
	hstsHeader, issues := ParseHeaderString("includeSubDomains; max-age;")
	expectIssuesEqual(t, issues,
		Issues{
			Errors:   []string{"Syntax error: A max-age directive name is present without an associated value."},
			Warnings: []string{"Syntax warning: Header includes an empty directive or extra semicolon."},
		},
	)
	expectHeadersEqual(t, hstsHeader, HSTSHeader{
		preload:           false,
		includeSubDomains: true,
		maxAgePresent:     false,
		maxAgeSeconds:     BOGUS_MAX_AGE,
	})
}

/******** CheckHeader() ********/

// Most of the heavy testing takes place in CheckHeaderString().
// We include a few direct tests here as a sanity check.

func TestCheckHeaderMissingPreloadAndMoreThanOneYear(t *testing.T) {
	expectIssuesEqual(t,
		CheckHeader(HSTSHeader{
			preload:           false,
			includeSubDomains: true,
			maxAgePresent:     true,
			maxAgeSeconds:     31536001,
		}),
		Issues{
			Errors:   []string{"Header requirement error: Header must contain the `preload` directive."},
			Warnings: []string{"Header FYI: The max-age (31536001 seconds) is longer than a year. Note that Chrome will round HSTS header max-age values down to 1 year (31536000 seconds)."},
		},
	)
}

/******** CheckHeaderString() without issues. ********/

func TestCheckHeaderStringFull(t *testing.T) {
	expectIssuesEmpty(t, CheckHeaderString("max-age=10886400; includeSubDomains; preload"))
}

/******** CheckHeaderString() with warnings only. ********/

func TestCheckHeaderStringMoreThanOneYear(t *testing.T) {
	expectIssuesEqual(t,
		CheckHeaderString("max-age=31536001; preload; includeSubDomains"),
		NewIssues().addWarning("Header FYI: The max-age (31536001 seconds) is longer than a year. Note that Chrome will round HSTS header max-age values down to 1 year (31536000 seconds)."),
	)
}

/******** CheckHeaderString() with errors only. ********/

func TestCheckHeaderStringEmpty(t *testing.T) {
	expectIssuesEqual(t,
		CheckHeaderString(""),
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

func TestCheckHeaderStringMissingPreload(t *testing.T) {
	expectIssuesEqual(t,
		CheckHeaderString("includeSubDomains; max-age=10886400"),
		NewIssues().addError("Header requirement error: Header must contain the `preload` directive."),
	)
}

func TestCheckHeaderStringMissingIncludeSubdomains(t *testing.T) {
	expectIssuesEqual(t,
		CheckHeaderString("preload; max-age=10886400"),
		NewIssues().addError("Header requirement error: Header must contain the `includeSubDomains` directive."),
	)
}

func TestCheckHeaderStringMissingMaxAge(t *testing.T) {
	expectIssuesEqual(t,
		CheckHeaderString("includeSubDomains; preload"),
		NewIssues().addError("Header requirement error: Header must contain a valid `max-age` directive."),
	)
}

func TestCheckHeaderStringOnlyPreload(t *testing.T) {
	expectIssuesEqual(t,
		CheckHeaderString("preload"),
		Issues{
			Errors: []string{
				"Header requirement error: Header must contain the `includeSubDomains` directive.",
				"Header requirement error: Header must contain a valid `max-age` directive.",
			},
			Warnings: []string{},
		},
	)
}

func TestCheckHeaderStringOnlyIncludeSubdomains(t *testing.T) {
	expectIssuesEqual(t,
		CheckHeaderString("includeSubDomains"),
		Issues{
			Errors: []string{
				"Header requirement error: Header must contain the `preload` directive.",
				"Header requirement error: Header must contain a valid `max-age` directive.",
			},
			Warnings: []string{},
		},
	)
}

func TestCheckHeaderStringOnlyMaxAge(t *testing.T) {
	expectIssuesEqual(t,
		CheckHeaderString("max-age=12345678"),
		Issues{
			Errors: []string{
				"Header requirement error: Header must contain the `includeSubDomains` directive.",
				"Header requirement error: Header must contain the `preload` directive.",
			},
			Warnings: []string{},
		},
	)
}

func TestCheckHeaderStringMaxAgeWithoutValue(t *testing.T) {
	expectIssuesEqual(t,
		CheckHeaderString("includeSubDomains; preload; max-age"),
		Issues{
			Errors: []string{
				"Syntax error: A max-age directive name is present without an associated value.",
				"Header requirement error: Header must contain a valid `max-age` directive.",
			},
			Warnings: []string{},
		},
	)
}

func TestCheckHeaderStringMaxAge0(t *testing.T) {
	// Give information about what to do if you want to remove HSTS.
	expectIssuesEqual(t,
		CheckHeaderString("includeSubDomains; preload; max-age=0"),
		NewIssues().addError("Header requirement error: The max-age must be at least 10886400 seconds (== 18 weeks), but the header only had max-age=0."),
	)
}

func TestCheckHeaderStringMaxAge100(t *testing.T) {
	expectIssuesEqual(t,
		CheckHeaderString("includeSubDomains; preload; max-age=100"),
		NewIssues().addError("Header requirement error: The max-age must be at least 10886400 seconds (== 18 weeks), but the header only had max-age=100."),
	)
}

func TestCheckHeaderStringMaxAge10886399(t *testing.T) {
	expectIssuesEqual(t,
		CheckHeaderString("max-age=10886399; preload; includeSubDomains"),
		NewIssues().addError("Header requirement error: The max-age must be at least 10886400 seconds (== 18 weeks), but the header only had max-age=10886399."),
	)
}

/******** CheckHeaderString() with errors and warnings. ********/

func TestCheckHeaderStringMissingPreloadAndMoreThanOneYear(t *testing.T) {
	expectIssuesEqual(t,
		CheckHeaderString("max-age=31536001; includeSubDomains"),
		Issues{
			Errors:   []string{"Header requirement error: Header must contain the `preload` directive."},
			Warnings: []string{"Header FYI: The max-age (31536001 seconds) is longer than a year. Note that Chrome will round HSTS header max-age values down to 1 year (31536000 seconds)."},
		},
	)
}
