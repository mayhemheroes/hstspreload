package hstspreload

import (
	"fmt"
	"testing"
)

const (
	headersShouldBeEqual = `Header did not match expected value after parsing.
			Actual: %v
			Expected: %v`
)

func ExampleParseHeaderString() {
	hstsHeader, issues := ParseHeaderString("includeSubDomains; max-age;")
	fmt.Printf("%v\n%v", hstsHeader, issues)
}

/******** HSTSHeader Comparison *********/

func headersEqual(header1 HSTSHeader, header2 HSTSHeader) bool {
	if header1.Preload != header2.Preload {
		return false
	}

	if header1.IncludeSubDomains != header2.IncludeSubDomains {
		return false
	}

	if header1.MaxAge != header2.MaxAge {
		return false
	}

	return true
}

func TestHeadersEqual(t *testing.T) {
	if !headersEqual(
		HSTSHeader{
			Preload:           false,
			IncludeSubDomains: true,
			MaxAge:            12345,
		},
		HSTSHeader{
			Preload:           false,
			IncludeSubDomains: true,
			MaxAge:            12345,
		},
	) {
		t.Errorf("HSTSHeader structs should be considered equal if all values match.")
	}

	if headersEqual(
		HSTSHeader{
			Preload:           false,
			IncludeSubDomains: true,
			MaxAge:            12345,
		},
		HSTSHeader{
			Preload:           true,
			IncludeSubDomains: true,
			MaxAge:            12345,
		},
	) {
		t.Errorf("HSTSHeader structs should be considered non-equal if preload values don't match.")
	}
}

func expectHeadersEqual(t *testing.T, expected HSTSHeader, actual HSTSHeader) {
	if !headersEqual(actual, expected) {
		t.Errorf(headersShouldBeEqual, actual, expected)
	}
}

var parseHeaderStringTests = []struct {
	description        string
	header             string
	expectedIssues     Issues
	expectedHSTSHeader HSTSHeader
}{

	/******** no warnings, no errors ********/

	{
		"without preload",
		"includeSubDomains; max-age=1337",
		Issues{},
		HSTSHeader{Preload: false, IncludeSubDomains: true, MaxAge: 1337},
	},
	{
		"without includeSubDomains",
		"preload; max-age=1337",
		Issues{},
		HSTSHeader{Preload: true, IncludeSubDomains: false, MaxAge: 1337},
	},
	{
		"without max-age",
		"preload; includeSubDomains",
		Issues{},
		HSTSHeader{Preload: true, IncludeSubDomains: true, MaxAge: MaxAgeNotPresent},
	},
	{
		"full",
		"max-age=10886400; includeSubDomains; preload",
		Issues{},
		HSTSHeader{Preload: true, IncludeSubDomains: true, MaxAge: 10886400},
	},
	{
		"any order",
		"includeSubDomains; preload; max-age=4321",
		Issues{},
		HSTSHeader{Preload: true, IncludeSubDomains: true, MaxAge: 4321},
	},
	{
		"extra whitespace",
		"   max-age=10886400  ;     includeSubDomains    ;     preload      ",
		Issues{},
		HSTSHeader{Preload: true, IncludeSubDomains: true, MaxAge: 10886400},
	},
	{
		"larger max-age",
		"includeSubDomains; preload; max-age=12345678",
		Issues{},
		HSTSHeader{Preload: true, IncludeSubDomains: true, MaxAge: 12345678},
	},
	{
		"reordered",
		"max-age=10886400; preload; includeSubDomains",
		Issues{},
		HSTSHeader{Preload: true, IncludeSubDomains: true, MaxAge: 10886400},
	},
	{
		"reordered, without preload",
		"max-age=10886400; includeSubDomains",
		Issues{},
		HSTSHeader{Preload: false, IncludeSubDomains: true, MaxAge: 10886400},
	},

	/******** no errors, warnings only ********/

	{
		"empty",
		"",
		NewIssues().addWarningf("Syntax warning: Header is empty."),
		HSTSHeader{Preload: false, IncludeSubDomains: false, MaxAge: MaxAgeNotPresent},
	},
	{
		"case-insensitive",
		"inCLUDESUBDomaINs; max-AGe=12345678",
		NewIssues().addWarningf("Syntax warning: Header contains the token `inCLUDESUBDomaINs`. The recommended capitalization is `includeSubDomains`."),
		HSTSHeader{Preload: false, IncludeSubDomains: true, MaxAge: 12345678},
	},
	{
		"repeated preload",
		"preload; includeSubDomains; preload; max-age=12345678; preload",
		NewIssues().addWarningf("Syntax warning: Header contains a repeated directive: `preload`"),
		HSTSHeader{Preload: true, IncludeSubDomains: true, MaxAge: 12345678},
	},
	{
		"single extra directive",
		"includeSubDomains; max-age=12345678; preload; extraDirective",
		NewIssues().addWarningf("Syntax warning: Header contains an unknown directive: `extraDirective`"),
		HSTSHeader{Preload: true, IncludeSubDomains: true, MaxAge: 12345678},
	},
	{
		"multiple extra directives",
		"max-age=12345678; extra; includeSubDomains; directives; preload",
		Issues{Warnings: []string{
			"Syntax warning: Header contains an unknown directive: `extra`",
			"Syntax warning: Header contains an unknown directive: `directives`",
		}},
		HSTSHeader{Preload: true, IncludeSubDomains: true, MaxAge: 12345678},
	},
	{
		"semicolon only",
		";",
		NewIssues().addWarningf("Syntax warning: Header includes an empty directive or extra semicolon."),
		HSTSHeader{Preload: false, IncludeSubDomains: false, MaxAge: MaxAgeNotPresent},
	},
	{
		"trailing semicolon",
		"max-age=10886400; includeSubDomains; preload;",
		NewIssues().addWarningf("Syntax warning: Header includes an empty directive or extra semicolon."),
		HSTSHeader{Preload: true, IncludeSubDomains: true, MaxAge: 10886400},
	},
	{
		"prefixed by semicolon",
		"; max-age=10886400; includeSubDomains; preload",
		NewIssues().addWarningf("Syntax warning: Header includes an empty directive or extra semicolon."),
		HSTSHeader{Preload: true, IncludeSubDomains: true, MaxAge: 10886400},
	},
	{
		"bad max-age: leading 0",
		"max-age=01234",
		NewIssues().addWarningf("Syntax warning: max-age value contains a leading 0: `max-age=01234`"),
		HSTSHeader{Preload: false, IncludeSubDomains: false, MaxAge: 1234},
	},
}

func TestParseHeaderString(t *testing.T) {
	for _, tt := range parseHeaderStringTests {
		hstsHeader, issues := ParseHeaderString(tt.header)
		if !issuesEqual(issues, tt.expectedIssues) {
			t.Errorf("[%s] "+issuesShouldBeEqual, tt.description, issues, tt.expectedIssues)
		}
		if !headersEqual(hstsHeader, tt.expectedHSTSHeader) {
			t.Errorf("[%s] "+headersShouldBeEqual, tt.description, hstsHeader, tt.expectedHSTSHeader)
		}
	}
}

var parseHeaderStringWithErrorsTests = []struct {
	description    string
	header         string
	expectedIssues Issues
}{

	/******** errors only, no warnings ********/

	{
		"bad max-age: empty value",
		"max-age=",
		NewIssues().addErrorf("Syntax error: Could not parse max-age value ``."),
	},
	{
		"bad max-age: no value",
		"max-age",
		NewIssues().addErrorf("Syntax error: A max-age directive name is present without an associated value."),
	},
	{
		" max-age: minus", // Motivated by https://crbug.com/596561
		"max-age=-101",    // Motivated by https://crbug.com/596561
		NewIssues().addErrorf("Syntax error: max-age value contains characters that are not digits: `max-age=-101`"),
	},
	{
		" max-age: plus", // Motivated by https://crbug.com/596561
		"max-age=+101",
		NewIssues().addErrorf("Syntax error: max-age value contains characters that are not digits: `max-age=+101`"),
	},

	/******** errors and warnings ********/

	{
		"error and warning: no max-age value, trailing semicolon", // Motivated by https://crbug.com/596561
		"max-age;",
		Issues{
			Errors:   []string{"Syntax error: A max-age directive name is present without an associated value."},
			Warnings: []string{"Syntax warning: Header includes an empty directive or extra semicolon."},
		},
	},
	{
		"error and warnings: no max-age value, unknown directive, trailing semicolon", // Motivated by https://crbug.com/596561
		"includeDomains; max-age;",
		Issues{
			Errors: []string{"Syntax error: A max-age directive name is present without an associated value."},
			Warnings: []string{
				"Syntax warning: Header contains an unknown directive: `includeDomains`",
				"Syntax warning: Header includes an empty directive or extra semicolon.",
			},
		},
	},
}

func TestParseHeaderStringWithErrors(t *testing.T) {
	for _, tt := range parseHeaderStringWithErrorsTests {
		_, issues := ParseHeaderString(tt.header)
		if !issuesEqual(issues, tt.expectedIssues) {
			t.Errorf("[%s] "+issuesShouldBeEqual, tt.description, issues, tt.expectedIssues)
		}
	}
}

/******** PreloadableHeader() ********/

// Most of the heavy testing takes place in PreloadableHeaderString().
// We include a few direct tests here as a sanity check.

func TestPreloadableHeaderMissingPreloadAndMoreThanTenYears(t *testing.T) {
	expectIssuesEqual(t,
		PreloadableHeader(HSTSHeader{
			Preload:           false,
			IncludeSubDomains: true,
			MaxAge:            315360001,
		}),
		Issues{
			Errors:   []string{"Header requirement error: Header must contain the `preload` directive."},
			Warnings: []string{"Header FYI: The max-age (315360001 seconds) is longer than 10 years, which is an unusually long value."},
		},
	)
}

func TestPreloadableHeaderMaxAgeNotPresent(t *testing.T) {
	expectIssuesEqual(t,
		PreloadableHeader(HSTSHeader{
			Preload:           true,
			IncludeSubDomains: true,
			MaxAge:            -2,
		}),
		NewIssues().addErrorf("Internal error: encountered an HSTSHeader with a negative max-age that does not equal MaxAgeNotPresent: -2"),
	)
}

/******** PreloadableHeaderString() without issues. ********/

func TestPreloadableHeaderStringFull(t *testing.T) {
	expectIssuesEmpty(t, PreloadableHeaderString("max-age=10886400; includeSubDomains; preload"))
}

/******** PreloadableHeaderString() with warnings only. ********/

func TestPreloadableHeaderStringMoreThanTenYears(t *testing.T) {
	expectIssuesEqual(t,
		PreloadableHeaderString("max-age=315360001; preload; includeSubDomains"),
		NewIssues().addWarningf("Header FYI: The max-age (315360001 seconds) is longer than 10 years, which is an unusually long value."),
	)
}

/******** PreloadableHeaderString() with errors only. ********/

func TestPreloadableHeaderStringEmpty(t *testing.T) {
	expectIssuesEqual(t,
		PreloadableHeaderString(""),
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

func TestPreloadableHeaderStringMissingPreload(t *testing.T) {
	expectIssuesEqual(t,
		PreloadableHeaderString("includeSubDomains; max-age=10886400"),
		NewIssues().addErrorf("Header requirement error: Header must contain the `preload` directive."),
	)
}

func TestPreloadableHeaderStringMissingIncludeSubdomains(t *testing.T) {
	expectIssuesEqual(t,
		PreloadableHeaderString("preload; max-age=10886400"),
		NewIssues().addErrorf("Header requirement error: Header must contain the `includeSubDomains` directive."),
	)
}

func TestPreloadableHeaderStringMissingMaxAge(t *testing.T) {
	expectIssuesEqual(t,
		PreloadableHeaderString("includeSubDomains; preload"),
		NewIssues().addErrorf("Header requirement error: Header must contain a valid `max-age` directive."),
	)
}

func TestPreloadableHeaderStringOnlyPreload(t *testing.T) {
	expectIssuesEqual(t,
		PreloadableHeaderString("preload"),
		Issues{
			Errors: []string{
				"Header requirement error: Header must contain the `includeSubDomains` directive.",
				"Header requirement error: Header must contain a valid `max-age` directive.",
			},
			Warnings: []string{},
		},
	)
}

func TestPreloadableHeaderStringOnlyIncludeSubdomains(t *testing.T) {
	expectIssuesEqual(t,
		PreloadableHeaderString("includeSubDomains"),
		Issues{
			Errors: []string{
				"Header requirement error: Header must contain the `preload` directive.",
				"Header requirement error: Header must contain a valid `max-age` directive.",
			},
			Warnings: []string{},
		},
	)
}

func TestPreloadableHeaderStringOnlyMaxAge(t *testing.T) {
	expectIssuesEqual(t,
		PreloadableHeaderString("max-age=12345678"),
		Issues{
			Errors: []string{
				"Header requirement error: Header must contain the `includeSubDomains` directive.",
				"Header requirement error: Header must contain the `preload` directive.",
			},
			Warnings: []string{},
		},
	)
}

func TestPreloadableHeaderStringMaxAgeWithoutValue(t *testing.T) {
	expectIssuesEqual(t,
		PreloadableHeaderString("includeSubDomains; preload; max-age"),
		Issues{
			Errors: []string{
				"Syntax error: A max-age directive name is present without an associated value.",
				"Header requirement error: Header must contain a valid `max-age` directive.",
			},
			Warnings: []string{},
		},
	)
}

func TestPreloadableHeaderStringMaxAge0(t *testing.T) {
	// Give information about what to do if you want to remove HSTS.
	expectIssuesEqual(t,
		PreloadableHeaderString("includeSubDomains; preload; max-age=0"),
		NewIssues().addErrorf("Header requirement error: The max-age must be at least 10886400 seconds (== 18 weeks), but the header currently only has max-age=0. If you are trying to remove this domain from the preload list, please contact Lucas Garron at hstspreload@chromium.org"),
	)
}

func TestPreloadableHeaderStringMaxAge100(t *testing.T) {
	expectIssuesEqual(t,
		PreloadableHeaderString("includeSubDomains; preload; max-age=100"),
		NewIssues().addErrorf("Header requirement error: The max-age must be at least 10886400 seconds (== 18 weeks), but the header currently only has max-age=100."),
	)
}

/******** PreloadableHeaderString() with errors and warnings. ********/

func TestPreloadableHeaderStringMissingPreloadAndMoreThanTenYears(t *testing.T) {
	expectIssuesEqual(t,
		PreloadableHeaderString("max-age=315360001; includeSubDomains"),
		Issues{
			Errors:   []string{"Header requirement error: Header must contain the `preload` directive."},
			Warnings: []string{"Header FYI: The max-age (315360001 seconds) is longer than 10 years, which is an unusually long value."},
		},
	)
}

/******** RemovableResponseString() without issues. ********/

func TestRemovableResponseStringOkay(t *testing.T) {
	expectIssuesEmpty(t,
		RemovableHeaderString("max-age=315360001; includeSubDomains"),
	)
	expectIssuesEmpty(t,
		RemovableHeaderString("max-age=315360001"),
	)
}

func TestRemovableResponseStringMaxAge0(t *testing.T) {
	expectIssuesEmpty(t,
		RemovableHeaderString("max-age=0"),
	)
}

func TestRemovableResponseStringMaxAgeMissing(t *testing.T) {
	expectIssuesEqual(t,
		RemovableHeaderString("includeSubDomains"),
		Issues{
			Errors:   []string{"Header requirement error: Header must contain a valid `max-age` directive."},
			Warnings: []string{},
		},
	)
}

func TestRemovableResponseStringEmptyHeader(t *testing.T) {
	expectIssuesEqual(t,
		RemovableHeaderString(""),
		Issues{
			Errors:   []string{"Header requirement error: Header must contain a valid `max-age` directive."},
			Warnings: []string{},
		},
	)
}

func TestRemovableResponseStringPreloadPresent(t *testing.T) {
	expectIssuesEqual(t,
		RemovableHeaderString("max-age=315360001; includeSubDomains; preload"),
		Issues{
			Errors:   []string{"Header requirement error: For preload list removal, the header must not contain the `preload` directive."},
			Warnings: []string{},
		},
	)
}

func TestRemovableResponseStringPreloadOnly(t *testing.T) {
	expectIssuesEqual(t,
		RemovableHeaderString("preload"),
		Issues{
			Errors: []string{
				"Header requirement error: For preload list removal, the header must not contain the `preload` directive.",
				"Header requirement error: Header must contain a valid `max-age` directive.",
			},
			Warnings: []string{},
		},
	)
}
