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
		Issues{Warnings: []string{"Syntax warning: Header is empty."}},
		HSTSHeader{Preload: false, IncludeSubDomains: false, MaxAge: MaxAgeNotPresent},
	},
	{
		"case-insensitive",
		"inCLUDESUBDomaINs; max-AGe=12345678",
		Issues{Warnings: []string{"Syntax warning: Header contains the token `inCLUDESUBDomaINs`. The recommended capitalization is `includeSubDomains`."}},
		HSTSHeader{Preload: false, IncludeSubDomains: true, MaxAge: 12345678},
	},
	{
		"repeated preload",
		"preload; includeSubDomains; preload; max-age=12345678; preload",
		Issues{Warnings: []string{"Syntax warning: Header contains a repeated directive: `preload`"}},
		HSTSHeader{Preload: true, IncludeSubDomains: true, MaxAge: 12345678},
	},
	{
		"single extra directive",
		"includeSubDomains; max-age=12345678; preload; extraDirective",
		Issues{Warnings: []string{"Syntax warning: Header contains an unknown directive: `extraDirective`"}},
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
		Issues{Warnings: []string{"Syntax warning: Header includes an empty directive or extra semicolon."}},
		HSTSHeader{Preload: false, IncludeSubDomains: false, MaxAge: MaxAgeNotPresent},
	},
	{
		"trailing semicolon",
		"max-age=10886400; includeSubDomains; preload;",
		Issues{Warnings: []string{"Syntax warning: Header includes an empty directive or extra semicolon."}},
		HSTSHeader{Preload: true, IncludeSubDomains: true, MaxAge: 10886400},
	},
	{
		"prefixed by semicolon",
		"; max-age=10886400; includeSubDomains; preload",
		Issues{Warnings: []string{"Syntax warning: Header includes an empty directive or extra semicolon."}},
		HSTSHeader{Preload: true, IncludeSubDomains: true, MaxAge: 10886400},
	},
	{
		"bad max-age: leading 0",
		"max-age=01234",
		Issues{Warnings: []string{"Syntax warning: max-age value contains a leading 0: `max-age=01234`"}},
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
		Issues{Errors: []string{"Syntax error: Could not parse max-age value ``."}},
	},
	{
		"bad max-age: no value",
		"max-age",
		Issues{Errors: []string{"Syntax error: A max-age directive name is present without an associated value."}},
	},
	{
		" max-age: minus", // Motivated by https://crbug.com/596561
		"max-age=-101",    // Motivated by https://crbug.com/596561
		Issues{Errors: []string{"Syntax error: max-age value contains characters that are not digits: `max-age=-101`"}},
	},
	{
		" max-age: plus", // Motivated by https://crbug.com/596561
		"max-age=+101",
		Issues{Errors: []string{"Syntax error: max-age value contains characters that are not digits: `max-age=+101`"}},
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
	issues := PreloadableHeader(HSTSHeader{
		Preload:           false,
		IncludeSubDomains: true,
		MaxAge:            315360001,
	})
	expected := Issues{
		Errors:   []string{"Header requirement error: Header must contain the `preload` directive."},
		Warnings: []string{"Header FYI: The max-age (315360001 seconds) is longer than 10 years, which is an unusually long value."},
	}
	if !issuesEqual(issues, expected) {
		t.Errorf(issuesShouldBeEqual, issues, expected)
	}
}

func TestPreloadableHeaderMaxAgeNotPresent(t *testing.T) {
	issues := PreloadableHeader(HSTSHeader{
		Preload:           true,
		IncludeSubDomains: true,
		MaxAge:            -2,
	})
	expected := Issues{Errors: []string{"Internal error: encountered an HSTSHeader with a negative max-age that does not equal MaxAgeNotPresent: -2"}}
	if !issuesEqual(issues, expected) {
		t.Errorf(issuesShouldBeEqual, issues, expected)
	}
}

var preloadableHeaderStringTests = []struct {
	description    string
	header         string
	expectedIssues Issues
}{

	/******** no errors, no warnings ********/

	{
		"no issues",
		"max-age=10886400; includeSubDomains; preload",
		Issues{},
	},

	/******** no errors, warnings only ********/

	{
		"max-age > 10 years",
		"max-age=315360001; preload; includeSubDomains",
		Issues{Warnings: []string{"Header FYI: The max-age (315360001 seconds) is longer than 10 years, which is an unusually long value."}},
	},

	/******** errors only, no warnings ********/

	{
		"empty",
		"",
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
		"missing preload",
		"includeSubDomains; max-age=10886400",
		Issues{Errors: []string{"Header requirement error: Header must contain the `preload` directive."}},
	},
	{
		"missing includeSubdomains",
		"preload; max-age=10886400",
		Issues{Errors: []string{"Header requirement error: Header must contain the `includeSubDomains` directive."}},
	},
	{
		"missing max-age",
		"includeSubDomains; preload",
		Issues{Errors: []string{"Header requirement error: Header must contain a valid `max-age` directive."}},
	},
	{
		"only preload",
		"preload",
		Issues{
			Errors: []string{
				"Header requirement error: Header must contain the `includeSubDomains` directive.",
				"Header requirement error: Header must contain a valid `max-age` directive.",
			},
		},
	},
	{
		"only includeSubdomains",
		"includeSubDomains",
		Issues{
			Errors: []string{
				"Header requirement error: Header must contain the `preload` directive.",
				"Header requirement error: Header must contain a valid `max-age` directive.",
			},
		},
	},
	{
		"only max-age",
		"max-age=12345678",
		Issues{
			Errors: []string{
				"Header requirement error: Header must contain the `includeSubDomains` directive.",
				"Header requirement error: Header must contain the `preload` directive.",
			},
		},
	},
	{
		"max-age without vale",
		"includeSubDomains; preload; max-age",
		Issues{
			Errors: []string{
				"Syntax error: A max-age directive name is present without an associated value.",
				"Header requirement error: Header must contain a valid `max-age` directive.",
			},
		},
	},
	{
		"maxAge=0", // Give information about what to do if you want to remove HSTS.
		"includeSubDomains; preload; max-age=0",
		Issues{Errors: []string{"Header requirement error: The max-age must be at least 10886400 seconds (== 18 weeks), but the header currently only has max-age=0. If you are trying to remove this domain from the preload list, please contact Lucas Garron at hstspreload@chromium.org"}},
	},
	{
		"maxAge=100",
		"includeSubDomains; preload; max-age=100",
		Issues{Errors: []string{"Header requirement error: The max-age must be at least 10886400 seconds (== 18 weeks), but the header currently only has max-age=100."}},
	},

	/******** errors and warnings ********/

	{
		"missing preload, >10 years",
		"max-age=315360001; includeSubDomains",
		Issues{
			Errors:   []string{"Header requirement error: Header must contain the `preload` directive."},
			Warnings: []string{"Header FYI: The max-age (315360001 seconds) is longer than 10 years, which is an unusually long value."},
		},
	},
}

func TestPreloadableHeaderString(t *testing.T) {
	for _, tt := range preloadableHeaderStringTests {
		issues := PreloadableHeaderString(tt.header)
		if !issuesEqual(issues, tt.expectedIssues) {
			t.Errorf("[%s] "+issuesShouldBeEqual, tt.description, issues, tt.expectedIssues)
		}
	}
}

var removableHeaderStringTests = []struct {
	description    string
	header         string
	expectedIssues Issues
}{

	/******** no issues ********/

	{
		"max-age only",
		"max-age=315360001",
		Issues{},
	},
	{
		"max-age=0",
		"max-age=0",
		Issues{},
	},
	{
		"max-age and includeSubDomains",
		"max-age=315360001; includeSubDomains",
		Issues{},
	},

	/******** errors ********/

	{
		"includeSubDomains only",
		"includeSubDomains",
		Issues{Errors: []string{"Header requirement error: Header must contain a valid `max-age` directive."}},
	},
	{
		"max-age missing",
		"includeSubDomains",
		Issues{Errors: []string{"Header requirement error: Header must contain a valid `max-age` directive."}},
	},
	{
		"empty header",
		"includeSubDomains",
		Issues{Errors: []string{"Header requirement error: Header must contain a valid `max-age` directive."}},
	},
	{
		"preload present",
		"max-age=315360001; includeSubDomains; preload",
		Issues{Errors: []string{"Header requirement error: For preload list removal, the header must not contain the `preload` directive."}},
	},
	{
		"preload only",
		"preload",
		Issues{
			Errors: []string{
				"Header requirement error: For preload list removal, the header must not contain the `preload` directive.",
				"Header requirement error: Header must contain a valid `max-age` directive.",
			},
		},
	},
}

func TestRemovableHeaderString(t *testing.T) {
	for _, tt := range removableHeaderStringTests {
		issues := RemovableHeaderString(tt.header)
		if !issuesEqual(issues, tt.expectedIssues) {
			t.Errorf("[%s] "+issuesShouldBeEqual, tt.description, issues, tt.expectedIssues)
		}
	}
}
