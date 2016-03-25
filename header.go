package hstspreload

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	// Value to use for maxAgeSeconds when invalid.
	// Note that the struct will still be inialized with a value of
	// maxAgeSeconds == 0, so this value is only used as a best effort to
	// catch bugs.
	BOGUS_MAX_AGE = (-1)

	// 18 weeks
	HSTS_MINIMUM_MAX_AGE = 10886400 // seconds

	// 1 year: https://code.google.com/p/chromium/codesearch#chromium/src/net/http/http_security_headers.h&q=kMaxHSTSAgeSecs
	HSTS_CHROME_MAX_AGE_CAP_ONE_YEAR = 86400 * 365 // seconds
)

type HSTSHeader struct {
	preload           bool
	includeSubDomains bool
	maxAgePresent     bool
	// maxAgeSeconds is valid iff maxAgePreset == true
	// It is recommended to set this to BOGUS_MAX_AGE when invalid.
	maxAgeSeconds int64
}

// Mainly useful for testing.
func headersEqual(header1 HSTSHeader, header2 HSTSHeader) bool {
	if header1.preload != header2.preload {
		return false
	}

	if header1.includeSubDomains != header2.includeSubDomains {
		return false
	}

	if header1.maxAgePresent != header2.maxAgePresent {
		return false
	}

	if header1.maxAgePresent && (header1.maxAgeSeconds != header2.maxAgeSeconds) {
		return false
	}

	return true
}

// Iff Issues has no errors, the output integer is the max-age in seconds.
func parseMaxAge(directive string) (int64, Issues) {
	issues := NewIssues()

	maxAgeNumericalString := directive[8:]

	// TODO: Use more concise validation code to parse a digit string to a signed int.
	for i, c := range maxAgeNumericalString {
		if i == 0 && c == '0' && len(maxAgeNumericalString) > 1 {
			issues = issues.addWarning(fmt.Sprintf("Syntax warning: max-age value contains a leading 0: `%s`", directive))
		}
		if c < '0' || c > '9' {
			return BOGUS_MAX_AGE, issues.addError(fmt.Sprintf("Syntax error: max-age value contains characters that are not digits: `%s`", directive))
		}
	}

	maxAge, err := strconv.ParseInt(maxAgeNumericalString, 10, 64)

	if err != nil {
		return BOGUS_MAX_AGE, issues.addError(fmt.Sprintf("Syntax error: Could not parse max-age value [%s].", maxAgeNumericalString))
	}

	if maxAge < 0 {
		return BOGUS_MAX_AGE, issues.addError(fmt.Sprintf("Internal error: unexpected negative integer: `%s`"))
	}

	return maxAge, issues
}

// This function parses an HSTS header.
//
// It will report syntax errors and warnings, but does NOT calculate
// whether the header value is semantically valid.
//
// To interpret the issues, see the list of conventions in the
// documentation for `Issues`.
//
// Example Usage:
//
//     hstsHeader, issues := ParseHeaderString("includeSubDomains; max-age;")
//
//     issues.Errors[0] == []string{"Syntax error: A max-age directive name is present without an associated value."}
//     issues.Warnings[0] == []string{"Syntax warning: Header includes an empty directive or extra semicolon."}
func ParseHeaderString(headerString string) (HSTSHeader, Issues) {
	var hstsHeader HSTSHeader
	issues := NewIssues()

	hstsHeader.preload = false
	hstsHeader.includeSubDomains = false
	hstsHeader.maxAgePresent = false
	hstsHeader.maxAgeSeconds = BOGUS_MAX_AGE

	directives := strings.Split(headerString, ";")
	for i, directive := range directives {
		// TODO: this trims more than spaces and tabs (LWS). https://crbug.com/596561#c10
		directives[i] = strings.TrimSpace(directive)
	}

	// If strings.Split() is given whitespace, it still returns an (empty) directive.
	// So we handle this case separately.
	if len(directives) == 1 && directives[0] == "" {
		// Return immediately, because all the extra information is redundant.
		return hstsHeader, issues.addWarning("Syntax warning: Header is empty.")
	}

	for _, directive := range directives {
		directiveEqualsIgnoringCase := func(s string) bool {
			return strings.ToLower(directive) == strings.ToLower(s)
		}

		directiveHasPrefixIgnoringCase := func(prefix string) bool {
			return strings.HasPrefix(strings.ToLower(directive), strings.ToLower(prefix))
		}

		switch {
		case directiveEqualsIgnoringCase("preload"):
			if hstsHeader.preload {
				issues = issues.addUniqueWarning("Syntax warning: Header contains a repeated directive: `preload`")
			} else {
				hstsHeader.preload = true
			}

		case directiveHasPrefixIgnoringCase("preload"):
			issues = issues.addUniqueWarning("Syntax warning: Header contains a `preload` directive with extra directives.")

		case directiveEqualsIgnoringCase("includeSubDomains"):
			if hstsHeader.includeSubDomains {
				issues = issues.addUniqueWarning("Syntax warning: Header contains a repeated directive: `includeSubDomains`")
			} else {
				hstsHeader.includeSubDomains = true
				if directive != "includeSubDomains" {
					issues = issues.addUniqueWarning(fmt.Sprintf(
						"Syntax warning: Header contains the token `%s`. The recommended capitalization is `includeSubDomains`.",
						directive,
					))
				}
			}

		case directiveHasPrefixIgnoringCase("includeSubDomains"):
			issues = issues.addUniqueWarning("Syntax warning: Header contains an `includeSubDomains` directive with extra directives.")

		case directiveHasPrefixIgnoringCase("max-age="):
			maxAge, maxAgeIssues := parseMaxAge(directive)
			issues = combineIssues(issues, maxAgeIssues)

			if len(maxAgeIssues.Errors) > 0 {
				continue
			}

			if hstsHeader.maxAgePresent {
				issues = issues.addUniqueWarning(fmt.Sprintf("Syntax warning: Header contains a repeated directive: `max-age`"))
			} else {
				hstsHeader.maxAgePresent = true
				hstsHeader.maxAgeSeconds = maxAge
			}

		case directiveHasPrefixIgnoringCase("max-age"):
			issues = issues.addUniqueError("Syntax error: A max-age directive name is present without an associated value.")

		case directiveEqualsIgnoringCase(""):
			issues = issues.addUniqueWarning("Syntax warning: Header includes an empty directive or extra semicolon.")

		default:
			issues = issues.addWarning(fmt.Sprintf("Syntax warning: Header contains an unknown directive: `%s`", directive))
		}
	}
	return hstsHeader, issues
}

// This function checks whether the `HSTSHeader` matches all
// requirements for preloading in Chromium.
//
// To interpret the result, see the list of conventions in the
// documentation for `Issues`.
//
// Most of the time, you'll probably want to use `CheckHeaderString()` instead.
func CheckHeader(hstsHeader HSTSHeader) Issues {
	issues := NewIssues()

	if !hstsHeader.includeSubDomains {
		issues = issues.addError("Header requirement error: Header must contain the `includeSubDomains` directive.")
	}

	if !hstsHeader.preload {
		issues = issues.addError("Header requirement error: Header must contain the `preload` directive.")
	}

	if !hstsHeader.maxAgePresent {
		issues = issues.addError("Header requirement error: Header must contain a valid `max-age` directive.")
	}

	if hstsHeader.maxAgePresent && hstsHeader.maxAgeSeconds < HSTS_MINIMUM_MAX_AGE {
		issues = issues.addError(fmt.Sprintf(
			"Header requirement error: The max-age must be at least 10886400 seconds (== 18 weeks), but the header only had max-age=%d.",
			hstsHeader.maxAgeSeconds,
		))
	}

	if hstsHeader.maxAgePresent && hstsHeader.maxAgeSeconds > HSTS_CHROME_MAX_AGE_CAP_ONE_YEAR {
		issues = issues.addWarning(fmt.Sprintf(
			"Header FYI: The max-age (%d seconds) is longer than a year. Note that Chrome will round HSTS header max-age values down to 1 year (%d seconds).",
			hstsHeader.maxAgeSeconds,
			HSTS_CHROME_MAX_AGE_CAP_ONE_YEAR,
		))
	}

	if !hstsHeader.maxAgePresent && hstsHeader.maxAgeSeconds != BOGUS_MAX_AGE {
		issues = issues.addWarning("Internal issue: encountered an HSTSHeader with maxAgePresent but an unexpected maxAgeSeconds.")
	}

	return issues
}

// This convenience function calls ParseHeaderString() and then calls on
// the parsed headerCheckHeader(). It returns all issues from both calls, combined.
//
// To interpret the result, see the list of conventions in the
// documentation for `Issues`.
//
// Example Usage:
//
//     hstsHeader, issues := ParseHeaderString("includeSubDomains; max-age;")
//
//     hstsHeader.Errors[0] == "Header requirement error: Header must contain the `preload` directive."
//     hstsHeader.Warnings[0] == "Header FYI: The max-age (31536001 seconds) is longer than a year. Note that Chrome will round HSTS header max-age values down to 1 year (31536000 seconds)."
func CheckHeaderString(headerString string) Issues {
	hstsHeader, issues := ParseHeaderString(headerString)
	return combineIssues(issues, CheckHeader(hstsHeader))
}
