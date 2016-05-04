package hstspreload

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	// 18 weeks
	hstsMinimumMaxAge = 10886400 // seconds

	tenYears = 86400 * 365 * 10 // seconds
)

// MaxAge holds the max-age of an HSTS header in seconds.
// See https://tools.ietf.org/html/rfc6797#section-6.1.1
type MaxAge struct {
	Seconds uint64 `json:"seconds"`
}

// An HSTSHeader stores the semantics of an HSTS header.
// https://tools.ietf.org/html/rfc6797#section-6.1
//
// Note that the `preload` directive is not standardized yet:  https://crbug.com/591212
type HSTSHeader struct {
	// A MaxAge of `nil` indicates "not present".
	MaxAge            *MaxAge `json:"max_age,omitempty"`
	IncludeSubDomains bool    `json:"includeSubDomains"`
	Preload           bool    `json:"preload"`
}

// Iff Issues has no errors, the output integer is the max-age in seconds.
func parseMaxAge(directive string) (*MaxAge, *Issues) {
	issues := &Issues{}
	maxAgeNumericalString := directive[8:]

	// TODO: Use more concise validation code to parse a digit string to a signed int.
	for i, c := range maxAgeNumericalString {
		if i == 0 && c == '0' && len(maxAgeNumericalString) > 1 {
			issues.addWarningf(
				"header.parse.max_age.leading_zero",
				"Unexpected max-age syntax",
				"The header's max-age value contains a leading 0: `%s`", directive)
		}
		if c < '0' || c > '9' {
			issues.addErrorf(
				"header.parse.max_age.non_digit_characters",
				"Invalid max-age syntax",
				"The header's max-age value contains characters that are not digits: `%s`", directive)
			return nil, issues
		}
	}

	seconds, err := strconv.ParseUint(maxAgeNumericalString, 10, 64)

	if err != nil {
		issues.addErrorf(
			"header.parse.max_age.parse_int_error",
			"Invalid max-age syntax",
			"We could not parse the header's max-age value `%s`.", maxAgeNumericalString)
		return nil, issues
	}

	return &MaxAge{Seconds: seconds}, issues
}

// ParseHeaderString parses an HSTS header. ParseHeaderString will
// report syntax errors and warnings, but does NOT calculate whether the
// header value is semantically valid. (See PreloadableHeaderString() for
// that.)
//
// To interpret the Issues that are returned, see the list of
// conventions in the documentation for Issues.
func ParseHeaderString(headerString string) (HSTSHeader, *Issues) {
	hstsHeader := HSTSHeader{}
	issues := &Issues{}

	directives := strings.Split(headerString, ";")
	for i, directive := range directives {
		// TODO: this trims more than spaces and tabs (LWS). https://crbug.com/596561#c10
		directives[i] = strings.TrimSpace(directive)
	}

	// If strings.Split() is given whitespace, it still returns an (empty) directive.
	// So we handle this case separately.
	if len(directives) == 1 && directives[0] == "" {
		// Return immediately, because all the extra information is redundant.
		issues.addWarningf(
			"header.parse.empty",
			"Empty Header",
			"The HSTS header is empty.")
		return hstsHeader, issues
	}

	for _, directive := range directives {
		directiveEqualsIgnoringCase := func(s string) bool {
			return strings.EqualFold(directive, s)
		}

		directiveHasPrefixIgnoringCase := func(prefix string) bool {
			return strings.HasPrefix(strings.ToLower(directive), strings.ToLower(prefix))
		}

		switch {
		case directiveEqualsIgnoringCase("preload"):
			if hstsHeader.Preload {
				issues.addUniqueWarningf(
					"header.parse.repeated.preload",
					"Repeated preload directive",
					"Header contains a repeated directive: `preload`")
			} else {
				hstsHeader.Preload = true
			}

		case directiveHasPrefixIgnoringCase("preload"):
			issues.addUniqueWarningf(
				"header.parse.invalid.preload",
				"Invalid preload directive",
				"Header contains a `preload` directive with extra parts.")

		case directiveEqualsIgnoringCase("includeSubDomains"):
			if hstsHeader.IncludeSubDomains {
				issues.addUniqueWarningf(
					"header.parse.repeated.include_sub_domains",
					"Repeated includeSubDomains directive",
					"Header contains a repeated directive: `includeSubDomains`")
			} else {
				hstsHeader.IncludeSubDomains = true
				if directive != "includeSubDomains" {
					issues.addUniqueWarningf(
						"header.parse.spelling.include_sub_domains",
						"Non-standard capitalization of includeSubDomains",
						"Header contains the token `%s`. The recommended capitalization is `includeSubDomains`.",
						directive,
					)
				}
			}

		case directiveHasPrefixIgnoringCase("includeSubDomains"):
			issues.addUniqueWarningf(
				"header.parse.invalid.include_sub_domains",
				"Invalid includeSubDomains directive",
				"The header contains an `includeSubDomains` directive with extra directives.")

		case directiveHasPrefixIgnoringCase("max-age="):
			maxAge, maxAgeIssues := parseMaxAge(directive)
			issues.merge(maxAgeIssues)

			if len(maxAgeIssues.Errors) > 0 {
				continue
			}

			if hstsHeader.MaxAge == nil {
				hstsHeader.MaxAge = maxAge
			} else {
				issues.addUniqueWarningf(
					"header.parse.repeated.max_age",
					"Repeated max-age directive",
					"The header contains a repeated directive: `max-age`")
			}

		case directiveHasPrefixIgnoringCase("max-age"):
			issues.addUniqueErrorf(
				"header.parse.invalid.max_age.no_value",
				"Max-age drective without a value",
				"The header contains a max-age directive name without an associated value. Please specify the max-age in seconds.")

		case directiveEqualsIgnoringCase(""):
			issues.addUniqueWarningf(
				"header.parse.empty_directive",
				"Empty directive or extra semicolon",
				"The header includes an empty directive or extra semicolon.")

		default:
			issues.addWarningf(
				"header.parse.unknown_directive",
				"Unknown directive",
				"The header contains an unknown directive: `%s`", directive)
		}
	}
	return hstsHeader, issues
}

func preloadableHeaderPreload(hstsHeader HSTSHeader) *Issues {
	issues := &Issues{}

	if !hstsHeader.Preload {
		issues.addErrorf(
			"header.preloadable.preload.missing",
			"No preload directive",
			"The header must contain the `preload` directive.")
	}

	return issues
}

func preloadableHeaderSubDomains(hstsHeader HSTSHeader) *Issues {
	issues := &Issues{}

	if !hstsHeader.IncludeSubDomains {
		issues.addErrorf(
			"header.preloadable.include_sub_domains.missing",
			"No includeSubDomains directive",
			"The header must contain the `includeSubDomains` directive.")
	}

	return issues
}

func preloadableHeaderMaxAge(hstsHeader HSTSHeader) *Issues {
	issues := &Issues{}

	switch {
	case hstsHeader.MaxAge == nil:
		issues.addErrorf(
			"header.preloadable.max_age.missing",
			"No max-age directice",
			"Header requirement error: Header must contain a valid `max-age` directive.")

	case hstsHeader.MaxAge.Seconds < 0:
		issues.addErrorf(
			"internal.header.preloadable.max_age.negative",
			"Negative max-age",
			"Encountered an HSTSHeader with a negative max-age that does not equal MaxAgeNotPresent: %d", hstsHeader.MaxAge.Seconds)

	case hstsHeader.MaxAge.Seconds < hstsMinimumMaxAge:
		errorStr := fmt.Sprintf(
			"The max-age must be at least 10886400 seconds (== 18 weeks), but the header currently only has max-age=%d.",
			hstsHeader.MaxAge.Seconds,
		)
		if hstsHeader.MaxAge.Seconds == 0 {
			errorStr += " If you are trying to remove this domain from the preload list, please contact Lucas Garron at hstspreload@chromium.org"
			issues.addErrorf(
				"header.preloadable.max_age.zero",
				"Max-age is 0",
				errorStr,
			)
		} else {
			issues.addErrorf(
				"header.preloadable.max_age.too_low",
				"Max-age too low",
				errorStr,
			)
		}

	case hstsHeader.MaxAge.Seconds > tenYears:
		issues.addWarningf(
			"header.preloadable.max_age.over_10_years",
			"Max-age > 10 years",
			"FYI: The max-age (%d seconds) is longer than 10 years, which is an unusually long value.",
			hstsHeader.MaxAge.Seconds,
		)

	}

	return issues
}

// PreloadableHeader checks whether hstsHeader satisfies all requirements
// for preloading in Chromium.
//
// To interpret the result, see the list of conventions in the
// documentation for Issues.
//
// Most of the time, you'll probably want to use PreloadableHeaderString() instead.
func PreloadableHeader(hstsHeader HSTSHeader) *Issues {
	issues := &Issues{}

	issues.merge(preloadableHeaderSubDomains(hstsHeader))
	issues.merge(preloadableHeaderPreload(hstsHeader))
	issues.merge(preloadableHeaderMaxAge(hstsHeader))
	return issues
}

// RemovableHeader checks whether the header satisfies all requirements
// for being removed from the Chromium preload list.
//
// To interpret the result, see the list of conventions in the
// documentation for Issues.
//
// Most of the time, you'll probably want to use RemovableHeaderString() instead.
func RemovableHeader(hstsHeader HSTSHeader) *Issues {
	issues := &Issues{}

	if hstsHeader.Preload {
		issues.addErrorf(
			"header.removable.contains.preload",
			"Contains preload directive",
			"Header requirement error: For preload list removal, the header must not contain the `preload` directive.")
	}

	if hstsHeader.MaxAge == nil {
		issues.addErrorf(
			"header.removable.missing.max_age",
			"No max-age directive",
			"Header requirement error: Header must contain a valid `max-age` directive.")
	}

	return issues
}

// PreloadableHeaderString is a convenience function that calls
// ParseHeaderString() and then calls on PreloadableHeader() the parsed
// header. It returns all issues from both calls, combined.
//
// To interpret the result, see the list of conventions in the
// documentation for Issues.
func PreloadableHeaderString(headerString string) *Issues {
	hstsHeader, issues := ParseHeaderString(headerString)
	issues.merge(PreloadableHeader(hstsHeader))
	return issues
}

// RemovableHeaderString is a convenience function that calls
// ParseHeaderString() and then calls on RemovableHeader() the parsed
// header. It returns all errors from ParseHeaderString() and all
// issues from RemovableHeader(). Note that *warnings* from
// ParseHeaderString() are ignored, since domains asking to be removed
// will often have minor errors that shouldn't affect removal. It's
// better to have a cleaner verdict in this case.
//
// To interpret the result, see the list of conventions in the
// documentation for Issues.
func RemovableHeaderString(headerString string) *Issues {
	issues := &Issues{}

	hstsHeader, parseIssues := ParseHeaderString(headerString)
	issues.merge(&Issues{
		Errors: parseIssues.Errors,
		// Ignore parse warnings for removal testing.
	})
	issues.merge(RemovableHeader(hstsHeader))
	return issues
}
