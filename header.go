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
	BOGUS_MAX_AGE = (1<<64 - 1)

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
	maxAgeSeconds uint64
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

// This function parses an HSTS header.
// It will report syntax errors and warnings,
// but does not calculate whether the header value is semantically valid.
func ParseHeaderString(headerString string) (HSTSHeader, Issues) {
	var hstsHeader HSTSHeader
	var issues Issues

	hstsHeader.preload = false
	hstsHeader.includeSubDomains = false
	hstsHeader.maxAgePresent = false
	hstsHeader.maxAgeSeconds = BOGUS_MAX_AGE

	hstsParts := strings.Split(headerString, ";")
	for i, part := range hstsParts {
		// TODO: this trims more than spaces and tabs (LWS). https://crbug.com/596561#c10
		hstsParts[i] = strings.TrimSpace(part)
	}

	// If strings.Split() is given whitespace, it still returns an (empty) part.
	// So we handle this case separately.
	if len(hstsParts) == 1 && hstsParts[0] == "" {
		// Return immediately, because all the extra information is redundant.
		return hstsHeader, issues.AddWarning("Header is empty.")
	}

	emptyPartSeen := false

	for _, part := range hstsParts {
		partEqualsIgnoringCase := func(s string) bool {
			return strings.ToLower(part) == strings.ToLower(s)
		}

		partHasPrefixIgnoringCase := func(prefix string) bool {
			return strings.HasPrefix(strings.ToLower(part), strings.ToLower(prefix))
		}

		switch {
		case partEqualsIgnoringCase("preload"):
			if hstsHeader.preload {
				issues = issues.AddWarning("Header contains a repeated directive: `preload`")
			} else {
				hstsHeader.preload = true
			}

		case partHasPrefixIgnoringCase("preload"):
			issues = issues.AddWarning("Header contains a `preload` directive with extra parts.")

		case partEqualsIgnoringCase("includeSubDomains"):
			if hstsHeader.includeSubDomains {
				issues = issues.AddWarning("Header contains a repeated directive: `includeSubDomains`")
			} else {
				hstsHeader.includeSubDomains = true
				if part != "includeSubDomains" {
					issues = issues.AddWarning(fmt.Sprintf(
						"Header contains the token `%s`. The recommended capitalization is `includeSubDomains`.",
						part,
					))
				}
			}

		case partHasPrefixIgnoringCase("includeSubDomains"):
			issues = issues.AddWarning("Header contains an `includeSubDomains` directive with extra parts.")

		case partHasPrefixIgnoringCase("max-age="):
			maxAgeNumericalString := part[8:]
			// TODO the numerical string contains only digits, no symbols (no "+")
			maxAge, err := strconv.ParseUint(maxAgeNumericalString, 10, 63)
			if err != nil {
				issues = issues.AddError(fmt.Sprintf("Could not parse max-age value [%s].", maxAgeNumericalString))
			} else {
				if hstsHeader.maxAgePresent {
					issues = issues.AddWarning(fmt.Sprintf("Header contains a repeated directive: `max-age`"))
				}
				hstsHeader.maxAgePresent = true
				hstsHeader.maxAgeSeconds = maxAge
			}

		case partHasPrefixIgnoringCase("max-age"):
			issues = issues.AddError("A max-age directive name is present without an associated value.")

		case partEqualsIgnoringCase(""):
			// Since we can't give useful information for each individual "empty part",
			// we only record the warning once.
			if !emptyPartSeen {
				issues = issues.AddWarning("Header includes an empty directive or extra semicolon.")
				emptyPartSeen = true
			}

		default:
			issues = issues.AddWarning(fmt.Sprintf("Header contains an unknown directive: `%s`", part))
		}
	}
	return hstsHeader, issues
}

func CheckHeader(hstsHeader HSTSHeader) Issues {
	issues := NewIssues()

	if !hstsHeader.includeSubDomains {
		issues = issues.AddError("Header must contain the `includeSubDomains` directive.")
	}

	if !hstsHeader.preload {
		issues = issues.AddError("Header must contain the `preload` directive.")
	}

	if !hstsHeader.maxAgePresent {
		issues = issues.AddError("Header must contain a valid `max-age` directive.")
	}

	if hstsHeader.maxAgePresent && hstsHeader.maxAgeSeconds < HSTS_MINIMUM_MAX_AGE {
		issues = issues.AddError(fmt.Sprintf(
			"The max-age must be at least 10886400 seconds (== 18 weeks), but the header only had max-age=%d.",
			hstsHeader.maxAgeSeconds,
		))
	}

	if hstsHeader.maxAgePresent && hstsHeader.maxAgeSeconds > HSTS_CHROME_MAX_AGE_CAP_ONE_YEAR {
		issues = issues.AddWarning(fmt.Sprintf(
			"The max-age (%d seconds) is longer than a year. Note that Chrome will round HSTS header max-age values down to 1 year (%d seconds).",
			hstsHeader.maxAgeSeconds,
			HSTS_CHROME_MAX_AGE_CAP_ONE_YEAR,
		))
	}

	if !hstsHeader.maxAgePresent && hstsHeader.maxAgeSeconds != BOGUS_MAX_AGE {
		issues = issues.AddWarning("Internal issue: encountered an HSTSHeader with maxAgePresent but an unexpected maxAgeSeconds.")
	}

	return issues
}

func CheckHeaderString(headerString string) Issues {
	hstsHeader, issues := ParseHeaderString(headerString)
	return CombineIssues(issues, CheckHeader(hstsHeader))
}
