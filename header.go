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

	for _, part := range hstsParts {
		part = strings.ToLower(part)
		switch {
		case part == "preload":
			if hstsHeader.preload {
				issues.AddWarning("Header contains a repeated directive: `preload`")
			}
			hstsHeader.preload = true

		case strings.HasPrefix(part, "preload"):
			issues.AddWarning("Header contains a `preload` directive with extra parts.")

		case part == "includesubdomains":
			if hstsHeader.includeSubDomains {
				issues.AddWarning("Header contains a repeated directive: `includeSubDomains`")
			}
			hstsHeader.includeSubDomains = true

		case strings.HasPrefix(part, "includesubdomains"):
			issues.AddWarning("Header contains a `includesubdomains` directive with extra parts.")

		case strings.HasPrefix(part, "max-age="):
			maxAgeNumericalString := part[8:]
			// TODO the numerical string contains only digits, no symbols (no "+")
			maxAge, err := strconv.ParseUint(maxAgeNumericalString, 10, 63)
			if err != nil {
				issues = issues.AddError(fmt.Sprintf("Could not parse max-age value [%s].", maxAgeNumericalString))
			}
			if hstsHeader.maxAgePresent {
				issues.AddWarning(fmt.Sprintf("Header contains a repeated directive: `max-age`"))
			}
			hstsHeader.maxAgePresent = true
			hstsHeader.maxAgeSeconds = maxAge

		case strings.HasPrefix(part, "max-age"):
			issues = issues.AddError("A max-age directive name is present without an associated value.")

		case part == "":
			issues.AddWarning("Header includes an empty directive or extra semicolons.")

		default:
			issues.AddWarning(fmt.Sprintf("Header contains an unknown directive: `%s`", part))
		}
	}

	// TODO: show multiple errors
	// TODO: warn on repeated directives
	// TODO: Warn when max-age is longer than a year (Chrome will truncate)
	// TODO: Allow testing whether the header is valid according to the spec (vs. having all preload requirements)
	// TODO: warn on empty directives / extra semicolons

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

	if hstsHeader.maxAgePresent && hstsHeader.maxAgeSeconds < 10886400 {
		issues = issues.AddError(fmt.Sprintf(
			"The max-age must be at least 10886400 seconds (== 18 weeks), but the header only had max-age=%d.",
			hstsHeader.maxAgeSeconds,
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
