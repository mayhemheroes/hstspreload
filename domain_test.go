package hstspreload

import (
	"fmt"
	"testing"
)

func ExamplePreloadableDomain() {
	header, issues := PreloadableDomain("wikipedia.org")
	if header != nil {
		fmt.Printf("Header: %s", *header)
	}
	fmt.Printf("Issues %v", issues)
}

/******** Utility functions tests. ********/

var testCheckDomainFormatTests = []struct {
	actual   Issues
	expected Issues
}{
	{checkDomainFormat(".example.com"),
		Issues{Errors: []Issue{Issue{Code: "domain.format.begins_with_dot"}}},
	},
	{checkDomainFormat("example.com."),
		Issues{Errors: []Issue{Issue{Code: "domain.format.ends_with_dot"}}},
	},
	{checkDomainFormat("example..com"),
		Issues{Errors: []Issue{Issue{Code: "domain.format.contains_double_dot"}}},
	},
	{checkDomainFormat("example"),
		Issues{Errors: []Issue{Issue{Code: "domain.format.only_one_label"}}},
	},
	{checkDomainFormat("example&co.com"),
		Issues{Errors: []Issue{Issue{Code: "domain.format.invalid_characters"}}},
	},
}

func TestCheckDomainFormat(t *testing.T) {
	for _, tt := range testCheckDomainFormatTests {
		if !issuesMatchExpected(tt.actual, tt.expected) {
			t.Errorf(issuesShouldMatch, tt.actual, tt.expected)
		}
	}
}

var testPreloadableDomainLevel = []struct {
	actual   Issues
	expected Issues
}{
	{preloadableDomainLevel("subdomain.example.com"),
		Issues{Errors: []Issue{Issue{
			Code:    "domain.is_subdomain",
			Message: "`subdomain.example.com` is a subdomain. Please preload `example.com` instead. (Due to the size of the preload list and the behaviour of cookies across subdomains, we only accept automated preload list submissions of whole registered domains.)",
		}}},
	},
}

func TestPreloadableDomainLevel(t *testing.T) {
	for _, tt := range testPreloadableDomainLevel {
		if !issuesMatchExpected(tt.actual, tt.expected) {
			t.Errorf(issuesShouldMatch, tt.actual, tt.expected)
		}
	}
}

/******** Real domain tests. ********/

// Avoid hitting the network for short tests.
// This gives us performant, deterministic, and offline testing.
func skipIfShort(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping domain test.")
	}
}

var preloadableDomainTests = []struct {
	function       func(domain string) (header *string, issues Issues)
	description    string
	domain         string
	expectHeader   bool
	expectedHeader string
	expectedIssues Issues
}{

	/********* PreloadableDomain() ********/

	{
		PreloadableDomain,
		"valid HSTS",
		"wikipedia.org",
		true, "max-age=31536000; includeSubDomains; preload",
		Issues{},
	},
	{
		PreloadableDomain,
		"incomplete chain",
		"incomplete-chain.badssl.com",
		false, "",
		Issues{
			Errors: []Issue{
				Issue{Code: "domain.is_subdomain"},
				Issue{
					Code:    "domain.tls.cannot_connect",
					Message: "We cannot connect to https://incomplete-chain.badssl.com using TLS (\"Get https://incomplete-chain.badssl.com: x509: certificate signed by unknown authority\"). This might be caused by an incomplete certificate chain, which causes issues on mobile devices. Check out your site at https://www.ssllabs.com/ssltest/",
				},
			},
		},
	},
	{
		PreloadableDomain,
		"SHA-1",
		"sha1.badssl.com",
		false, "",
		Issues{
			Errors: []Issue{
				Issue{Code: "domain.is_subdomain"},
				Issue{
					Code:    "domain.tls.sha1",
					Message: "One or more of the certificates in your certificate chain is signed using SHA-1. This needs to be replaced. See https://security.googleblog.com/2015/12/an-update-on-sha-1-certificates-in.html. (The first SHA-1 certificate found has a common-name of \"*.badssl.com\".)",
				},
				Issue{Code: "response.no_header"},
			},
		},
	},
	{
		PreloadableDomain,
		"subdomain",
		"en.wikipedia.org",
		true, "max-age=31536000; includeSubDomains; preload",
		Issues{Errors: []Issue{Issue{
			Code:    "domain.is_subdomain",
			Message: "`en.wikipedia.org` is a subdomain. Please preload `wikipedia.org` instead. (Due to the size of the preload list and the behaviour of cookies across subdomains, we only accept automated preload list submissions of whole registered domains.)",
		}}},
	},
	{
		PreloadableDomain,
		"no HSTS",
		"example.com",
		false, "",
		Issues{
			Errors: []Issue{
				Issue{Code: "response.no_header"},
				Issue{
					Code:    "redirects.http.no_redirect",
					Message: "`http://example.com` does not redirect to `https://example.com`.",
				},
			},
		},
	},
	// Don't run this test like normal. See TestPreloadableDomainBogusDomain().
	{
		PreloadableDomain,
		"bogus domain",
		"example.notadomain",
		false, "",
		Issues{Errors: []Issue{Issue{Code: "domain.tls.cannot_connect"}}},
	},

	/******** RemovableDomain() ********/

	{
		RemovableDomain,
		"no header",
		"example.com",
		false, "",
		Issues{Errors: []Issue{Issue{Code: "response.no_header"}}},
	},
	{
		RemovableDomain,
		"no preload directive",
		"hsts.badssl.com",
		true, "max-age=15768000; includeSubDomains",
		Issues{},
	},
	{
		RemovableDomain,
		"preloaded",
		"preloaded-hsts.badssl.com",
		true, "max-age=15768000; includeSubDomains; preload",
		Issues{Errors: []Issue{Issue{Code: "header.removable.contains.preload"}}},
	},
}

func TestPreloadableDomainAndRemovableDomain(t *testing.T) {
	skipIfShort(t)

	for _, tt := range preloadableDomainTests {
		header, issues := tt.function(tt.domain)

		if tt.expectHeader {
			if header == nil {
				t.Errorf("[%s] %s: Did not receive exactly one HSTS header", tt.description, tt.domain)
			} else if *header != tt.expectedHeader {
				t.Errorf("[%s] %s: "+headerStringsShouldBeEqual, tt.description, tt.domain, *header, tt.expectedHeader)
			}
		} else {
			if header != nil {
				t.Errorf("[%s] %s: Did not expect a header, but received `%s`", tt.description, tt.domain, *header)
			}
		}

		if !issuesMatchExpected(issues, tt.expectedIssues) {
			t.Errorf("[%s] %s: "+issuesShouldMatch, tt.description, tt.domain, issues, tt.expectedIssues)
		}
	}
}

// func TestPreloadableDomainBogusDomain(t *testing.T) {
// 	skipIfShort(t)

// 	// The error message contains a local IP in Travis CI. Since this is the only
// 	// such test, we work around it with more crude checks.
// 	header, issues := PreloadableDomain("example.notadomain")
// 	if header != nil {
// 		t.Errorf("Did not expect a header, but received `%s`", *header)
// 	}
// 	if len(issues.Errors) != 1 || len(issues.Warnings) != 0 {
// 		t.Errorf("Expected one error and no warnings.")
// 	}
// 	if !strings.HasPrefix(issues.Errors[0], "TLS Error: We cannot connect to https://example.notadomain using TLS (\"Get https://example.notadomain: dial tcp: lookup example.notadomain") {
// 		t.Errorf("Expected one issues.")
// 	}
// 	if !strings.HasSuffix(issues.Errors[0], "no such host\"). This might be caused by an incomplete certificate chain, which causes issues on mobile devices. Check out your site at https://www.ssllabs.com/ssltest/") {
// 		t.Errorf("Expected one issues.")
// 	}
// }
