package hstspreload

import (
	"fmt"
	"strings"
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
		Issues{Errors: []string{"Domain name error: begins with `.`"}}},

	{checkDomainFormat("example.com."),
		Issues{Errors: []string{"Domain name error: ends with `.`"}}},

	{checkDomainFormat("example..com"),
		Issues{Errors: []string{"Domain name error: contains `..`"}}},

	{checkDomainFormat("example"),
		Issues{Errors: []string{"Domain name error: must have at least two labels."}}},

	{checkDomainFormat("example&co.com"),
		Issues{Errors: []string{"Domain name error: contains invalid characters."}}},
}

func TestCheckDomainFormat(t *testing.T) {
	for _, tt := range testCheckDomainFormatTests {
		if !issuesEqual(tt.actual, tt.expected) {
			t.Errorf(issuesShouldBeEqual, tt.actual, tt.expected)
		}
	}
}

var testCheckEffectiveTLDPlusOne = []struct {
	actual   Issues
	expected Issues
}{
	{checkEffectiveTLDPlusOne("subdomain.example.com"),
		Issues{Errors: []string{"Domain error: `subdomain.example.com` is a subdomain. Please preload `example.com` instead. The interaction of cookies, HSTS and user behaviour is complex; we believe that only accepting whole domains is simple enough to have clear security semantics."}}},
}

func TestCheckEffectiveTLDPlusOne(t *testing.T) {
	for _, tt := range testCheckEffectiveTLDPlusOne {
		if !issuesEqual(tt.actual, tt.expected) {
			t.Errorf(issuesShouldBeEqual, tt.actual, tt.expected)
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
			Errors: []string{
				"Domain error: `incomplete-chain.badssl.com` is a subdomain. Please preload `badssl.com` instead. The interaction of cookies, HSTS and user behaviour is complex; we believe that only accepting whole domains is simple enough to have clear security semantics.",
				"TLS Error: We cannot connect to https://incomplete-chain.badssl.com using TLS (\"Get https://incomplete-chain.badssl.com: x509: certificate signed by unknown authority\"). This might be caused by an incomplete certificate chain, which causes issues on mobile devices. Check out your site at https://www.ssllabs.com/ssltest/",
			},
		},
	},
	{
		PreloadableDomain,
		"SHA-1",
		"sha1.badssl.com",
		false, "",
		Issues{
			Errors: []string{
				"Domain error: `sha1.badssl.com` is a subdomain. Please preload `badssl.com` instead. The interaction of cookies, HSTS and user behaviour is complex; we believe that only accepting whole domains is simple enough to have clear security semantics.",
				"TLS error: One or more of the certificates in your certificate chain is signed using SHA-1. This needs to be replaced. See https://security.googleblog.com/2015/12/an-update-on-sha-1-certificates-in.html. (The first SHA-1 certificate found has a common-name of \"*.badssl.com\".)",
				"Response error: No HSTS header is present on the response.",
			},
		},
	},
	{
		PreloadableDomain,
		"subdomain",
		"en.wikipedia.org",
		true, "max-age=31536000; includeSubDomains; preload",
		Issues{Errors: []string{"Domain error: `en.wikipedia.org` is a subdomain. Please preload `wikipedia.org` instead. The interaction of cookies, HSTS and user behaviour is complex; we believe that only accepting whole domains is simple enough to have clear security semantics."}},
	},
	{
		PreloadableDomain,
		"no HSTS",
		"example.com",
		false, "",
		Issues{
			Errors: []string{
				"Response error: No HSTS header is present on the response.",
				"Redirect error: `http://example.com` does not redirect to `https://example.com`.",
			},
		},
	},
	// Don't run this test like normal. See TestPreloadableDomainBogusDomain().
	// {
	// 	PreloadableDomain,
	// 	"bogus domain",
	// 	"example.notadomain",
	// 	false, "",
	// 	Issues{Errors: []string{"TLS Error: We cannot connect to https://example.notadomain using TLS (\"Get https://example.notadomain: dial tcp: lookup example.notadomain: no such host\"). This might be caused by an incomplete certificate chain, which causes issues on mobile devices. Check out your site at https://www.ssllabs.com/ssltest/"}},
	// },

	/******** RemovableDomain() ********/

	{
		RemovableDomain,
		"no header",
		"example.com",
		false, "",
		Issues{Errors: []string{"Response error: No HSTS header is present on the response."}},
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
		Issues{Errors: []string{"Header requirement error: For preload list removal, the header must not contain the `preload` directive."}},
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

		if !issuesEqual(issues, tt.expectedIssues) {
			t.Errorf("[%s] %s: "+issuesShouldBeEqual, tt.description, tt.domain, issues, tt.expectedIssues)
		}
	}
}

func TestPreloadableDomainBogusDomain(t *testing.T) {
	skipIfShort(t)

	// The error message contains a local IP in Travis CI. Since this is the only
	// such test, we work around it with more crude checks.
	header, issues := PreloadableDomain("example.notadomain")
	expectNil(t, header)
	if len(issues.Errors) != 1 || len(issues.Warnings) != 0 {
		t.Errorf("Expected one error and no warnings.")
	}
	if !strings.HasPrefix(issues.Errors[0], "TLS Error: We cannot connect to https://example.notadomain using TLS (\"Get https://example.notadomain: dial tcp: lookup example.notadomain") {
		t.Errorf("Expected one issues.")
	}
	if !strings.HasSuffix(issues.Errors[0], "no such host\"). This might be caused by an incomplete certificate chain, which causes issues on mobile devices. Check out your site at https://www.ssllabs.com/ssltest/") {
		t.Errorf("Expected one issues.")
	}
}
