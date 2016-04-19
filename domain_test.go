package hstspreload

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
)

func ExampleCheckDomain() {
	issues := CheckDomain("wikipedia.org")
	fmt.Printf("%v", issues)
}

/******** Utility functions tests. ********/

func TestCheckDomainFormat(t *testing.T) {
	expectIssuesEqual(t, checkDomainFormat(".example.com"),
		NewIssues().addErrorf("Domain name error: begins with `.`"))
	expectIssuesEqual(t, checkDomainFormat("example.com."),
		NewIssues().addErrorf("Domain name error: ends with `.`"))
	expectIssuesEqual(t, checkDomainFormat("example..com"),
		NewIssues().addErrorf("Domain name error: contains `..`"))
	expectIssuesEqual(t, checkDomainFormat("example"),
		NewIssues().addErrorf("Domain name error: must have at least two labels."))
	expectIssuesEqual(t, checkDomainFormat("example&co.com"),
		NewIssues().addErrorf("Domain name error: contains invalid characters."))
}

func TestCheckEffectiveTLDPlusOne(t *testing.T) {
	expectIssuesEqual(t, checkEffectiveTLDPlusOne("subdomain.example.com"),
		NewIssues().addErrorf("Domain error: `subdomain.example.com` is a subdomain. Please preload `example.com` instead. The interaction of cookies, HSTS and user behaviour is complex; we believe that only accepting whole domains is simple enough to have clear security semantics."))
}

/******** Real domain tests. ********/

// Avoid hitting the network for short tests.
// This gives us performant, deterministic, and offline testing.
func skipIfShort(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping domain test.")
	}
}

func TestCheckDomainIncompleteChain(t *testing.T) {
	skipIfShort(t)
	expectIssuesEqual(t, CheckDomain("incomplete-chain.badssl.com"),
		Issues{
			Errors: []string{
				"Domain error: `incomplete-chain.badssl.com` is a subdomain. Please preload `badssl.com` instead. The interaction of cookies, HSTS and user behaviour is complex; we believe that only accepting whole domains is simple enough to have clear security semantics.",
				"TLS Error: We cannot connect to https://incomplete-chain.badssl.com using TLS (\"Get https://incomplete-chain.badssl.com: x509: certificate signed by unknown authority\"). This might be caused by an incomplete certificate chain, which causes issues on mobile devices. Check out your site at https://www.ssllabs.com/ssltest/",
			},
			Warnings: []string{},
		},
	)
}

func TestCheckDomainSHA1(t *testing.T) {
	skipIfShort(t)
	expectIssuesEqual(t, CheckDomain("sha1.badssl.com"),
		Issues{
			Errors: []string{
				"Domain error: `sha1.badssl.com` is a subdomain. Please preload `badssl.com` instead. The interaction of cookies, HSTS and user behaviour is complex; we believe that only accepting whole domains is simple enough to have clear security semantics.",
				"TLS error: One or more of the certificates in your certificate chain is signed using SHA-1. This needs to be replaced. See https://security.googleblog.com/2015/12/an-update-on-sha-1-certificates-in.html. (The first SHA-1 certificate found has a common-name of \"*.badssl.com\".)",
				"Response error: No HSTS header is present on the response.",
			},
			Warnings: []string{},
		},
	)
}

func TestCheckDomainWithValidHSTS(t *testing.T) {
	skipIfShort(t)
	expectIssuesEmpty(t, CheckDomain("wikipedia.org"))
}

func TestCheckDomainSubdomain(t *testing.T) {
	skipIfShort(t)
	expectIssuesEqual(t, CheckDomain("en.wikipedia.org"),
		NewIssues().addErrorf("Domain error: `en.wikipedia.org` is a subdomain. Please preload `wikipedia.org` instead. The interaction of cookies, HSTS and user behaviour is complex; we believe that only accepting whole domains is simple enough to have clear security semantics."),
	)
}

func TestCheckDomainWithoutHSTS(t *testing.T) {
	skipIfShort(t)
	expectIssuesEqual(t, CheckDomain("example.com"),
		Issues{
			Errors: []string{
				"Response error: No HSTS header is present on the response.",
				"Redirect error: `http://example.com` does not redirect to `https://example.com`.)",
			},
			Warnings: []string{},
		})
}

func TestCheckDomainBogusDomain(t *testing.T) {
	skipIfShort(t)

	// The error message contains a local IP in Travis CI. Since this is the only
	// such test, we work around it with more crude checks.
	issues := CheckDomain("example.notadomain")
	if len(issues.Errors) != 1 || len(issues.Warnings) != 0 {
		t.Errorf("Expected one error and no warnings.")
	}
	if !strings.HasPrefix(issues.Errors[0], "TLS Error: We cannot connect to https://example.notadomain using TLS (\"Get https://example.notadomain: dial tcp: lookup example.notadomain") {
		t.Errorf("Expected one issues.")
	}
	if !strings.HasSuffix(issues.Errors[0], "no such host\"). This might be caused by an incomplete certificate chain, which causes issues on mobile devices. Check out your site at https://www.ssllabs.com/ssltest/") {
		t.Errorf("Expected one issues.")
	}

	// Normal test
	// expectIssuesEqual(t, CheckDomain("example.notadomain"),
	// 	NewIssues().addErrorf("TLS Error: We cannot connect to https://example.notadomain using TLS (\"Get https://example.notadomain: dial tcp: lookup example.notadomain: no such host\"). This might be caused by an incomplete certificate chain, which causes issues on mobile devices. Check out your site at https://www.ssllabs.com/ssltest/"))
}

func chainEquals(actual []*url.URL, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}
	for i, u := range actual {
		if fmt.Sprintf("%s", u) != expected[i] {
			return false
		}
	}
	return true
}

func TestAlmostTooManyRedirects(t *testing.T) {
	skipIfShort(t)
	chain, issues := checkRedirects("https://httpbin.org/redirect/3")
	if !chainEquals(chain, []string{"https://httpbin.org/relative-redirect/2", "https://httpbin.org/relative-redirect/1", "https://httpbin.org/get"}) {
		t.Errorf("Unexpected chain: %v", chain)
	}
	expectIssuesEmpty(t, issues)
}

func TestTooManyRedirects(t *testing.T) {
	skipIfShort(t)
	chain, issues := checkRedirects("https://httpbin.org/redirect/4")
	if !chainEquals(chain, []string{"https://httpbin.org/relative-redirect/3", "https://httpbin.org/relative-redirect/2", "https://httpbin.org/relative-redirect/1", "https://httpbin.org/get"}) {
		t.Errorf("Unexpected chain: %v", chain)
	}
	expectIssuesEqual(
		t,
		issues,
		Issues{
			Errors: []string{"Redirect error: More than 3 redirects from `https://httpbin.org/redirect/4`."},
		},
	)
}

func TestInsecureRedirect(t *testing.T) {
	skipIfShort(t)
	chain, issues := checkRedirects("https://httpbin.org/redirect-to?url=http://httpbin.org")
	if !chainEquals(chain, []string{"http://httpbin.org"}) {
		t.Errorf("Unexpected chain: %v", chain)
	}
	expectIssuesEqual(
		t,
		issues,
		Issues{
			Errors: []string{"Redirect error: `https://httpbin.org/redirect-to?url=http://httpbin.org` redirects to an insecure page: `http://httpbin.org`"},
		},
	)
}

func TestIndirectInsecureRedirect(t *testing.T) {
	skipIfShort(t)
	chain, issues := checkRedirects("https://httpbin.org/redirect-to?url=https://httpbin.org/redirect-to?url=http://httpbin.org")
	if !chainEquals(chain, []string{"https://httpbin.org/redirect-to?url=http://httpbin.org", "http://httpbin.org"}) {
		t.Errorf("Unexpected chain: %v", chain)
	}
	expectIssuesEqual(
		t,
		issues,
		Issues{
			Errors: []string{"Redirect error: `https://httpbin.org/redirect-to?url=https://httpbin.org/redirect-to?url=http://httpbin.org` redirects to an insecure page on redirect #2: `http://httpbin.org`"},
		},
	)
}

func TestHTTPNoRedirect(t *testing.T) {
	skipIfShort(t)
	issues := checkHTTPRedirects("httpbin.org")
	expectIssuesEqual(
		t,
		issues,
		Issues{
			Errors:   []string{"Redirect error: `http://httpbin.org` does not redirect to `https://httpbin.org`.)"},
			Warnings: []string{},
		},
	)
}

func TestHTTPWrongHostRedirect(t *testing.T) {
	skipIfShort(t)
	// http://bofa.com redirects to https://www.bankofamerica.com
	issues := checkHTTPRedirects("bofa.com")
	expectIssuesEqual(
		t,
		issues,
		Issues{
			Errors:   []string{"Redirect error: the first redirect from `http://bofa.com` is not to a secure page on the same host (`https://bofa.com`). It is to `https://www.bankofamerica.com/vanity/redirect.go?src=/` instead."},
			Warnings: []string{},
		},
	)
}

func TestHTTPSameOriginRedirect(t *testing.T) {
	skipIfShort(t)
	// http://www.wikia.com redirects to http://www.wikia.com/fandom
	issues := checkHTTPRedirects("www.wikia.com")
	expectIssuesEqual(
		t,
		issues,
		Issues{
			Errors:   []string{"Redirect error: `http://www.wikia.com` redirects to an insecure page: `http://www.wikia.com/fandom`"},
			Warnings: []string{},
		},
	)
}
