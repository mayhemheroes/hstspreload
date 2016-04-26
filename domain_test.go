package hstspreload

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
)

const (
	headersStringsShouldBeEqual = `Did not receive expected header.
			Actual: %v
			Expected: %v`
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
		NewIssues().addErrorf("Domain name error: begins with `.`")},

	{checkDomainFormat("example.com."),
		NewIssues().addErrorf("Domain name error: ends with `.`")},

	{checkDomainFormat("example..com"),
		NewIssues().addErrorf("Domain name error: contains `..`")},

	{checkDomainFormat("example"),
		NewIssues().addErrorf("Domain name error: must have at least two labels.")},

	{checkDomainFormat("example&co.com"),
		NewIssues().addErrorf("Domain name error: contains invalid characters.")},
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
		NewIssues().addErrorf("Domain error: `subdomain.example.com` is a subdomain. Please preload `example.com` instead. The interaction of cookies, HSTS and user behaviour is complex; we believe that only accepting whole domains is simple enough to have clear security semantics.")},
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
	description    string
	domain         string
	expectHeader   bool
	expectedHeader string
	expectedIssues Issues
}{

	/********* preloadable ********/

	{
		"valid HSTS",
		"wikipedia.org",
		true, "max-age=31536000; includeSubDomains; preload",
		Issues{},
	},

	/********* not preloadable ********/

	{
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
		"subdomain",
		"en.wikipedia.org",
		true, "max-age=31536000; includeSubDomains; preload",
		NewIssues().addErrorf("Domain error: `en.wikipedia.org` is a subdomain. Please preload `wikipedia.org` instead. The interaction of cookies, HSTS and user behaviour is complex; we believe that only accepting whole domains is simple enough to have clear security semantics."),
	},
	{
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
	// 	"bogus domain",
	// 	"example.notadomain",
	// 	false, "",
	// 	NewIssues().addErrorf("TLS Error: We cannot connect to https://example.notadomain using TLS (\"Get https://example.notadomain: dial tcp: lookup example.notadomain: no such host\"). This might be caused by an incomplete certificate chain, which causes issues on mobile devices. Check out your site at https://www.ssllabs.com/ssltest/"),
	// },
}

func TestPreloadableDomain(t *testing.T) {
	skipIfShort(t)

	for _, tt := range preloadableDomainTests {
		header, issues := PreloadableDomain(tt.domain)

		if tt.expectHeader {
			if header == nil {
				t.Errorf("[%s] %s: Did not receive exactly one HSTS header", tt.description, tt.domain)
			} else if *header != tt.expectedHeader {
				t.Errorf("[%s] %s: "+headersStringsShouldBeEqual, tt.description, tt.domain, header, tt.expectedHeader)
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

	if !issuesEmpty(issues) {
		t.Errorf(issuesShouldBeEmpty, issues)
	}
}

func TestTooManyRedirects(t *testing.T) {
	skipIfShort(t)
	chain, issues := checkRedirects("https://httpbin.org/redirect/4")
	if !chainEquals(chain, []string{"https://httpbin.org/relative-redirect/3", "https://httpbin.org/relative-redirect/2", "https://httpbin.org/relative-redirect/1", "https://httpbin.org/get"}) {
		t.Errorf("Unexpected chain: %v", chain)
	}

	expected := Issues{Errors: []string{"Redirect error: More than 3 redirects from `https://httpbin.org/redirect/4`."}}
	if !issuesEqual(issues, expected) {
		t.Errorf(issuesShouldBeEqual, issues, expected)
	}
}

func TestInsecureRedirect(t *testing.T) {
	skipIfShort(t)
	u := "https://httpbin.org/redirect-to?url=http://httpbin.org"

	chain, issues := checkRedirects(u)
	if !chainEquals(chain, []string{"http://httpbin.org"}) {
		t.Errorf("Unexpected chain: %v", chain)
	}
	if !issuesEmpty(issues) {
		t.Errorf(issuesShouldBeEmpty, issues)
	}

	httpsIssues := checkHTTPSRedirectsURL(u)
	expected := Issues{Errors: []string{"Redirect error: `https://httpbin.org/redirect-to?url=http://httpbin.org` redirects to an insecure page: `http://httpbin.org`"}}
	if !issuesEqual(httpsIssues, expected) {
		t.Errorf(issuesShouldBeEqual, httpsIssues, expected)
	}
}

func TestIndirectInsecureRedirect(t *testing.T) {
	skipIfShort(t)
	u := "https://httpbin.org/redirect-to?url=https://httpbin.org/redirect-to?url=http://httpbin.org"

	chain, issues := checkRedirects(u)
	if !chainEquals(chain, []string{"https://httpbin.org/redirect-to?url=http://httpbin.org", "http://httpbin.org"}) {
		t.Errorf("Unexpected chain: %v", chain)
	}
	if !issuesEmpty(issues) {
		t.Errorf(issuesShouldBeEmpty, issues)
	}

	httpsIssues := checkHTTPSRedirectsURL(u)
	expected := Issues{Errors: []string{"Redirect error: `https://httpbin.org/redirect-to?url=https://httpbin.org/redirect-to?url=http://httpbin.org` redirects to an insecure page on redirect #2: `http://httpbin.org`"}}
	if !issuesEqual(httpsIssues, expected) {
		t.Errorf(issuesShouldBeEqual, httpsIssues, expected)
	}
}

func TestHTTPNoRedirect(t *testing.T) {
	skipIfShort(t)
	u := "http://httpbin.org"
	domain := "httpbin.org"

	chain, issues := checkRedirects(u)
	if !chainEquals(chain, []string{}) {
		t.Errorf("Unexpected chain: %v", chain)
	}

	if !issuesEmpty(issues) {
		t.Errorf(issuesShouldBeEmpty, issues)
	}

	mainIssues, firstRedirectHSTSIssues := checkHTTPRedirectsURL(u, domain)
	expected := Issues{Errors: []string{"Redirect error: `http://httpbin.org` does not redirect to `https://httpbin.org`."}}
	if !issuesEqual(mainIssues, expected) {
		t.Errorf(issuesShouldBeEqual, mainIssues, expected)
	}

	if !issuesEmpty(firstRedirectHSTSIssues) {
		t.Errorf(issuesShouldBeEmpty, firstRedirectHSTSIssues)
	}
}

func TestHTTPWrongHostRedirect(t *testing.T) {
	skipIfShort(t)
	// http://bofa.com redirects to https://www.bankofamerica.com
	mainIssues, firstRedirectHSTSIssues := checkHTTPRedirects("bofa.com")

	expected := Issues{Errors: []string{"Redirect error: `http://bofa.com` (HTTP) redirects to `https://www.bankofamerica.com/vanity/redirect.go?src=/`. The first redirect from `http://bofa.com` should be to a secure page on the same host (`https://bofa.com`)."}}
	if !issuesEqual(mainIssues, expected) {
		t.Errorf(issuesShouldBeEqual, mainIssues, expected)
	}

	if !issuesEmpty(firstRedirectHSTSIssues) {
		t.Errorf(issuesShouldBeEmpty, firstRedirectHSTSIssues)
	}
}

func TestHTTPSameOriginRedirect(t *testing.T) {
	skipIfShort(t)
	// http://www.wikia.com redirects to http://www.wikia.com/fandom
	mainIssues, firstRedirectHSTSIssues := checkHTTPRedirects("www.wikia.com")

	expected := Issues{Errors: []string{"Redirect error: `http://www.wikia.com` (HTTP) redirects to `http://www.wikia.com/fandom`. The first redirect from `http://www.wikia.com` should be to a secure page on the same host (`https://www.wikia.com`)."}}
	if !issuesEqual(mainIssues, expected) {
		t.Errorf(issuesShouldBeEqual, mainIssues, expected)
	}

	if !issuesEmpty(firstRedirectHSTSIssues) {
		t.Errorf(issuesShouldBeEmpty, firstRedirectHSTSIssues)
	}
}

func TestHTTPRedirectWWWFirst(t *testing.T) {
	skipIfShort(t)
	mainIssues, firstRedirectHSTSIssues := checkHTTPRedirects("blogger.com")

	expected := Issues{
		Errors: []string{
			"Redirect error: More than 3 redirects from `http://blogger.com`.",
			"Redirect error: `http://blogger.com` (HTTP) should immediately redirect to `https://blogger.com` (HTTPS) before adding the www subdomain. Right now, the first redirect is to `http://www.blogger.com/`.",
		},
	}
	if !issuesEqual(mainIssues, expected) {
		t.Errorf(issuesShouldBeEqual, mainIssues, expected)
	}

	if !issuesEmpty(firstRedirectHSTSIssues) {
		t.Errorf(issuesShouldBeEmpty, firstRedirectHSTSIssues)
	}
}

func TestHTTPRedirectToCorrectOriginButNotHSTS(t *testing.T) {
	skipIfShort(t)
	mainIssues, firstRedirectHSTSIssues := checkHTTPRedirects("sha256.badssl.com")

	if !issuesEmpty(mainIssues) {
		t.Errorf(issuesShouldBeEmpty, mainIssues)
	}

	expected := Issues{Errors: []string{"Redirect error: `http://sha256.badssl.com` redirects to `https://sha256.badssl.com/`, which does not serve a HSTS header that satisfies preload conditions. First error: Response error: No HSTS header is present on the response."}}
	if !issuesEqual(firstRedirectHSTSIssues, expected) {
		t.Errorf(issuesShouldBeEmpty, firstRedirectHSTSIssues)
	}
}

var removableDomainTests = []struct {
	description    string
	domain         string
	expectHeader   bool
	expectedHeader string
	expectedIssues Issues
}{
	{
		"no header",
		"example.com",
		false, "",
		Issues{Errors: []string{"Response error: No HSTS header is present on the response."}},
	},
	{
		"no preload directive",
		"hsts.badssl.com",
		true, "max-age=15768000; includeSubDomains",
		Issues{},
	},
	{
		"preloaded",
		"preloaded-hsts.badssl.com",
		true, "max-age=15768000; includeSubDomains; preload",
		Issues{Errors: []string{"Header requirement error: For preload list removal, the header must not contain the `preload` directive."}},
	},
}

func TestRemovableDomain(t *testing.T) {
	skipIfShort(t)

	for _, tt := range removableDomainTests {
		header, issues := RemovableDomain(tt.domain)

		if tt.expectHeader {
			if header == nil {
				t.Errorf("[%s] %s: Did not receive exactly one HSTS header", tt.description, tt.domain)
			} else if *header != tt.expectedHeader {
				t.Errorf("[%s] %s: "+headersStringsShouldBeEqual, tt.description, tt.domain, header, tt.expectedHeader)
			}
		}

		if !issuesEqual(issues, tt.expectedIssues) {
			t.Errorf("[%s] %s: "+issuesShouldBeEqual, tt.description, tt.domain, issues, tt.expectedIssues)
		}
	}
}
