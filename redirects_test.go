package hstspreload

import (
	"fmt"
	"net/url"
	"testing"
)

func chainsEqual(actual []*url.URL, expected []string) bool {
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

var tooManyRedirectsTests = []struct {
	description    string
	url            string
	expectedChain  []string
	expectedIssues Issues
}{
	{
		"almost too many redirects",
		"https://httpbin.org/redirect/3",
		[]string{"https://httpbin.org/relative-redirect/2", "https://httpbin.org/relative-redirect/1", "https://httpbin.org/get"},
		Issues{},
	},
	{
		"too many redirects",
		"https://httpbin.org/redirect/4",
		[]string{"https://httpbin.org/relative-redirect/3", "https://httpbin.org/relative-redirect/2", "https://httpbin.org/relative-redirect/1", "https://httpbin.org/get"},
		Issues{Errors: []string{"Redirect error: More than 3 redirects from `https://httpbin.org/redirect/4`."}},
	},
}

func TestTooManyRedirects(t *testing.T) {
	skipIfShort(t)
	for _, tt := range tooManyRedirectsTests {
		chain, issues := preloadableRedirects(tt.url)
		if !chainsEqual(chain, tt.expectedChain) {
			t.Errorf("[%s] Unexpected chain: %v", tt.description, chain)
		}

		if !issuesEqual(issues, tt.expectedIssues) {
			t.Errorf("[%s] "+issuesShouldBeEqual, tt.description, issues, tt.expectedIssues)
		}
	}
}

func TestInsecureRedirect(t *testing.T) {
	skipIfShort(t)
	u := "https://httpbin.org/redirect-to?url=http://httpbin.org"

	chain, issues := preloadableRedirects(u)
	if !chainsEqual(chain, []string{"http://httpbin.org"}) {
		t.Errorf("Unexpected chain: %v", chain)
	}
	if !issuesEmpty(issues) {
		t.Errorf(issuesShouldBeEmpty, issues)
	}

	httpsIssues := preloadableHTTPSRedirectsURL(u)
	expected := Issues{Errors: []string{"Redirect error: `https://httpbin.org/redirect-to?url=http://httpbin.org` redirects to an insecure page: `http://httpbin.org`"}}
	if !issuesEqual(httpsIssues, expected) {
		t.Errorf(issuesShouldBeEqual, httpsIssues, expected)
	}
}

func TestIndirectInsecureRedirect(t *testing.T) {
	skipIfShort(t)
	u := "https://httpbin.org/redirect-to?url=https://httpbin.org/redirect-to?url=http://httpbin.org"

	chain, issues := preloadableRedirects(u)
	if !chainsEqual(chain, []string{"https://httpbin.org/redirect-to?url=http://httpbin.org", "http://httpbin.org"}) {
		t.Errorf("Unexpected chain: %v", chain)
	}
	if !issuesEmpty(issues) {
		t.Errorf(issuesShouldBeEmpty, issues)
	}

	httpsIssues := preloadableHTTPSRedirectsURL(u)
	expected := Issues{Errors: []string{"Redirect error: `https://httpbin.org/redirect-to?url=https://httpbin.org/redirect-to?url=http://httpbin.org` redirects to an insecure page on redirect #2: `http://httpbin.org`"}}
	if !issuesEqual(httpsIssues, expected) {
		t.Errorf(issuesShouldBeEqual, httpsIssues, expected)
	}
}

func TestHTTPNoRedirect(t *testing.T) {
	skipIfShort(t)
	u := "http://httpbin.org"
	domain := "httpbin.org"

	chain, issues := preloadableRedirects(u)
	if !chainsEqual(chain, []string{}) {
		t.Errorf("Unexpected chain: %v", chain)
	}

	if !issuesEmpty(issues) {
		t.Errorf(issuesShouldBeEmpty, issues)
	}

	mainIssues, firstRedirectHSTSIssues := preloadableHTTPRedirectsURL(u, domain)
	expected := Issues{Errors: []string{"Redirect error: `http://httpbin.org` does not redirect to `https://httpbin.org`."}}
	if !issuesEqual(mainIssues, expected) {
		t.Errorf(issuesShouldBeEqual, mainIssues, expected)
	}

	if !issuesEmpty(firstRedirectHSTSIssues) {
		t.Errorf(issuesShouldBeEmpty, firstRedirectHSTSIssues)
	}
}

var preloadableHTTPRedirectsTests = []struct {
	description                     string
	domain                          string
	expectedMainIssues              Issues
	expectedFirstRedirectHSTSIssues Issues
}{
	{
		"different host",
		"bofa.com", // http://bofa.com redirects to https://www.bankofamerica.com
		Issues{Errors: []string{"Redirect error: `http://bofa.com` (HTTP) redirects to `https://www.bankofamerica.com/vanity/redirect.go?src=/`. The first redirect from `http://bofa.com` should be to a secure page on the same host (`https://bofa.com`)."}},
		Issues{},
	},
	{
		"same origin",
		"www.wikia.com", // http://www.wikia.com redirects to http://www.wikia.com/fandom
		Issues{Errors: []string{"Redirect error: `http://www.wikia.com` (HTTP) redirects to `http://www.wikia.com/fandom`. The first redirect from `http://www.wikia.com` should be to a secure page on the same host (`https://www.wikia.com`)."}},
		Issues{},
	},
	{
		"www first and > 3 redirects",
		"blogger.com",
		Issues{
			Errors: []string{
				"Redirect error: More than 3 redirects from `http://blogger.com`.",
				"Redirect error: `http://blogger.com` (HTTP) should immediately redirect to `https://blogger.com` (HTTPS) before adding the www subdomain. Right now, the first redirect is to `http://www.blogger.com/`.",
			},
		},
		Issues{},
	},
	{
		"correct origin but not HSTS",
		"sha256.badssl.com",
		Issues{},
		Issues{Errors: []string{"Redirect error: `http://sha256.badssl.com` redirects to `https://sha256.badssl.com/`, which does not serve a HSTS header that satisfies preload conditions. First error: Response error: No HSTS header is present on the response."}},
	},
}

func TestPreloadableHTTPRedirects(t *testing.T) {
	skipIfShort(t)
	for _, tt := range preloadableHTTPRedirectsTests {
		mainIssues, firstRedirectHSTSIssues := preloadableHTTPRedirects(tt.domain)

		if !issuesEqual(mainIssues, tt.expectedMainIssues) {
			t.Errorf("[%s] main issues for %s: "+issuesShouldBeEqual, tt.description, tt.domain, mainIssues, tt.expectedMainIssues)
		}

		if !issuesEqual(firstRedirectHSTSIssues, tt.expectedFirstRedirectHSTSIssues) {
			t.Errorf("[%s] first redirect HSTS issues for %s: "+issuesShouldBeEqual, tt.description, tt.domain, issuesShouldBeEmpty, tt.expectedFirstRedirectHSTSIssues)
		}
	}
}
