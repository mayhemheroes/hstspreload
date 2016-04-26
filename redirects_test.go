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

func TestAlmostTooManyRedirects(t *testing.T) {
	skipIfShort(t)
	chain, issues := preloadableRedirects("https://httpbin.org/redirect/3")
	if !chainsEqual(chain, []string{"https://httpbin.org/relative-redirect/2", "https://httpbin.org/relative-redirect/1", "https://httpbin.org/get"}) {
		t.Errorf("Unexpected chain: %v", chain)
	}

	if !issuesEmpty(issues) {
		t.Errorf(issuesShouldBeEmpty, issues)
	}
}

func TestTooManyRedirects(t *testing.T) {
	skipIfShort(t)
	chain, issues := preloadableRedirects("https://httpbin.org/redirect/4")
	if !chainsEqual(chain, []string{"https://httpbin.org/relative-redirect/3", "https://httpbin.org/relative-redirect/2", "https://httpbin.org/relative-redirect/1", "https://httpbin.org/get"}) {
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

func TestHTTPWrongHostRedirect(t *testing.T) {
	skipIfShort(t)
	// http://bofa.com redirects to https://www.bankofamerica.com
	mainIssues, firstRedirectHSTSIssues := preloadableHTTPRedirects("bofa.com")

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
	mainIssues, firstRedirectHSTSIssues := preloadableHTTPRedirects("www.wikia.com")

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
	mainIssues, firstRedirectHSTSIssues := preloadableHTTPRedirects("blogger.com")

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
	mainIssues, firstRedirectHSTSIssues := preloadableHTTPRedirects("sha256.badssl.com")

	if !issuesEmpty(mainIssues) {
		t.Errorf(issuesShouldBeEmpty, mainIssues)
	}

	expected := Issues{Errors: []string{"Redirect error: `http://sha256.badssl.com` redirects to `https://sha256.badssl.com/`, which does not serve a HSTS header that satisfies preload conditions. First error: Response error: No HSTS header is present on the response."}}
	if !issuesEqual(firstRedirectHSTSIssues, expected) {
		t.Errorf(issuesShouldBeEmpty, firstRedirectHSTSIssues)
	}
}
