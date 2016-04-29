package hstspreload

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

const (
	// dialTimeout specifies the amount of time that TCP or TLS connections
	// can take to complete.
	dialTimeout = 10 * time.Second

	// The maximum number of redirects when you visit the root path of the
	// domain over HTTP or HTTPS.
	maxRedirects = 3
	httpsScheme  = "https"
)

// dialer is a global net.Dialer that's used whenever making TLS connections in
// order to enforce dialTimeout.
var dialer = net.Dialer{
	Timeout: dialTimeout,
}

var clientWithTimeout = http.Client{
	Timeout: dialTimeout,
}

// PreloadableDomain checks whether the domain passes HSTS preload
// requirements for Chromium. This includes:
//
// - Serving a single HSTS header that passes header requirements.
//
// - Using TLS settings that will not cause new problems for
// Chromium/Chrome users. (Example of a new problem: a missing intermediate certificate
// will turn an error page from overrideable to non-overridable on
// some mobile devices.)
//
// Iff a single HSTS header was received, `header` contains its value, else
// `header` is `nil`.
// To interpret `issues`, see the list of conventions in the
// documentation for Issues.
func PreloadableDomain(domain string) (header *string, issues Issues) {
	// Check domain format issues first, since we can report something
	// useful even if the other checks fail.
	issues = combineIssues(issues, checkDomainFormat(domain))
	if len(issues.Errors) > 0 {
		return header, issues
	}

	// We don't currently allow automatic submissions of subdomains.
	levelIssues := preloadableDomainLevel(domain)
	issues = combineIssues(issues, levelIssues)

	// Start with an initial probe, and don't do the follow-up checks if
	// we can't connect.
	resp, respIssues := getResponse(domain)
	issues = combineIssues(issues, respIssues)
	if len(respIssues.Errors) == 0 {
		issues = combineIssues(issues, checkSHA1(certChain(*resp.TLS)))

		chanPreloadableResponse := make(chan Issues)
		chanHTTPRedirects := make(chan Issues)
		chanHTTPFirstRedirectsHSTS := make(chan Issues)
		chanHTTPSRedirects := make(chan Issues)
		chanWWW := make(chan Issues)

		// PreloadableResponse
		go func() {
			var preloadableIssues Issues
			header, preloadableIssues = PreloadableResponse(resp)
			chanPreloadableResponse <- preloadableIssues
		}()

		// checkHTTPRedirects
		go func() {
			mainIssues, firstRedirectHSTSIssues := preloadableHTTPRedirects(domain)
			chanHTTPRedirects <- mainIssues
			chanHTTPFirstRedirectsHSTS <- firstRedirectHSTSIssues
		}()

		// checkHTTPSRedirects
		go func() {
			chanHTTPSRedirects <- preloadableHTTPSRedirects(domain)
		}()

		// checkWWW
		go func() {
			// Skip the WWW check if the domain is not eTLD+1.
			if len(levelIssues.Errors) == 0 {
				chanWWW <- checkWWW(domain)
			}
			chanWWW <- Issues{}
		}()

		// Combine the issues in deterministic order.
		preloadableResponseIssues := <-chanPreloadableResponse
		issues = combineIssues(issues, preloadableResponseIssues)
		issues = combineIssues(issues, <-chanHTTPRedirects)
		// If there are issues with the HSTS header in the main
		// PreloadableResponse() check, it is redundant to report
		// them in the response after redirecting from HTTP.
		if len(preloadableResponseIssues.Errors) == 0 {
			issues = combineIssues(issues, <-chanHTTPFirstRedirectsHSTS)
		}
		issues = combineIssues(issues, <-chanHTTPSRedirects)
		issues = combineIssues(issues, <-chanWWW)
	}

	return header, issues
}

// PreloadableDomain checks whether the domain passes HSTS preload
// requirements for Chromium. This includes:
//
// - Serving a single valid HSTS header.
//
// - The header must not contain the `preload` directive..
//
// Iff a single HSTS header was received, `header` contains its value, else
// `header` is `nil`.
// To interpret `issues`, see the list of conventions in the
// documentation for Issues.
func RemovableDomain(domain string) (header *string, issues Issues) {
	resp, respIssues := getResponse(domain)
	issues = combineIssues(issues, respIssues)
	if len(respIssues.Errors) == 0 {
		var removableIssues Issues
		header, removableIssues = RemovableResponse(resp)
		issues = combineIssues(issues, removableIssues)
	}

	return header, issues
}

func getResponse(domain string) (resp *http.Response, issues Issues) {
	redirectPrevented := errors.New("REDIRECT_PREVENTED")

	client := http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return redirectPrevented
		},
		Timeout: dialTimeout,
	}

	resp, err := client.Get("https://" + domain)
	if err != nil {
		if urlError, ok := err.(*url.Error); !ok || urlError.Err != redirectPrevented {
			return resp, issues.addErrorf(
				IssueCode("domain.tls.cannot_connect"),
				"Cannot connect using TLS",
				"We cannot connect to https://%s using TLS (%q). This "+
					"might be caused by an incomplete certificate chain, which causes "+
					"issues on mobile devices. Check out your site at "+
					"https://www.ssllabs.com/ssltest/",
				domain,
				err,
			)
		}
	}

	return resp, issues
}

func checkDomainFormat(domain string) (issues Issues) {
	if strings.HasPrefix(domain, ".") {
		return issues.addErrorf(
			IssueCode("domain.format.begins_with_dot"),
			"Invalid domain name",
			"Please provide a domain that does not begin with `.`")
	}
	if strings.HasSuffix(domain, ".") {
		return issues.addErrorf(
			IssueCode("domain.format.ends_with_dot"),
			"Invalid domain name",
			"Please provide a domain that does not begin with `.`")
	}
	if strings.Index(domain, "..") != -1 {
		return issues.addErrorf(
			IssueCode("domain.format.contains_double_dot"),
			"Invalid domain name",
			"Please provide a domain that does not contain `..`")
	}
	if strings.Count(domain, ".") < 1 {
		return issues.addErrorf(
			IssueCode("domain.format.only_one_label"),
			"Invalid domain name",
			"Please provide a domain with least two labels "+
				"(e.g. `example.com` rather than `example` or `com`).")
	}

	domain = strings.ToLower(domain)
	for _, r := range domain {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '.' {
			continue
		}

		return issues.addErrorf("domain.format.invalid_characters", "Invalid domain name", "Please provide a domain using valid characters (letters, numbers, dashes, dots).")
	}

	return issues
}

func preloadableDomainLevel(domain string) (issues Issues) {
	canon, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return issues.addErrorf("internal.domain.name.cannot_compute_etld1", "Internal Error", "Could not compute eTLD+1.")
	}
	if canon != domain {
		return issues.addErrorf(
			IssueCode("domain.is_subdomain"),
			"Subdomain",
			"`%s` is a subdomain. Please preload `%s` instead. "+
				"(Due to the size of the preload list and the behaviour of "+
				"cookies across subdomains, we only accept automated preload list "+
				"submissions of whole registered domains.)",
			domain,
			canon,
		)
	}

	return issues
}

func checkSHA1(chain []*x509.Certificate) (issues Issues) {
	if firstSHA1, found := findPropertyInChain(isSHA1, chain); found {
		issues = issues.addErrorf(
			IssueCode("domain.tls.sha1"),
			"SHA-1 Certificate",
			"One or more of the certificates in your certificate chain "+
				"is signed using SHA-1. This needs to be replaced. "+
				"See https://security.googleblog.com/2015/12/an-update-on-sha-1-certificates-in.html. "+
				"(The first SHA-1 certificate found has a common-name of %q.)",
			firstSHA1.Subject.CommonName,
		)
	}

	return issues
}

func checkWWW(host string) (issues Issues) {
	hasWWW := false
	if conn, err := net.DialTimeout("tcp", "www."+host+":443", dialTimeout); err == nil {
		hasWWW = true
		conn.Close()
	}

	if hasWWW {
		wwwConn, err := tls.DialWithDialer(&dialer, "tcp", "www."+host+":443", nil)
		if err != nil {
			return issues.addErrorf(
				IssueCode("domain.www.no_tls"),
				"www subdomain does not support HTTPS",
				"Domain error: The www subdomain exists, but we couldn't connect to it using HTTPS (%q). "+
					"Since many people type this by habit, HSTS preloading would likely "+
					"cause issues for your site.",
				err,
			)
		}
		wwwConn.Close()
	}

	return issues
}

func certChain(connState tls.ConnectionState) []*x509.Certificate {
	chain := connState.VerifiedChains[0]
	return chain[:len(chain)-1]
}

func findPropertyInChain(pred func(*x509.Certificate) bool, chain []*x509.Certificate) (*x509.Certificate, bool) {
	for _, cert := range chain {
		if pred(cert) {
			return cert, true
		}
	}

	return nil, false
}

func isSHA1(cert *x509.Certificate) bool {
	switch cert.SignatureAlgorithm {
	case x509.SHA1WithRSA, x509.ECDSAWithSHA1:
		return true
	default:
		return false
	}
}
