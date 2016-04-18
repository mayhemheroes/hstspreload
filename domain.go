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

// CheckDomain checks whether the domain passes HSTS preload
// requirements for Chromium. This includes:
//
// - Serving a single HSTS header that passes header requirements.
//
// - Using TLS settings that will not cause new problems for
// Chromium/Chrome users. (Example of a new problem: a missing intermediate certificate
// will turn an error page from overrideable to non-overridable on
// some mobile devices.)
//
// To interpret the result, see the list of conventions in the
// documentation for Issues.
func CheckDomain(domain string) (issues Issues) {
	// Check domain format issues first, since we can report something
	// useful even if the other checks fail.
	issues = combineIssues(issues, checkDomainFormat(domain))

	// We don't currently allow automatic submissions of subdomains.
	eTLD1Issues := checkEffectiveTLDPlusOne(domain)
	issues = combineIssues(issues, eTLD1Issues)

	// Start with an initial probe, and don't do the follow-up checks if
	// we can't connect.
	resp, respIssues := getResponse(domain)
	issues = combineIssues(issues, respIssues)
	if len(respIssues.Errors) == 0 {
		issues = combineIssues(issues, checkSHA1(certChain(*resp.TLS)))

		chan1 := make(chan Issues)
		chan2 := make(chan Issues)
		chan3 := make(chan Issues)
		chan4 := make(chan Issues)

		go func() { chan1 <- CheckResponse(*resp) }()
		go func() { chan2 <- checkRedirects("http://" + domain) }()
		go func() { chan3 <- checkRedirects("https://" + domain) }()
		go func() {
			// Skip the WWW check if the domain is not eTLD+1.
			if len(eTLD1Issues.Errors) == 0 {
				chan4 <- checkWWW(domain)
			}
			chan4 <- NewIssues()
		}()

		// Combine the issues in deterministic order.
		issues = combineIssues(issues, <-chan1)
		issues = combineIssues(issues, <-chan2)
		issues = combineIssues(issues, <-chan3)
		issues = combineIssues(issues, <-chan4)
	}

	return issues
}

func getResponse(domain string) (resp *http.Response, issues Issues) {
	redirectPrevented := errors.New("REDIRECT_PREVENTED")

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return redirectPrevented
		},
		Timeout: dialTimeout,
	}

	resp, err := client.Get("https://" + domain)
	if err != nil {
		if urlError, ok := err.(*url.Error); !ok || urlError.Err != redirectPrevented {
			return resp, issues.addErrorf(
				"TLS Error: We cannot connect to https://%s using TLS (%q). This "+
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
		return issues.addErrorf("Domain name error: begins with `.`")
	}
	if strings.HasSuffix(domain, ".") {
		return issues.addErrorf("Domain name error: ends with `.`")
	}
	if strings.Index(domain, "..") != -1 {
		return issues.addErrorf("Domain name error: contains `..`")
	}
	if strings.Count(domain, ".") < 1 {
		return issues.addErrorf("Domain name error: must have at least two labels.")
	}

	domain = strings.ToLower(domain)
	for _, r := range domain {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '.' {
			continue
		}

		return issues.addErrorf("Domain name error: contains invalid characters.")
	}

	return issues
}

func checkEffectiveTLDPlusOne(domain string) (issues Issues) {
	canon, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return issues.addErrorf("Internal error: could not compute eTLD+1.")
	}
	if canon != domain {
		return issues.addErrorf(
			"Domain error: `%s` is a subdomain. Please preload `%s` instead. "+
				"The interaction of cookies, HSTS and user behaviour is complex; "+
				"we believe that only accepting whole domains is simple enough to "+
				"have clear security semantics.",
			domain,
			canon,
		)
	}

	return issues
}

func checkRedirects(url string) (issues Issues) {
	var requestChain []*http.Request

	insecureRedirect := errors.New("INSECURE_REDIRECT")
	tooManyRedirects := errors.New("TOO_MANY_REDIRECTS")

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			requestChain = append(requestChain, req)

			if req.URL.Scheme != httpsScheme {
				if len(requestChain) == 1 {
					issues = issues.addErrorf("Redirect error: `%s` redirects to an insecure page: `%s`", url, req.URL)
				} else {
					issues = issues.addErrorf("Redirect error: `%s` redirects to an insecure page on redirect #%d: `%s`", url, len(requestChain), req.URL)
				}
				return insecureRedirect
			}

			if len(requestChain) > maxRedirects {
				issues = issues.addErrorf("Redirect error: More than %d redirects from `%s`.", maxRedirects, url)
				return tooManyRedirects
			}
			return nil
		},
		Timeout: dialTimeout,
	}

	_, err := client.Get(url)
	if err != nil {
		if !strings.HasSuffix(err.Error(), insecureRedirect.Error()) &&
			!strings.HasSuffix(err.Error(), tooManyRedirects.Error()) {
			issues = issues.addErrorf("Redirect error: %s", err.Error())
		}
	}

	return issues
}

func checkSHA1(chain []*x509.Certificate) (issues Issues) {
	if firstSHA1, found := findPropertyInChain(isSHA1, chain); found {
		issues = issues.addErrorf(
			"TLS error: One or more of the certificates in your certificate chain "+
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
				"Domain error: The www subdomain exists, but we couldn't connect to it (%q). "+
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
