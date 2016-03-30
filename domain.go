package hstspreload

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"golang.org/x/net/publicsuffix"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// dialTimeout specifies the amount of time that TCP or TLS connections
	// can take to complete.
	dialTimeout = 10 * time.Second
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
		issues = combineIssues(issues, checkChain(certChain(*resp.TLS), domain))
		issues = combineIssues(issues, CheckResponse(*resp))

		// Skip the WWW check if the domain is not eTLD+1.
		if len(eTLD1Issues.Errors) == 0 {
			issues = combineIssues(issues, checkWWW(domain))
		}
	}

	return issues
}

func getResponse(domain string) (resp *http.Response, issues Issues) {
	redirectPrevented := errors.New("REDIRECT_PREVENTED")

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return redirectPrevented
		},
	}

	resp, err := client.Get("https://" + domain)
	if err != nil {
		if urlError, ok := err.(*url.Error); !ok || urlError.Err != redirectPrevented {
			return resp, issues.addErrorf(
				"Cannot connect using TLS (%q). This might be caused by an incomplete "+
					"certificate chain, which causes issues on mobile devices. "+
					"Check out your site at https://www.ssllabs.com/ssltest/",
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
			"Domain error: `%s` is not eTLD+1. Please preload `%s` instead.",
			domain,
			canon,
		)
	}

	return issues
}

// Takes the domain as argument because we may need to make more network
// connections to see if an ECDSA cert is permissible.
func checkChain(chain []*x509.Certificate, domain string) (issues Issues) {
	issues = combineIssues(issues, checkSHA1(chain))

	return issues
}

func checkSHA1(chain []*x509.Certificate) (issues Issues) {
	if firstSHA1, found := findPropertyInChain(isSHA1, chain); found {
		issues = issues.addErrorf(
			"One or more of the certificates in your certificate chain is signed with SHA-1. "+
				"This needs to be replaced. "+
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
				"The www subdomain exists, but we couldn't connect to it (%q). "+
					"Since many people type this by habit, HSTS preloading would likely"+
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
