package hstspreload

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"golang.org/x/net/publicsuffix"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
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
func CheckDomain(domain string) Issues {
	issues := NewIssues()

	// Check domain format issues first, since we can report something
	// useful even if the other checks fail.
	issues = combineIssues(issues, checkDomainFormat(domain))

	// We don't currently allow automatic submissions of subdomains.
	eTLD1Issues := checkEffectiveTLDPlusOne(domain)
	issues = combineIssues(issues, eTLD1Issues)

	// Start with an initial probe, and don't do the follow-up checks if
	// we can't connect.
	response, responseIssues := getResponse(domain)
	issues = combineIssues(issues, responseIssues)
	if len(responseIssues.Errors) == 0 {
		issues = combineIssues(issues, checkChain(certChain(*response.TLS), domain))
		issues = combineIssues(issues, CheckResponse(*response))

		// Skip the WWW check if the domain is not eTLD+1.
		if len(eTLD1Issues.Errors) == 0 {
			issues = combineIssues(issues, checkWWW(domain))
		}
	}

	return issues
}

func getResponse(domain string) (*http.Response, Issues) {
	issues := NewIssues()

	redirectPrevented := errors.New("REDIRECT_PREVENTED")

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return redirectPrevented
		},
	}

	response, err := client.Get("https://" + domain)
	if err != nil {
		if urlError, ok := err.(*url.Error); !ok || urlError.Err != redirectPrevented {
			return response, issues.addErrorf(
				"Cannot connect using TLS (%q). This might be caused by an incomplete "+
					"certificate chain, which causes issues on mobile devices. "+
					"Check out your site at https://www.ssllabs.com/ssltest/",
				err,
			)
		}
	}

	return response, issues
}

func checkDomainFormat(domain string) Issues {
	issues := NewIssues()

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

func checkEffectiveTLDPlusOne(domain string) Issues {
	issues := NewIssues()

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
func checkChain(chain []*x509.Certificate, domain string) Issues {
	issues := NewIssues()

	issues = combineIssues(issues, checkSHA1(chain))
	issues = combineIssues(issues, checkECDSA(chain, domain))

	return issues
}

func checkSHA1(chain []*x509.Certificate) Issues {
	issues := NewIssues()

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

func checkECDSA(chain []*x509.Certificate, domain string) Issues {
	issues := NewIssues()

	if firstECDSA, found := findPropertyInChain(isECDSA, chain); found {
		// There's an ECDSA certificate. Allow it if HTTP redirects to
		// HTTPS with ECDSA or if port 80 is closed.
		resp, err := http.Get("http://" + domain)

		var ecdsaOk bool
		var redirectMsg string

		if err == nil {
			if resp.TLS != nil {
				_, ecdsaOk = findPropertyInChain(isECDSA, certChain(*resp.TLS))
				if !ecdsaOk {
					redirectMsg = fmt.Sprintf(
						"HTTP redirected to %q, but that site doesn't have an ECDSA certificate",
						resp.Request.URL,
					)
				}
			} else {
				redirectMsg = fmt.Sprintf(
					"HTTP didn't redirect to an HTTPS URL",
				)
			}
			resp.Body.Close()
		} else if isConnectionRefused(err) {
			ecdsaOk = true
		} else {
			issues = issues.addErrorf(
				"Looking for a redirect from HTTP resulted in an error: %q",
				err,
			)
		}

		if !ecdsaOk {
			issues = issues.addErrorf(
				"One or more of the certificates in your certificate chain use ECDSA. "+
					"However, ECDSA can't be handled on Windows XP so adding your site "+
					"would break it on that platform. If you don't care about Windows XP, "+
					"you can have a blanket redirect from HTTP to HTTPS. "+
					"(The first ECDSA certificate found has a common-name of %q. %s)",
				firstECDSA.Subject.CommonName,
				redirectMsg,
			)
		}
	}

	return issues
}

func checkWWW(host string) Issues {
	issues := NewIssues()

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

// isConnectionRefused returns true if err is an error from net/http that was
// caused because the TCP connection was refused.
func isConnectionRefused(err error) bool {
	urlErr, ok := err.(*url.Error)
	if !ok {
		return false
	}

	netErr, ok := urlErr.Err.(*net.OpError)
	if !ok {
		return false
	}

	if netErr.Op != "dial" {
		return false
	}

	syscallErr, ok := netErr.Err.(*os.SyscallError)
	if !ok {
		return false
	}

	return syscallErr.Err == syscall.ECONNREFUSED
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

func isECDSA(cert *x509.Certificate) bool {
	return cert.PublicKeyAlgorithm == x509.ECDSA
}
