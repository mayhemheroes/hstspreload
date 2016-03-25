package hstspreload

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"syscall"
	"time"
)

// Checks whether the domain passes HSTS preload requirements for Chromium.
// This includes:
//
//   - Serving a single HSTS header that passes header requirements.
//   - Using TLS settings that will not cause new problems for
//     Chromium/Chrome users.
//     - Example of a new problem: a missing intermediate certificate
//       will turn an error page from overrideable to non-overridable on
//       some mobile devices.
//
// To interpret the result, see the list of conventions in the
// documentation for `Issues`.
//
// Example usage:
//
//     issues := CheckDomain("wikipedia.org")
func CheckDomain(domain string) Issues {
	issues := NewIssues()

	// TODO: Use TLS.dial
	response, err := http.Get("https://" + domain)
	if err != nil {
		// cannot continue => return early
		return issues.addError(fmt.Sprintf("Domain error: Cannot connect to domain (%s). Error: [%s]", domain, err))
	}

	issues = combineIssues(issues, checkTLS(domain))

	// TODO: Verify chain conditions, check subdomains, handle redirects, etc.

	return combineIssues(issues, CheckResponse(response))
}

// func certificateSubjectSummary(cert *x509.Certificate) string {
// 	switch {
// 	case len(cert.DNSNames) > 2:
// 		return fmt.Sprintf("[%s, %s, ...]", cert.DNSNames[0], cert.DNSNames[1])
// 	case len(cert.DNSNames) == 2:
// 		// It's common to have a certificate for example.com and www.example.com
// 		return fmt.Sprintf("[%s, %s]", cert.DNSNames[0], cert.DNSNames[1])
// 	case len(cert.DNSNames) == 1:
// 		return fmt.Sprintf("[%s]", cert.DNSNames[0])
// 	default:
// 		return fmt.Sprintf("%v", cert.Subject.Organization)
// 	}
// }

// func checkTLS(connectionState *tls.ConnectionState) Issues {
// 	issues := NewIssues()
// 	// chain := connectionState.PeerCertificates

// 	// We only check the chain sent by the certificate, not the verified chain.
// 	// Since a missing certificate is a fatal error, this means the domain ultimately
// 	// needs to present a full chain without SHA-1 in order to check out.

// 	if firstSHA1, foundSHA1 := findPropertyInChain(isSHA1, connectionState.PeerCertificates); foundSHA1 {
// 		issues = issues.addError(fmt.Sprintf(
// 			"Certificate error: The server sent a SHA-1 certificate (issued to %s by %s).",
// 			certificateSubjectSummary(firstSHA1),
// 			firstSHA1.Issuer.Organization,
// 		))
// 	}

// 	if firstECDSA, foundECDSA := findPropertyInChain(isECDSA, connectionState.PeerCertificates); foundECDSA {
// 		// TODO: allow if redirecting to HTTP.
// 		issues = issues.addError(fmt.Sprintf(
// 			"Certificate error: The server sent an ECDSA certificate (issued to %s by %s).",
// 			certificateSubjectSummary(firstECDSA),
// 			firstECDSA.Issuer.Organization,
// 		))
// 	}

// 	return issues
// }

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

func checkTLS(host string) Issues {
	issues := NewIssues()

	conn, err := tls.DialWithDialer(&dialer, "tcp", host+":443", nil)
	if err != nil {
		return issues.addError(fmt.Sprintf("Cannot connect using TLS (%q). This might be caused by an incomplete certificate chain, which causes issues on mobile devices. Check out your site at https://ssllabs.com.", err))
	}
	chain := certChain(conn.ConnectionState())
	conn.Close()

	if firstSHA1, ok := findPropertyInChain(isSHA1, chain); ok && chain[0].NotAfter.Year() >= 2016 {
		return issues.addError(fmt.Sprintf("One or more of the certificates in your certificate chain is signed with SHA-1, but the leaf certificate extends into 2016. This needs to be replaced. See https://security.googleblog.com/2015/12/an-update-on-sha-1-certificates-in.html. (The first SHA-1 certificate found has a common-name of %q.)", firstSHA1.Subject.CommonName))
	}

	if firstECDSA, ok := findPropertyInChain(isECDSA, chain); ok {
		// There's an ECDSA certificate. Allow it if HTTP redirects to
		// HTTPS with ECDSA or if port 80 is closed.
		resp, err := http.Get("http://" + host)

		var ecdsaOk bool
		var redirectMsg string

		if err == nil {
			if resp.TLS != nil {
				_, ecdsaOk = findPropertyInChain(isECDSA, certChain(*resp.TLS))
				if !ecdsaOk {
					redirectMsg = fmt.Sprintf("HTTP redirected to %q, but that site doesn't have an ECDSA certificate", resp.Request.URL)
				}
			} else {
				redirectMsg = fmt.Sprintf("HTTP didn't redirect to an HTTPS URL")
			}
			resp.Body.Close()
		} else if isConnectionRefused(err) {
			ecdsaOk = true
		} else {
			redirectMsg = fmt.Sprintf("Looking for a redirect from HTTP resulted in an error: %q", err)
		}

		if !ecdsaOk {
			return issues.addError(fmt.Sprintf("One or more of the certificates in your certificate chain use ECDSA. However, ECDSA can't be handled on Windows XP so adding your site would break it on that platform. If you don't care about Windows XP, you can have a blanket redirect from HTTP to HTTPS. (The first ECDSA certificate found has a common-name of %q. %s)", firstECDSA.Subject.CommonName, redirectMsg))
		}
	}

	hasWWW := false
	if conn, err := net.DialTimeout("tcp", "www."+host+":443", dialTimeout); err == nil {
		hasWWW = true
		conn.Close()
	}

	if hasWWW {
		wwwConn, err := tls.DialWithDialer(&dialer, "tcp", "www."+host+":443", nil)
		if err != nil {
			return issues.addError(fmt.Sprintf("The www subdomain exists, but we couldn't connect to it (%q). Since many people type this by habit, HSTS preloading would likely cause issues for your site.", err))
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
