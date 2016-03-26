package hstspreload

import (
	"fmt"
	"testing"
)

func ExampleCheckDomain() {
	issues := CheckDomain("wikipedia.org")
	fmt.Printf("%v", issues)
}

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
				"Domain error: not eTLD+1.",
				"Domain error: Cannot connect to domain (incomplete-chain.badssl.com). Error: [Get https://incomplete-chain.badssl.com: x509: certificate signed by unknown authority]",
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
				"Domain error: not eTLD+1.",
				"One or more of the certificates in your certificate chain is signed with SHA-1, but the leaf certificate extends into 2016. This needs to be replaced. See https://security.googleblog.com/2015/12/an-update-on-sha-1-certificates-in.html. (The first SHA-1 certificate found has a common-name of \"*.badssl.com\".)",
				"Response error: No HSTS headers are present on the response.",
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
		NewIssues().addErrorf("Domain error: not eTLD+1."),
	)
}

func TestCheckDomainWithoutHSTS(t *testing.T) {
	skipIfShort(t)
	expectIssuesEqual(t, CheckDomain("example.com"),
		NewIssues().addErrorf("Response error: No HSTS headers are present on the response."))
}

func TestCheckDomainBogusDomain(t *testing.T) {
	skipIfShort(t)
	expectIssuesEqual(t, CheckDomain("example.notadomain"),
		NewIssues().addErrorf("Domain error: Cannot connect to domain (example.notadomain). Error: [Get https://example.notadomain: dial tcp: lookup example.notadomain: no such host]"))
}

/******** Utility functions tests. ********/

func TestCheckDomainName(t *testing.T) {
	expectIssuesEqual(t, checkDomainName(".example.com"),
		NewIssues().addErrorf("Domain name error: begins with `.`"))
	expectIssuesEqual(t, checkDomainName("example.com."),
		NewIssues().addErrorf("Domain name error: ends with `.`"))
	expectIssuesEqual(t, checkDomainName("example..com"),
		NewIssues().addErrorf("Domain name error: contains `..`"))
	expectIssuesEqual(t, checkDomainName("example"),
		NewIssues().addErrorf("Domain name error: must have at least two labels."))
	expectIssuesEqual(t, checkDomainName("example&co.com"),
		NewIssues().addErrorf("Domain name error: contains invalid characters."))
	expectIssuesEqual(t, checkDomainName("subdomain.example.com"),
		NewIssues().addErrorf("Domain error: not eTLD+1."))
}
