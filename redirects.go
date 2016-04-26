package hstspreload

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
)

func preloadableHTTPRedirects(domain string) (mainIssues Issues, firstRedirectHSTSIssues Issues) {
	return preloadableHTTPRedirectsURL("http://"+domain, domain)
}

func preloadableHTTPSRedirects(domain string) Issues {
	return preloadableHTTPSRedirectsURL("https://" + domain)
}

func preloadableRedirectChain(initialURL string, chain []*url.URL) (issues Issues) {
	for i, u := range chain {
		if u.Scheme != httpsScheme {
			if i == 0 {
				return issues.addErrorf("Redirect error: `%s` redirects to an insecure page: `%s`", initialURL, u)
			} else {
				return issues.addErrorf("Redirect error: `%s` redirects to an insecure page on redirect #%d: `%s`", initialURL, i+1, u)
			}
		}
	}
	return issues
}

// Taking a URL allows us to test more easily. Use preloadableHTTPRedirects()
// where possible.
func preloadableHTTPRedirectsURL(initialURL string, domain string) (mainIssues Issues, firstRedirectHSTSIssues Issues) {
	chain, issues := preloadableRedirects(initialURL)
	if len(chain) == 0 {
		return issues.addErrorf(
			"Redirect error: `%s` does not redirect to `%s`.",
			initialURL,
			"https://"+domain,
		), firstRedirectHSTSIssues
	}

	if chain[0].Scheme == httpsScheme && chain[0].Host == domain {
		// Check for HSTS on the first redirect.
		resp, err := clientWithTimeout.Get(chain[0].String())
		if err != nil {
			// We cannot connect this time. This error has high priority,
			// so return immediately and allow it to mask other errors.
			return mainIssues, firstRedirectHSTSIssues.addErrorf(
				"Redirect error: `%s` redirects to `%s`, which we could not connect to: %s",
				initialURL,
				chain[0],
				err,
			)
		} else {
			_, redirectHSTSIssues := PreloadableResponse(resp)
			if len(redirectHSTSIssues.Errors) > 0 {
				firstRedirectHSTSIssues = firstRedirectHSTSIssues.addErrorf(
					"Redirect error: `%s` redirects to `%s`, which does not serve a HSTS header that satisfies preload conditions. First error: %s",
					initialURL,
					chain[0],
					redirectHSTSIssues.Errors[0],
				)
			}
		}

		mainIssues = combineIssues(mainIssues, preloadableRedirectChain(initialURL, chain))
		return mainIssues, firstRedirectHSTSIssues
	} else if chain[0].Host == "www."+domain {
		// For simplicity, we use the same message for two cases:
		// - http://example.com -> http://www.example.com
		// - http://example.com -> https://www.example.com
		return issues.addErrorf(
			"Redirect error: `%s` (HTTP) should immediately redirect to `%s` (HTTPS) "+
				"before adding the www subdomain. Right now, the first redirect is to `%s`.",
			initialURL,
			"https://"+domain,
			chain[0],
		), firstRedirectHSTSIssues
	} else {
		return issues.addErrorf(
			"Redirect error: `%s` (HTTP) redirects to `%s`. The first redirect "+
				"from `%s` should be to a secure page on the same host (`%s`).",
			initialURL,
			chain[0],
			initialURL,
			"https://"+domain,
		), firstRedirectHSTSIssues
	}
}

// Taking a URL allows us to test more easily. Use preloadableHTTPSRedirects()
// where possible.
func preloadableHTTPSRedirectsURL(initialURL string) Issues {
	chain, issues := preloadableRedirects(initialURL)
	return combineIssues(issues, preloadableRedirectChain(initialURL, chain))
}

func preloadableRedirects(initialURL string) (chain []*url.URL, issues Issues) {
	var redirectChain []*url.URL
	tooManyRedirects := errors.New("TOO_MANY_REDIRECTS")

	client := http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			redirectChain = append(redirectChain, req.URL)

			if len(redirectChain) > maxRedirects {
				issues = issues.addErrorf("Redirect error: More than %d redirects from `%s`.", maxRedirects, initialURL)
				return tooManyRedirects
			}

			return nil
		},
		Timeout: dialTimeout,
	}

	_, err := client.Get(initialURL)
	if err != nil {
		if !strings.HasSuffix(err.Error(), tooManyRedirects.Error()) {
			issues = issues.addErrorf("Redirect error: %s", err.Error())
		}
	}

	return redirectChain, issues
}
