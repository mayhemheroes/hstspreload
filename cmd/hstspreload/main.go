package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/chromium/hstspreload"
)

func main() {
	flag.Parse()
	args := flag.Args()

	if len(args) < 2 {
		fmt.Printf(`hstspreload is a tool for checking conditions to be added to Chromium 's
HSTS preload list. See hstspreload.appspot.com for more details.

Usage:

  hstspreload command argument

The commands are:

  header    Check an HSTS header for preload requirements
  url       Check the headers of a URL for preload requirements.
            Both http:// and https:// URLs can be checked, so the
            scheme must be specified.
  domain    Check the TLS configuration and headers of a domain for
            preload requirements.

Examples:

  hstspreload header "max-age=10886400; includeSubDomains; preload"
  hstspreload url http://localhost:8080
  hstspreload domain wikipedia.org

Return code:

  0    Passed all checks.
  1    Error (failed at least one requirement).
  2    Had warnings, but passed all requirements.
  3    Invalid commandline arguments
  4    Displayed help

`)
		os.Exit(4)
		return
	}

	var issues hstspreload.Issues

	switch args[0] {
	case "header":
		issues = hstspreload.CheckHeaderString(args[1])

	case "url":
		if !strings.HasPrefix(args[1], "http") {
			fmt.Fprintf(os.Stderr,
				"Invalid argument: Please supply a scheme (http:// or https://) for the URL.\n")
			os.Exit(3)
		}

		response, err := http.Get(args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not connect to URL: %s\n", args[1])
			os.Exit(3)
		}
		issues = hstspreload.CheckResponse(*response)

	case "domain":
		if strings.HasPrefix(args[1], "http") {
			fmt.Fprintf(os.Stderr,
				"Invalid argument: Please do not supply a scheme (http:// or https://) before the domain.\n")
			os.Exit(3)
		}
		issues = hstspreload.CheckDomain(args[1])
	}

	// TODO: Show the HSTS header sent by the domain.

	// Wrap this in a function to (statically) enforce a return code.
	showResult := func() int {
		switch {
		case len(issues.Errors) > 0:
			fmt.Printf("There were was at least one error.\n\n%v\n", issues)
			return 1

		case len(issues.Warnings) > 0:
			fmt.Printf("There were no errors, but at least one warning.\n\n%v\n", issues)
			return 2

		default:
			fmt.Printf("Satisfies requirements for preloading.\n")
			return 0
		}
	}

	os.Exit(showResult())
}
