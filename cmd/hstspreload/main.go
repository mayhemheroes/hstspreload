package main

import (
	"flag"
	"fmt"
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

  checkheader    Check an HSTS header for preload requirements
  checkdomain    Check the TLS configuration and headers of a domain for
                 preload requirements.

Examples:

  hstspreload checkheader "max-age=10886400; includeSubDomains; preload"
  hstspreload checkdomain wikipedia.org

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
	case "checkheader":
		issues = hstspreload.CheckHeaderString(args[1])

	case "checkdomain":
		if strings.HasPrefix(args[1], "http") {
			fmt.Fprintf(os.Stderr,
				"Invalid argument: Please do not supply a scheme (http:// or https://) before the domain.\n")
			os.Exit(3)
		}
		issues = hstspreload.CheckDomain(args[1])

	default:
		os.Exit(4)
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
