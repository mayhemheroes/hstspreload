package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/chromium/hstspreload"
	"github.com/chromium/hstspreload/chromiumpreload"
)

func main() {
	args := os.Args[1:]

	if len(args) < 2 {
		fmt.Printf(`hstspreload is a tool for checking conditions to be added to Chromium 's
HSTS preload list. See hstspreload.appspot.com for more details.

Usage:

  hstspreload command argument

The commands are:

  preloadabledomain (+d) Check the TLS configuration and headers of a domain for
                         preload requirements.
  removabledomain   (-d) Check the headers of a domain for removal requirements.
  preloadableheader (+h) Check an HSTS header for preload requirements
  removableheader   (-h) Check an HSTS header for removal requirements
  status                 Check the preload status of a domain

Examples:

  hstspreload +d wikipedia.org
  hstspreload +h "max-age=10886400; includeSubDomains; preload"
  hstspreload -h "max-age=10886400; includeSubDomains"

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

	var header *string
	var issues hstspreload.Issues

	switch args[0] {
	case "+h":
		fallthrough
	case "preloadableheader":
		issues = preloadableHeader(args[1])

	case "-h":
		fallthrough
	case "removableheader":
		issues = removableHeader(args[1])

	case "+d":
		fallthrough
	case "preloadabledomain":
		header, issues = preloadableDomain(args[1])

	case "-d":
		fallthrough
	case "removabledomain":
		header, issues = removableDomain(args[1])

	case "status":
		l, err := chromiumpreload.GetLatest()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
		}
		m := chromiumpreload.PreloadEntriesToMap(l)
		fmt.Printf("Status: %v", m[chromiumpreload.Domain(args[1])])
		os.Exit(0)

	default:
		fmt.Printf("Unknown command: %s\n", args[0])
		os.Exit(3)
	}

	// Wrap this in a function to (statically) enforce a return code.
	showResult := func() int {
		if header != nil {
			fmt.Printf("Observed header: ")
			format(bold)
			fmt.Printf("%s\n", *header)
			format(reset)
		}

		fmt.Printf("\n")
		switch {
		case len(issues.Errors) > 0:
			return 1

		case len(issues.Warnings) > 0:
			return 2

		default:
			format(green)
			fmt.Printf("Satisfies requirements.\n\n")
			format(reset)
			return 0
		}
	}
	exitCode := showResult()

	printList(issues.Errors, "Error", red)
	printList(issues.Warnings, "Warning", yellow)

	os.Exit(exitCode)
}

func preloadableHeader(header string) (issues hstspreload.Issues) {
	expectHeaderOrWarn(header)

	fmt.Printf("Checking header \"")
	format(bold)
	fmt.Printf("%s", header)
	format(reset)
	fmt.Printf("\" for preload requirements...\n")

	return hstspreload.PreloadableHeaderString(header)
}

func removableHeader(header string) (issues hstspreload.Issues) {
	expectHeaderOrWarn(header)

	fmt.Printf("Checking header \"")
	format(bold)
	fmt.Printf("%s", header)
	format(reset)
	fmt.Printf("\" for removal requirements...\n")

	return hstspreload.RemovableHeaderString(header)
}

func preloadableDomain(domain string) (header *string, issues hstspreload.Issues) {
	expectDomainOrExit(domain)

	fmt.Printf("Checking domain ")
	format(underline)
	fmt.Printf("%s", domain)
	format(reset)
	fmt.Printf(" for preload requirements...\n")

	return hstspreload.PreloadableDomain(domain)
}

func removableDomain(domain string) (header *string, issues hstspreload.Issues) {
	expectDomainOrExit(domain)

	fmt.Printf("Checking domain ")
	format(underline)
	fmt.Printf("%s", domain)
	format(reset)
	fmt.Printf(" for removal requirements...\n")

	return hstspreload.RemovableDomain(domain)
}

func expectHeaderOrWarn(str string) {
	if probablyURL(str) {
		fmt.Fprintf(os.Stderr,
			"Warning: please supply an HSTS header string (it appears you supplied a URL).\n")
	}
	if probablyDomain(str) {
		fmt.Fprintf(os.Stderr,
			"Warning: please supply an HSTS header string (it appears you supplied a domain).\n")
	}
}

func expectDomainOrExit(str string) {
	if probablyHeader(str) {
		fmt.Fprintf(os.Stderr,
			"Invalid argument: please supply a domain (example.com), not a header string.\n")
		os.Exit(3)
	}

	if probablyURL(str) {
		fmt.Fprintf(os.Stderr,
			"Invalid argument: please supply a domain (example.com) rather than a URL (https://example.com/index.html).\n")
		os.Exit(3)
	}
}

func probablyHeader(str string) bool {
	return strings.Contains(str, ";") || strings.Contains(str, " ")
}

func probablyURL(str string) bool {
	return strings.HasPrefix(str, "http") || strings.Contains(str, ":") || strings.Contains(str, "/")
}

func probablyDomain(str string) bool {
	return strings.Contains(str, ".") && !strings.Contains(str, " ")
}

func printList(list []hstspreload.Issue, title string, fs string) {
	if len(list) == 0 {
		return
	}

	titlePluralized := title
	if len(list) != 1 {
		titlePluralized += "s"
	}
	format(fs)
	fmt.Printf("%s:\n", titlePluralized)
	format(reset)

	for i, is := range list {
		fmt.Printf("\n%d. ", i+1)
		format(fs)
		fmt.Printf("%s", is.Summary)
		format(reset)
		fmt.Printf(" [%s]\n%s\n", is.Code, is.Message)
	}

	fmt.Printf("\n")
}
