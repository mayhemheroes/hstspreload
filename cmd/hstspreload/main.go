package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/chromium/hstspreload"
	"github.com/fatih/color"
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

	default:
		fmt.Printf("Unknown command: %s\n", args[0])
		os.Exit(3)
	}

	// Wrap this in a function to (statically) enforce a return code.
	showResult := func() int {
		bold := color.New(color.Bold)
		if header != nil {
			fmt.Printf("Observed header: ")
			bold.Printf("%s\n", *header)
		}

		fmt.Printf("\n")
		switch {
		case len(issues.Errors) > 0:
			return 1

		case len(issues.Warnings) > 0:
			return 2

		default:
			boldGreen := color.New(color.Bold, color.FgGreen)
			boldGreen.Printf("Satisfies requirements.\n\n")
			return 0
		}
	}
	exitCode := showResult()
	printList(issues.Errors, "Error", color.New(color.FgRed))
	printList(issues.Warnings, "Warning", color.New(color.FgYellow))
	os.Exit(exitCode)
}

func preloadableHeader(header string) (issues hstspreload.Issues) {
	expectHeaderOrWarn(header)
	bolded := color.New(color.Bold).SprintFunc()
	fmt.Printf("Checking header \"%s\" for preload requirements...\n", bolded(header))
	return hstspreload.PreloadableHeaderString(header)
}

func removableHeader(header string) (issues hstspreload.Issues) {
	expectHeaderOrWarn(header)
	bolded := color.New(color.Bold).SprintFunc()
	fmt.Printf("Checking header \"%s\" for removal requirements...\n", bolded(header))
	return hstspreload.RemovableHeaderString(header)
}

func preloadableDomain(domain string) (header *string, issues hstspreload.Issues) {
	expectDomainOrExit(domain)
	bolded := color.New(color.Bold).SprintFunc()
	fmt.Printf("Checking domain %s for preload requirements...\n", bolded(domain))
	return hstspreload.PreloadableDomain(domain)
}

func removableDomain(domain string) (header *string, issues hstspreload.Issues) {
	expectDomainOrExit(domain)
	bolded := color.New(color.Bold).SprintFunc()
	fmt.Printf("Checking domain %s for removal requirements...\n", bolded(domain))
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

func printList(list []string, title string, color *color.Color) {
	if len(list) == 0 {
		return
	}

	titlePluralized := title
	if len(list) != 1 {
		titlePluralized += "s"
	}
	color.Printf("%s:\n", titlePluralized)

	for i, s := range list {
		color.Printf("\n%d. %s\n", i+1, s)
	}

	color.Printf("\n")
}
