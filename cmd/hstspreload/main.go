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
  removabledomain   (-d) Check the TLS configuration and headers of a domain for
                         removal requirements.
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

	var hstsHeader *string
	var issues hstspreload.Issues

	bolded := color.New(color.Bold).SprintFunc()

	switch args[0] {
	case "+h":
		fallthrough
	case "preloadableheader":
		fmt.Printf("Checking header \"%s\" for preload requirements...\n", bolded(args[1]))
		issues = hstspreload.PreloadableHeaderString(args[1])

	case "-h":
		fallthrough
	case "removableheader":
		fmt.Printf("Checking header \"%s\" for removal requirements...\n", bolded(args[1]))
		issues = hstspreload.RemovableHeaderString(args[1])

	case "+d":
		fallthrough
	case "preloadabledomain":
		if strings.HasPrefix(args[1], "http") {
			fmt.Fprintf(os.Stderr,
				"Invalid argument: Please do not supply a scheme (http:// or https://) before the domain.\n")
			os.Exit(3)
		}
		fmt.Printf("Checking domain %s for preload requirements...\n", bolded(args[1]))
		hstsHeader, issues = hstspreload.PreloadableDomain(args[1])

	case "-d":
		fallthrough
	case "removabledomain":
		if strings.HasPrefix(args[1], "http") {
			fmt.Fprintf(os.Stderr,
				"Invalid argument: Please do not supply a scheme (http:// or https://) before the domain.\n")
			os.Exit(3)
		}
		fmt.Printf("Checking domain %s for removal requirements...\n", bolded(args[1]))
		hstsHeader, issues = hstspreload.RemovableDomain(args[1])

	default:
		fmt.Printf("Unknown command: %s\n", args[0])
		os.Exit(3)
	}

	// Wrap this in a function to (statically) enforce a return code.
	showResult := func() int {
		bold := color.New(color.Bold)

		fmt.Printf("\n")
		switch {
		case len(issues.Errors) > 0:
			if hstsHeader != nil {
				fmt.Printf("Observed header: ")
				bold.Printf("%s\n\n", *hstsHeader)
			}
			return 1

		case len(issues.Warnings) > 0:
			if hstsHeader != nil {
				fmt.Printf("Observed header: ")
				bold.Printf("%s\n\n", *hstsHeader)
			}
			return 2

		default:
			if hstsHeader != nil {
				fmt.Printf("Observed header: ")
				bold.Printf("%s\n\n", *hstsHeader)
			}
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
