package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/chromium/hstspreload"
)

const (
	parallelism = 100
)

// A Result holds the outcome of PreloadableDomain() for a given Domain.
type Result struct {
	Domain       string                 `json:"domain"`
	Header       string                 `json:"header,omitempty"`
	ParsedHeader hstspreload.HSTSHeader `json:"parsed_header,omitempty"`
	Issues       hstspreload.Issues     `json:"issues"`
}

func worker(in chan string, out chan Result) {
	for d := range in {

		header, issues := hstspreload.PreloadableDomain(d)

		r := Result{
			Domain: d,
			Issues: issues,
		}
		if header != nil {
			r.Header = *header
			ParsedHeader, _ := hstspreload.ParseHeaderString(*header)
			r.ParsedHeader = ParsedHeader
		}

		out <- r
	}
}

// BatchPreloadable runs hstspreload.PreloadableDomain() over the given domains
// in parallel, and returns the results in an arbitrary order.
func BatchPreloadable(domains []string) chan Result {
	in := make(chan string)
	out := make(chan Result)
	for i := 0; i < parallelism; i++ {
		go worker(in, out)
	}

	go func() {
		for _, d := range domains {
			in <- d
		}
	}()

	results := make(chan Result)
	go func() {
		for range domains {
			results <- (<-out)
		}
		close(in)
		close(out)
		close(results)
	}()

	return results
}

// BatchPrint runs BatchPreloadable on the given domains and prints the results.
// Prints and returns an error if one was encountered.
func BatchPrint(domains []string) error {
	fmt.Println("[")
	results := BatchPreloadable(domains)
	for i := range domains {
		r := <-results
		j, err := json.MarshalIndent(r, "  ", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "// JSON error: %s \n", err)
			return err
		}
		comma := ""
		if i != len(domains)-1 {
			comma = ","
		}
		fmt.Printf("  %s%s\n", j, comma)
	}
	fmt.Println("]")

	return nil
}
