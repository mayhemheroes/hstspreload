package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"

	"github.com/chromium/hstspreload"
)

const (
	parallelism = 10
)

type Result struct {
	Domain string
	Header *string
	Issues hstspreload.Issues
}

func Scan(domains []string) (results []Result) {
	c := make(chan Result)

	parallel := make(chan int)
	for i := 0; i < parallelism; i++ {
		parallel <- i
	}

	// TODO: parallelism semaphore
	for _, domain := range domains {
		go func(d string) {
			fmt.Printf("%s...\n", d)
			i := <-parallel
			fmt.Printf("[%d] %s...\n", i, d)
			header, issues := hstspreload.PreloadableDomain(d)
			fmt.Printf("[%d] ✅  %s\n", i, d)
			c <- Result{d, header, issues}
			parallel <- i
		}(domain)
	}

	for _, _ = range domains {
		results = append(results, <-c)
	}
	return results
}

func main() {

	var domains []string
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		domains = append(domains, sc.Text())
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "%s", err)
		os.Exit(1)
	}

	j, err := json.MarshalIndent(Scan(domains), "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s", err)
		os.Exit(1)
	}
	fmt.Printf("%s", j)
}
