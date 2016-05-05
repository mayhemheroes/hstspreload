package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"sync"

	"github.com/chromium/hstspreload"
)

const (
	parallelism = 10
)

// A Result holds the outcome of PreloadableDomain() for a given Domain.
type Result struct {
	Domain string
	Header *string
	Issues hstspreload.Issues
}

// Scan runs hstspreload.PreloadableDomain() over the given domains
// in parallel, and returns the results in an arbitrary order.
func Scan(domains []string) (results []Result) {
	in := make(chan string)
	out := make(chan Result)

	var wg sync.WaitGroup
	wg.Add(parallelism + 1)
	for i := 0; i < parallelism; i++ {
		go func(i int) {
			for true {
				d := <-in
				if d == "" {
					break
				}
				fmt.Printf("[%d] %s...\n", i, d)
				header, issues := hstspreload.PreloadableDomain(d)

				// Retry once.
				if len(issues.Errors) != 0 {
					fmt.Printf("[%d] retrying %s\n", i, d)
					header, issues = hstspreload.PreloadableDomain(d)
				}

				fmt.Printf("[%d] ✅  %s\n", i, d)

				r := Result{d, header, issues}

				j, err := json.MarshalIndent(r, "", "  ")
				if err != nil {
					fmt.Printf("[%d] %s ❌ json %s \n", i, d, err)
				} else {
					err = ioutil.WriteFile("domains/"+d+".json", j, 0644)
					if err != nil {
						fmt.Printf("[%d] %s ❌ write %s \n", i, d, err)
					}
				}

				out <- r
			}
			fmt.Printf("[%d] done\n", i)
			wg.Done()
		}(i)
	}

	go func() {
		for _ = range domains {
			results = append(results, <-out)
		}
		wg.Done()
	}()

	for _, d := range domains {
		in <- d
	}
	for i := 0; i < parallelism; i++ {
		in <- ""
	}

	wg.Wait()

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
	err = ioutil.WriteFile("output.json", j, 0644)
}
