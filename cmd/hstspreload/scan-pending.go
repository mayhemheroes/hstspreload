package main

import (
	"encoding/json"
	"net/http"

	"github.com/chromium/hstspreload/chromium/preloadlist"
)

// ScanPending scans all pending submitted domains.
func ScanPending() error {
	domains, err := GetPending()
	if err != nil {
		return err
	}

	err = BatchPrint(domains)
	if err != nil {
		return err
	}

	return nil
}

// GetPending gets the list of pending domains from the submission site.
func GetPending() ([]string, error) {
	resp, err := http.Get("https://hstspreload.appspot.com/api/v2/pending")
	if err != nil {
		return []string{}, err
	}

	var entries []preloadlist.Entry
	err = json.NewDecoder(resp.Body).Decode(&entries)
	if err != nil {
		return []string{}, err
	}

	var domains []string
	for _, entry := range entries {
		domains = append(domains, entry.Name)
	}

	return domains, nil
}
