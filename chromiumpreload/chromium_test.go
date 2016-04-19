package chromiumpreload

import (
	"testing"
)

func TestGetLatest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test to avoid preload list download.")
	}

	preloadList, err := GetLatest()
	if err != nil {
		t.Errorf("Could not retrieve preload list.")
	}

	firstEntry := preloadList.Entries[0]
	if firstEntry.Name != "pinningtest.appspot.com" {
		t.Errorf("First entry of preload list does not have the expected name.")
	}
}

func TestPreloadEntriesToMap(t *testing.T) {
	m := PreloadEntriesToMap(PreloadList{
		Entries: []PreloadEntry{
			PreloadEntry{
				Name:              "garron.net",
				Mode:              "ForceHTTPS",
				IncludeSubDomains: true,
			},
			PreloadEntry{
				Name:              "example.com",
				Mode:              "",
				IncludeSubDomains: false,
			},
		},
	})

	if len(m) != 2 {
		t.Errorf("Map has the wrong number of entries.")
	}

	if m["garron.net"].Mode != "ForceHTTPS" {
		t.Errorf("Map has invalid entries.")
	}
}
