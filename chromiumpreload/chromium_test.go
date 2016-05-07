package chromiumpreload

import (
	"testing"
)

func TestGetLatest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test to avoid preload list download.")
	}

	list, err := GetLatest()
	if err != nil {
		t.Errorf("Could not retrieve preload list.")
	}

	firstEntry := list.Entries[0]
	if firstEntry.Name != "pinningtest.appspot.com" {
		t.Errorf("First entry of preload list does not have the expected name.")
	}
}

func TestPreloadEntriesToMap(t *testing.T) {
	list := PreloadList{
		Entries: []PreloadEntry{
			{
				Name:              "garron.NET",
				Mode:              "ForceHTTPS",
				IncludeSubDomains: true,
			},
			{
				Name:              "example.com",
				Mode:              "",
				IncludeSubDomains: false,
			},
		},
	}

	idx := list.Index()

	if len(idx.index) != 2 {
		t.Errorf("Map has the wrong number of entries.")
	}

	_, ok := idx.Get("example")
	if ok {
		t.Errorf("Entry should not be present.")
	}

	entry, ok := idx.Get("GARRON.net")
	if !ok {
		t.Errorf("Entry should be present.")
	}
	if entry.Mode != "ForceHTTPS" {
		t.Errorf("Map has invalid entry.")
	}
}
