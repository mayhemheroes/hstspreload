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
