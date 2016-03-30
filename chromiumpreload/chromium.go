package chromiumpreload

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"
)

const (
	ForceHTTPS = "force-https"
)

// PreloadList contains a parsed form of the Chromium Preload list.
//
// The full list contains information about more than just HSTS, but only
// HSTS-related contents are currently exposed in this struct.
type PreloadList struct {
	Entries []PreloadEntry `json:"entries"`
}

type Domain string

// A PreloadEntry contains the data from an entry in the Chromium
// Preload list.
//
// - Name: The domain name.
// - Mode: The only valid non-empty value is ForceHTTPS
// - IncludeSubDomains: If Mode == ForceHTTPS, forces HSTS to apply to
//   all subdomains.
type PreloadEntry struct {
	Name              Domain `json:"name"`
	Mode              string `json:"mode"`
	IncludeSubDomains bool   `json:"include_subdomains"`
}

const (
	latestChromiumListURL = "https://chromium.googlesource.com/chromium/src/+/master/net/http/transport_security_state_static.json?format=TEXT"
)

// GetLatest retrieves the latest PreloadList from the Chromium source at
// https://chromium.googlesource.com/chromium/src/+/master/net/http/transport_security_state_static.json
//
// Note that this list may be up to 12 weeks fresher than the list used
// by the current stable version of Chrome. See
// https://www.chromium.org/developers/calendar for a calendar of releases.
func GetLatest() (PreloadList, error) {
	var preloadList PreloadList

	client := http.Client{
		Timeout: time.Second * 10,
	}

	resp, err := client.Get(latestChromiumListURL)
	if err != nil {
		return preloadList, err
	}

	if resp.StatusCode != 200 {
		return preloadList, fmt.Errorf("Status code %d", resp.StatusCode)
	}

	body := base64.NewDecoder(base64.StdEncoding, resp.Body)
	jsonBytes, err := removeComments(body)
	if err != nil {
		return preloadList, errors.New("Could not decode body.")
	}

	if err := json.Unmarshal(jsonBytes, &preloadList); err != nil {
		return preloadList, err
	}

	return preloadList, nil
}

// commentRegexp matches lines that optionally start with whitespace
// followed by "//".
var commentRegexp = regexp.MustCompile("^[ \t]*//")

var newLine = []byte("\n")

// removeComments reads the contents of |r| and removes any lines beginning
// with optional whitespace followed by "//"
func removeComments(r io.Reader) ([]byte, error) {
	var buf bytes.Buffer
	in := bufio.NewReader(r)

	for {
		line, isPrefix, err := in.ReadLine()
		if isPrefix {
			return nil, errors.New("line too long in JSON")
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if commentRegexp.Match(line) {
			continue
		}
		buf.Write(line)
		buf.Write(newLine)
	}

	return buf.Bytes(), nil
}
