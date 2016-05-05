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
	"strings"
	"time"
	"unicode"
)

const (
	// ForceHTTPS indicates that all requests should be upgraded from HTTP to
	// HTTPS using the HSTS mechanism (https://tools.ietf.org/html/rfc6797).
	ForceHTTPS = "force-https"
)

// PreloadList contains a parsed form of the Chromium Preload list.
//
// The full list contains information about more than just HSTS, but only
// HSTS-related contents are currently exposed in this struct.
type PreloadList struct {
	Entries []PreloadEntry `json:"entries"`
}

// A Domain in the Chromium preload list. Note that this corresponds
// to "host" in the HSTS spec, and does not contain the scheme or port.
// We call it a "domain" because this makes the meaning more clear to
// web developers, and naturally allows us to refer to domains vs.
// subdomains.
type Domain string

// A PreloadEntry contains the data from an entry in the Chromium
// Preload list.
//
// - Name: The domain name.
//
// - Mode: The only valid non-empty value is ForceHTTPS
//
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
	var list PreloadList

	client := http.Client{
		Timeout: time.Second * 10,
	}

	resp, err := client.Get(latestChromiumListURL)
	if err != nil {
		return list, err
	}

	if resp.StatusCode != 200 {
		return list, fmt.Errorf("status code %d", resp.StatusCode)
	}

	body := base64.NewDecoder(base64.StdEncoding, resp.Body)
	jsonBytes, err := removeComments(body)
	if err != nil {
		return list, errors.New("could not decode body")
	}

	if err := json.Unmarshal(jsonBytes, &list); err != nil {
		return list, err
	}

	return list, nil
}

// PreloadEntriesToMap creates an indexed map (Domain -> PreloadEntry) of
// the entries from the given PreloadList.
func PreloadEntriesToMap(list PreloadList) map[Domain]PreloadEntry {
	m := make(map[Domain]PreloadEntry)
	for _, entry := range list.Entries {
		m[entry.Name] = entry
	}
	return m
}

// removeComments reads the contents of |r| and removes any lines beginning
// with optional whitespace followed by "//"
func removeComments(r io.Reader) ([]byte, error) {
	var buf bytes.Buffer

	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if isCommentLine(line) {
			fmt.Fprintln(&buf, line)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func isCommentLine(line string) bool {
	trimmed := strings.TrimLeftFunc(line, unicode.IsSpace)
	return !strings.HasPrefix(trimmed, "//")
}
