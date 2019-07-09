package hstspreload

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"sync"
	"testing"
)

const FILE = "./test_responses.json"

const (
	REPLAY = iota
	RECORD
)

const MODE = RECORD

// func Read() {
// 	file, e := ioutil.ReadFile(FILE)
// 	if e != nil {
// 		fmt.Printf("File error: %v\n", e)
// 		os.Exit(1)
// 	}
// 	fmt.Printf("%s\n", string(file))

// 	//m := new(Dispatch)
// 	//var m interface{}
// 	var jsontype jsonobject
// 	json.Unmarshal(file, &jsontype)
// 	fmt.Printf("Results: %v\n", jsontype)
// }

type testTransport struct {
	responses        map[string]string
	lock             sync.RWMutex
	defaultTransport http.RoundTripper
}

func newTestTransport() testTransport {
	return testTransport{
		responses:        map[string]string{},
		defaultTransport: http.DefaultTransport,
	}
}

func (t testTransport) Write() error {
	b, err := json.Marshal(t.responses)
	if err != nil {
		return err
	}

	ioutil.WriteFile(FILE, b, 0644)
	return nil
}

func testMainWrapper(m *testing.M) int {
	t := newTestTransport()
	http.DefaultTransport = &t
	code := m.Run()

	if MODE == RECORD {
		err := t.Write()
		if err != nil {
			fmt.Printf("%s", err)
			return 1
		}
	}

	return code
}

// func cacheKey(r *http.Request) string {
//   return r.URL.String()
// }

// type CacheTransport struct {
//   data              map[string]string
//   mu                sync.RWMutex
//   originalTransport http.RoundTripper
// }

// func (c *CacheTransport) Set(r *http.Request, value string) {
//   fmt.Printf("-------")
//   fmt.Printf(value)
//   fmt.Printf("-------")
//   c.mu.Lock()
//   defer c.mu.Unlock()
//   c.data[cacheKey(r)] = value
// }

// func (c *CacheTransport) Get(r *http.Request) (string, error) {
//   c.mu.RLock()
//   defer c.mu.RUnlock()

//   if val, ok := c.data[cacheKey(r)]; ok {
//     return val, nil
//   }

//   return "", errors.New("key not found in cache")
// }

func (t testTransport) Record(r *http.Response) error {
	b, err := httputil.DumpResponse(r, true)
	if err != nil {
		return err
	}
	responses[r.URL.String()] = string(*b)
}

// Here is the main functionality
func (t testTransport) RoundTrip(r *http.Request) (*http.Response, error) {

	// // Check if we have the response cached..
	// // If yes, we don't have to hit the server
	// // We just return it as is from the cache store.
	// if val, err := c.Get(r); err == nil {
	// 	fmt.Println("Fetching the response from the cache")
	// 	return cachedResponse([]byte(val), r)
	// }

	// Ok, we don't have the response cached, the store was probably cleared.
	// Make the request to the server.
	resp, err := c.defaultTransport.RoundTrip(r)

	if err != nil {
		return nil, err
	}

	resp.ContentLength = 0
	resp.Body = http.NoBody
	t.Record(r)

	// // Get the body of the response so we can save it in the cache for the next request.
	// buf, err := httputil.DumpResponse(resp, true)

	// if err != nil {
	// 	return nil, err
	// }

	// // Saving it to the cache store
	// c.Set(r, string(buf))

	// fmt.Println("Fetching the data from the real source")
	return resp, nil
}

// func cachedResponse(b []byte, r *http.Request) (*http.Response, error) {
//   buf := bytes.NewBuffer(b)
//   return http.ReadResponse(bufio.NewReader(buf), r)
// }
