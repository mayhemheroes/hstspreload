// The hstspreload package has 4 parts:
//
// - A Go package with functions to check HSTS preload requirements.
//
// - The `hstspreload` command line tool, which can be installed with:
//
//     go get github.com/chromium/hstspreload/cmd/hstspreload
//
// - The `transport_security_state_static_generate.go` script, which can
// be installed with:
//
//     go get github.com/chromium/hstspreload/cmd/transport_security_state_static_generate
//
// - Source code for hstspreload.appspot.com
package hstspreload
