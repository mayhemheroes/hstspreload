package hstspreload

import (
  "crypto/tls"
  "fmt"
  "net/http"
)

func MayPreload(host string) error {
  conn, err := tls.Dial("tcp", host + ":443", nil)
  if err != nil {
    return fmt.Errorf("Cannot connect using TLS (%q). " +
      "This might be caused by an incomplete certificate chain, which " +
      "causes issues on mobile devices. " +
      "Check out your site at https://www.ssllabs.com/ssltest/.", err)
  }

  response, err := http.Get("https://" + host)
  if err != nil {
    return fmt.Errorf("Error while retrieving %s using http.Get()", err)
  }

  conn.Close()

  hstsHeader := response.Header.Get("Strict-Transport-Security")
  if (hstsHeader != "max-age=31536000; includeSubDomains; preload") {
    return fmt.Errorf("Invalid preload header (%s)", hstsHeader)
  }

  return nil
}