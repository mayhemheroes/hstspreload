# HSTS utility code.

HSTS is [HTTP Strict Transport Security](https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security), which is a policy system for web sites to express a desire only to be contacted over HTTPS.

Chrome supports HSTS and also includes a list of domains with [preloaded HSTS](https://hstspreload.appspot.com) policies. This list is used by Firefox, IE and Safari.

This directory contains tools that Chrome developers use to manage the preload list:

* The `hstspreload.appspot.com` directory contains an AppEngine app that is live at [https://hstspreload.appspot.com](https://hstspreload.appspot.com). This app allows people to register their sites for inclusion in the HSTS preload list.
* The `hsts-review.go` tool is used to fetch the list of pending submissions from the AppEngine site and run some basic checks on them. It outputs a list of rejections to submission to the site and a JSON snippet, suitable for inclusion in the preload list.

Note that, in order to build the `hsts-preload` app, you'll need a [Go workspace](https://golang.org/doc/code.html#Workspaces) configured and then you'll need to run `go get golang.org/x/net/publicsuffix` to install a needed package.

## Reviewing adding automated submissions to the HSTS preload list

### "Manual Review" (`hsts-review.go`)

NOTE: This is a vestigial step based on the old "manual review". It will be folded into the AppEngine app. See https://crbug.com/587957

To review the [pending entries](https://hstspreload.appspot.com/pending), run:

    go run hsts-review.go

This will download the list of pending sites and, check them, and output two JSON snippets.

- The first will be the errors, which should be pasted into https://hstspreload.appspot.com/setmessages (requires permissions)
- The second is for submission, which is handled in the next section.

### Updating the JSON (`transport_security_state_static_generate.go`)

Run:

    go run \
      path-to/transport_security_state_static_generate.go \
      transport_security_state_static.json transport_security_state_static.certs

That should update `transport_security_state_static.h` with lots of new, binary data.

### Sync the AppEngine app

To sync the AppEngine app's pending list against the Chromium source, visit <https://hstspreload.appspot.com/update>