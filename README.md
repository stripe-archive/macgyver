# MacGyver

![Agent MacGyver](http://i.imgur.com/iwNSsNR.png ""If I had some duct tape, I could fix that"")

MacGyver is a Chrome extension for enterprise-managed Chromebooks. It
duct tapes an SSH agent to the new [chrome.platformKeys][] API
(which provides access to X.509 certificates stored in a Chromebook's
TPM), exposing it to the Chrome [Secure Shell][] extension.

## Background

For some time, Chrome OS has included the ability to store X.509
certificates in its [TPM][]. This allows certificates to be stored in
such a way that the private keys can not be extracted. Chrome 45 added
the new [chrome.platformKeys][] extension API, which allows extensions
to use those certificates (subject to some permissions constraints)
for signing data.

Separately, the [Secure Shell][] extension for Chrome (which is an
OpenSSH compiled for [NaCl][]) [supports][chromium-hterm ssh-agent]
using an external extension as a stand-in for an SSH agent.

MacGyver duct tapes these two developments together, allowing the
[Secure Shell][] extension to utilize TPM-stored certificates (or,
really, the public key in the certificates) and private keys via the
SSH agent protocol and the [chrome.platformKeys][] API.

## Usage

After installing, you can pass `--ssh-agent=extensionid` in the "relay
options" field (not the "SSH Arguments"!) of the Secure Shell
extension.

## Building

The extension is written in [Go][], and compiled to JavaScript using
[GopherJS][]. Using Go lets us take advantage of packages like
[x/crypto][], which already has an SSH agent implementation.

You can compile the extension by running the following:

 * `go get -u github.com/gopherjs/gopherjs`
 * `cd go && gopherjs build`

## Permissions

Unfortunately, the new [chrome.platformKeys][] API doesn't make it
very easy to get at certificates.

It's only possible to access certificates that were generated using
the [chrome.enterprise.platformKeys][] API. In order to use MacGyver,
this means that you must have an enterprise-enrolled Chromebook that
uses an administrator-provisioned extension to generate and load
certificates. This also means that MacGyver will never see
certificates that are (e.g.) imported using the Certificate manager or
generated via &lt;keygen&gt; tags.

Additionally, even if an extension has the `platformKeys` permission,
it can only access certificates created by
[chrome.enterprise.platformKeys][] if it's been explicitly whitelisted
for that access. That whitelisting happens via the `KeyPermissions`
policy, which must be set to `{"extensionid":
{"allowCorporateKeyUsage": true}}`.

Unfortunately, this is tricky, since the [KeyPermissions][] policy is
not yet exposed from the Google Apps control panel. As of this
writing, the only way to set `KeyPermissions` is to enter developer
mode (the process [differs by model][Chromebook developer mode]),
[disabling rootfs verification][Chromebook rootfs], and manually
creating a [Linux policy file][] in (for example)
`/etc/opt/chrome/policies/managed/macgyver.json`. The contents of the
file should look something like this:

```json
{
  "KeyPermissions": {
    "monnheglpedplnifignjahmadpadlmgj": {
      "allowCorporateKeyUsage": true
    }
  }
}
```

Once the file is in place, the system policies can be reloaded by
going to chrome://policy and clicking "Reload policies". If the
configuration worked, the `KeyPermissions` policy should immediately
show up in the list of active policies.

## Chrome SSH Agent Protocol

The [Secure Shell][] extension for Chrome has
[supported][chromium-hterm ssh-agent] relaying the SSH agent protocol
to another extension since November 2014. The [protocol][nassh agent]
is fairly straightforward, but undocumented.

The [SSH agent protocol][ssh-agent] is based on a simple
length-prefixed framing protocol. Each message is prefixed with a
4-byte network-encoded length. Messages are sent over a UNIX socket.

By contrast, the [Secure Shell][] agent protocol uses [Chrome
cross-extension messaging][Cross-extension messaging], connecting to
the agent extension with [chrome.runtime.connect][]. Each frame of the
SSH agent protocol is assembled, stripped of its length prefix, and
sent as an array of numbers (not, say, an ArrayBuffer) in the "data"
field of an object via `postMessage`.

Here's an example message, representing the
`SSH2_AGENTC_REQUEST_IDENTITIES` request (to list keys):

```json
{
  "type": "auth-agent@openssh.com",
  "data": [11]
}
```

SSH agents are expected to respond in the same format.

### macgyver.AgentPort

Because [x/crypto][]'s [SSH agent
implementation][x/crypto/ssh/agent.ServeAgent] expects an
[io.ReadWriter][] that implements the standard (length-prefixed)
protocol, MacGyver implements a wrapper around a `chrome.runtime.Port`
that between [Secure Shell][]'s protocol and the native protocol
(stripping or adding the length prefix and JSON object wrapper as
necessary).

## Hacking

If you want to hack on this not on a Chromebook, there's a rough localStorage
backend for keys that you can use instead of Chrome PlatformKeys.

 * Create a localStorage item for the extension with key `privateKey`. An easy way to do this is to open the console and run `localStorage.privateKey = "-----BEGIN RSA PRIVATE KEY-----\nkey\nwith\nliteral\nnewlines\n-----END RSA PRIVATE KEY-----"`
 * Edit main.go and change the branch to false.

## Contributors

* Evan Broder
* Dan Benamy

[Chromebook developer mode]: https://www.chromium.org/chromium-os/developer-information-for-chrome-os-devices
[Chromebook rootfs]: https://www.chromium.org/chromium-os/poking-around-your-chrome-os-device#TOC-Making-changes-to-the-filesystem
[Cross-extension messaging]: https://developer.chrome.com/extensions/messaging#external
[Go]: http://golang.org/
[Gopherjs]: http://www.gopherjs.org/
[KeyPermissions]: https://www.chromium.org/administrators/policy-list-3#KeyPermissions
[Linux policy file]: https://www.chromium.org/administrators/linux-quick-start
[NaCl]: https://en.wikipedia.org/wiki/Google_Native_Client
[Secure Shell]: https://chrome.google.com/webstore/detail/secure-shell/pnhechapfaindjhompbnflcldabbghjo?hl=en
[TPM]: https://en.wikipedia.org/wiki/Trusted_Platform_Module
[chrome.enterprise.platformKeys]: https://developer.chrome.com/extensions/enterprise_platformKeys
[chrome.platformKeys]: https://developer.chrome.com/extensions/platformKeys
[chrome.runtime.connect]: https://developer.chrome.com/extensions/runtime#method-connect
[chromium-hterm ssh-agent]: https://groups.google.com/a/chromium.org/d/msg/chromium-hterm/iq-AuvRJsYw/QVJdCw2wSM0J
[io.ReadWriter]: https://godoc.org/io#ReadWriter
[nassh agent]: https://github.com/libapps/libapps-mirror/blob/master/nassh/js/nassh_stream_sshagent_relay.js
[ssh-agent]: http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.agent?rev=HEAD
[x/crypto/ssh/agent.ServeAgent]: https://godoc.org/golang.org/x/crypto/ssh/agent#ServeAgent
[x/crypto]: https://godoc.org/golang.org/x/crypto
