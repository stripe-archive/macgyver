# MacGyver

MacGyver is a Chrome extension which provides an SSH agent for the
[Secure Shell][] extension. It back-ends into the new
[chrome.platformKeys][] API, giving it access to certificates stored
in a Chromebook's TPM.

## Building

The extension is written in [Go][], and compiled to JavaScript using
[GopherJS][]. Using Go lets us take advantage of packages like
[x/crypto][], which already has an SSH agent implementation.

You can compile the extension by running the following:

 * `go get -u github.com/gopherjs/gopherjs`
 * `cd go && gopherjs build`

## Permissions

In order for MacGyver to access certificates, the Chromebook must be
enrolled in a domain, and the certificate must have been generated
using the [chrome.enterprise.platformKeys][] API. Finally, the
`KeyPermissions` policy must be set to `{"extensionid":
{"allowCorporateKeyUsage": true}}`. This last bit is tricky, since the
`KeyPermissions` policy is not yet exposed from the Google Apps
cpanel.

## Usage

After installing, you can pass `--ssh-agent=extensionid` in the "relay
options" field (not the "SSH Arguments"!) of the Secure Shell
extension.

[Secure Shell]: https://chrome.google.com/webstore/detail/secure-shell/pnhechapfaindjhompbnflcldabbghjo?hl=en
[chrome.platformKeys]: https://developer.chrome.com/extensions/platformKeys
[Go]: http://golang.org/
[Gopherjs]: http://www.gopherjs.org/
[x/crypto]: https://godoc.org/golang.org/x/crypto
[chrome.enterprise.platformKeys]: https://developer.chrome.com/extensions/enterprise_platformKeys

## Hacking

If you want to hack on this not on a Chromebook, there's a rough localStorage
backend for keys that you can use instead of Chrome PlatformKeys.

 * Create a localStorage item for the extension with key `privateKey`. An easy way to do this is to open the console and run `localStorage.privateKey = "-----BEGIN RSA PRIVATE KEY-----\nkey\nwith\nliteral\nnewlines\n-----END RSA PRIVATE KEY-----"`
 * Edit main.go and change the branch to false.
