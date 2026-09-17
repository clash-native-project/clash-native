# curl CA Bundle

## Source and snapshot

- Bundle: `third_party/curl-ca/cacert.pem`
- Download URL: <https://curl.se/ca/cacert.pem>
- Upstream information: <https://curl.se/docs/caextract.html>
- Source: Mozilla's CA certificate store, converted to PEM by the curl project
- Snapshot date in the bundle: 2026-08-13
- Certificate count: 121
- File size: 188,900 bytes
- SHA-256: `f66dff1bdf8f96060b8177976f8b7d9254bc89bc4db933d769f7384d28480bc9`
- License: MPL-2.0, as documented by curl for the generated bundle

The CMake configure step embeds this PEM file into `clash-native-core`. DoT,
DoH/HTTP/1.1, DoH/HTTP/2, DoQ, and DoH/HTTP/3 use these roots when peer
verification is enabled, so the runtime does not need to locate a separate CA
file or consult platform-specific default certificate paths.

curl documents an important limitation: the PEM conversion preserves CA
certificates but not Mozilla's browser-specific domain name constraints and
additional CA policy conditions. This bundle should therefore not be treated as
an exact copy of Firefox's complete trust policy.

## Updating

Download the new upstream bundle and verify it against curl's published SHA-256
file before updating this snapshot:

```powershell
curl.exe --fail --location --output third_party/curl-ca/cacert.pem https://curl.se/ca/cacert.pem
curl.exe --fail --location --output "$env:TEMP/cacert.pem.sha256" https://curl.se/ca/cacert.pem.sha256
Get-FileHash third_party/curl-ca/cacert.pem -Algorithm SHA256
Get-Content "$env:TEMP/cacert.pem.sha256"
```

After an update, record the new snapshot date, certificate count, file size,
SHA-256, and validation date here. Reconfigure the project so CMake regenerates
the embedded source.
