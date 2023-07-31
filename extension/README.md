# Attested DNS Client Extension (Firefox)

## What it does

This extension registers handlers for URLs matching `*://*.attested.name/*`.
For domains that haven't been validated recently, it sends the following requests before the connection is opened:

- aDNS-specific, AAAA-fragmented, compressed attestation reports: `attest.*.attested.name`. The attestation report is checked by the WASM-compiled RAVL.
- DANE-style requests: `_443._tcp.*.attested.name` to verify the attested public key matches the DANE record.

Failure of these checks results in the connection being aborted.

Then, once the HTTPS connection has been established, but before sending the request, the actual public key of the certificate is matched with the attested public key.

## Can it run in Chrome?

This extension relies on `webRequest.getSecurityInfo` which is not supported on Chrome.
