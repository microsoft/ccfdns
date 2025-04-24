"use strict";

// Cache verification for one hour
const CACHE_TIME = 1000 * 5; // 60 * 60; set to 5s for demo
var cache = {};

// Block a request by redirecting to the block page
function errorPage(host, msg) {
  let hash = JSON.stringify({ msg: msg, host: host, entry: cache[host] });
  return { redirectUrl: browser.runtime.getURL("blocked.html") + "#" + hash };
}

// Verify that the TLS connection is consistent with the
async function checkConnection(details) {
  let url = new URL(details.url);
  if (url.port == 8443) return {};
  let entry = cache[url.hostname];

  // DNS resolution of the attestation and TLSA record failed
  if (!entry)
    return errorPage(url.hostname, "Failed to query attested DNS details");

  console.log("Getting certificate details...");
  try {
    let info = await browser.webRequest.getSecurityInfo(details.requestId, {
      certificateChain: true,
    });

    // Non TLS: abort connection and upgrade to HTTPS
    if (info.state != "secure") return { upgradeToSecure: true };

    console.log(
      `Certificate found: ${info.certificates[0].subject} (${info.certificates[0].subjectPublicKeyInfoDigest.sha256})`,
    );

    let valid = false;
    for (let i = 0; i < entry.claims.length; i++) {
      let user_data = entry.claims[i].custom_claims.sgx_report_data;
      let sha = await crypto.subtle.digest(
        "SHA-256",
        Uint8Array.from(user_data),
      );
      let sha2 = btoa(String.fromCharCode.apply(null, new Uint8Array(sha)));
      if (i == entry.claims.length - 1) {
        console.log(`Found match with attestation #${i} (${sha2})!`);
        valid = true;
        break;
      }
    }

    // Fill in the certificate and session info in the cache
    // This is used in the page action popup to inspect connection details
    entry.certificate = info.certificates[0];
    entry.tlsVersion = info.protocolVersion;
    entry.cipherSuite = info.cipherSuite;
    entry.kexGroup = info.keaGroupName;
    entry.signatureAlg = info.signatureScheme;
  } catch (error) {
    return errorPage(
      url.hostname,
      "Failed to verify TLS connection matches attestation",
    );
  }
}

// Resolve a fragmented, AAAA-encoded result.
//
// This is use for the TLSA and ATTEST records verified before connection
// Even though this is asynchronous these are meant to be used in a BlockingResponse
// promise to ensure that all checks pass before the request progresses to the TLS phase
//
//  Since we can only resolve A, AAAA and CNAME with the built in browser.dns.resolve()
//  We encode custom records (ATTEST and TLSA) as a list of AAAA record. The list may be too
//  long to fit a single response, so this is also split into subrequests _0.x, _1.x, etc.
async function getFragmentedAAAA(name, comp = false) {
  var result,
    size = 0;
  try {
    for (let i = 0, t = 0; ; i++) {
      console.log(`Looking up _${i}.${name}`);
      let oldt = t;

      //const response = await fetch(`https://dns.google/resolve?name=${url.hostname}&type=A&do=1`);
      const response = await browser.dns.resolve(`_${i}.${name}`, [
        "disable_ipv4",
      ]);

      // This may be unnecessary if the browser's DNS is checking the RRsig
      // the list will be signed by the aDNS server already sorted
      let sorted = response.addresses.sort(
        (x, y) =>
          (parseInt(x.split(":")[0], 16) >> 8) -
          (parseInt(y.split(":")[0], 16) >> 8),
      );

      //  Total size are in the 2nd and 3rd most significant bytes of the first address
      //  FIXME: Ask Christoph to use Big Endian encoding! currently AA is the LSB and BB the MSB
      //  IPv6 address list: [
      //    00SS : SSAA : BBCC ...;
      //    01XX : YYZZ : ... ;
      //  ]
      sorted.forEach((x, j) => {
        x.split(":").forEach((x, k) => {
          let y = parseInt(x, 16) || 0;
          if (k) {
            if (!i && !j && k == 1)
              result = new Uint8ClampedArray((size += y >> 8));
            else result[t++] = y >> 8;
          }
          if (!i && !j && !k) size += 256 * (y & 255);
          else result[t++] = y & 255;
        });
      });
      if (t >= size) break;
      if (oldt == t) return false;
    }

    console.log(size, result);
    if (comp) result = pako.inflate(result);
    // reduce((x,v)=>{return x+String.fromCharCode(v)},"");

    return result;
  } catch (e) {
    return false;
  }
}

async function validateAttestation(alist) {
  let quotes = CBOR.decode(alist.buffer);
  let res = [];
  if (!Array.isArray(quotes)) quotes = [quotes];
  console.log(quotes);

  for (let i = 0; i < quotes.length; i++) {
    try {
      let q = Module.check_partial_attestation(CBOR.encode(quotes[i]));
      q = JSON.parse(q);
      console.log(q);
      res.push(q);
    } catch (e) {
      console.log(`Attestation #${i} failed to validate!`);
    }
  }

  return res;
}

async function validateRequest(details) {
  let url = new URL(details.url);
  browser.pageAction.show(details.tabId);

  if (url.port == 8443) return {};
  // We have recently verified the attestation of this domain
  if (
    cache[url.hostname] &&
    cache[url.hostname].time >= Date.now() + CACHE_TIME
  ) {
    console.log(`Query to ${url.hostname} is still in attestation cache`);
    return {}; //Disable cache
  }

  let start = Date.now();
  let tlsa = await getFragmentedAAAA(`_443._tcp.${url.hostname}`);
  let attest = await getFragmentedAAAA(`attest.${url.hostname}`, true);
  let valid = await validateAttestation(attest);

  if (!tlsa) return errorPage(url.hostname, "Error resolving TLSA record");

  if (!attest) return errorPage(url.hostname, "Error resolving ATTEST record");

  // We only require any one of the attestations to validate
  if (!valid.length)
    return errorPage(
      url.hostname,
      "Found attestation records, but none passed local validation.",
    );

  cache[url.hostname] = {
    time: Date.now(),
    latency: Date.now() - start,
    tlsa: tlsa,
    attest: attest,
    claims: valid,
    collaterals: null,
    certificate: null,
    tlsVersion: "",
    cipherSuite: "",
    kexGroup: "",
    signatureAlg: "",
  };

  console.log(
    `All pre-flight checks completed in ${cache[url.hostname].latency}ms!`,
  );

  return {};
}

browser.webRequest.onHeadersReceived.addListener(
  checkConnection,
  { urls: ["*://*.attested.name/*"] },
  ["blocking"],
);

browser.webRequest.onBeforeRequest.addListener(
  validateRequest,
  { urls: ["*://*.attested.name/*"] },
  ["blocking"],
);
