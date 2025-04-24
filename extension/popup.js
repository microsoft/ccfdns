const ext = browser.extension.getBackgroundPage();

function toHex(a) {
  return a.map((x) => x.toString(16).padStart(2, "0")).join(":");
}

browser.tabs.query({ active: true, currentWindow: true }).then(async (tabs) => {
  const url = new URL(tabs[0].url);
  let info = ext.cache[url.hostname];
  let claims = info.claims[0].sgx_claims;

  let ns = url.hostname.split(".");
  ns[0] = "ns1";
  ns = ns.join(".");

  $("#name").text(url.hostname);
  $("#tab").append(
    "<tr><td>Connection</td>" +
      `<td>${info.tlsVersion}, ${info.cipherSuite}, ${info.kexGroup}. ${info.latency}ms aDNS validation.</td>` +
      "</tr>",
  );

  $("#tab").append(
    $("<tr>").append(
      $("<td>").text("DANE Record"),
      $("<td>").append(toHex([...info.tlsa])),
    ),
  );

  $("#tab").append(
    $("<tr>").append(
      $("<td>").text("Pinned Key"),
      $("<td>").append(toHex(info.claims[0].custom_claims.sgx_report_data)),
    ),
  );

  let qtype =
    "sgx_claims" in info.claims[0]
      ? "Intel SGX (isolated process)"
      : "AMD SEV-SNP (isolated virtual machine)";

  let atable = $("<table>").append(
    $("<tr>").append($("<td>").text(`TEE type`), $("<td>").text(qtype)),
    $("<tr>").append(
      $("<td>").text(`Basename`),
      $("<td>").text(toHex(claims.basename)),
    ),
    $("<tr>").append(
      $("<td>").text(`SVNs`),
      $("<td>").text(
        `PCE=${claims.pce_svn}, QE=${claims.qe_svn}, config=${claims.report_body.config_svn}, ISV=${claims.report_body.isv_svn}`,
      ),
    ),
    $("<tr>").append(
      $("<td>").text(`MRENCLAVE`),
      $("<td>").text(toHex(claims.report_body.mr_enclave)),
    ),
    $("<tr>").append(
      $("<td>").text(`MRSIGNER`),
      $("<td>").text(toHex(claims.report_body.mr_signer)),
    ),
    $("<tr>").append(
      $("<td>").text(`Attestation Key`),
      $("<td>").text(toHex(claims.signature_data.attest_pub_key)),
    ),
  );

  $("#tab").append(
    $("<tr>").append(
      $("<td>").text("SGX Attestation"),
      $("<td>").append(atable),
    ),
  );

  let receipt = await fetch(
    "https://" +
      ns +
      ":8443/app/registration-receipt?service-name=" +
      url.hostname,
    { credentials: "omit" },
  );
  receipt = await receipt.json();
  console.log(receipt);
  receipt = receipt.receipt;
  let proof = receipt.proof
    .map((x) => {
      return x.left;
    })
    .join("\n");

  let rtable = $("<table>").append(
    $("<tr>").append(
      $("<td>").text(`Certificate`),
      $("<td>").append(`<textarea>${receipt.cert}</textare>`),
    ),
    $("<tr>").append(
      $("<td>").text(`Root Signature`),
      $("<td>").text(receipt.signature),
    ),
    $("<tr>").append(
      $("<td>").text(`Proof`),
      $("<td>").append(`<textarea>${proof}</textarea>`),
    ),
  );

  $("#tab").append(
    $("<tr>").append($("<td>").text("Registration"), $("<td>").append(rtable)),
  );
});
