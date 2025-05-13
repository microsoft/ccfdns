# ccfdns

A CCF-based, attested DNS server.

# Build

The build depends on a local installation of [CCF](https://github.com/microsoft/ccf) 6.0.0 or above, on Azure Linux 3.0.

```
mkdir build
cd build
cmake -GNinja -DVIRTUAL=ON ..
ninja
```

# Run sandbox:

(May depend on your version of CCF)

```
/opt/ccf_virtual/bin/sandbox.sh -p libccfdns.virtual.so
```

# Run aDNS server/service

For an example of how to run an aDNS server/service, see [adns_service.py](tests/adns_service.py). Most of this is a simple application of the CCF infrastructure scripts. The [CCF documentation](https://microsoft.github.io/CCF/main/index.html) describes all of the components.

Note that for a complete service, your server(s) or VM(s) must be SEV-SNP-enabled and registered with at least a traditional, DNSSEC-enabled DNS server. Of course, that server may also be another aDNS server.

Additionally, you may have to

- Add inbound rules to your network security group/firewall to allow inbound traffic on port 53
- Disable the service `systemd-resolved` (which uses also uses port 53) and manually add a well-known DNS server to `/etc/resolve.conf`.
- If you are using docker to run the service, then use the host network

## Contributing

This project welcomes contributions and suggestions. Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft
trademarks or logos is subject to and must follow
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
