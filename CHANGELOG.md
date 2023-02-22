# v0.3.0 (2023-02-22)

Thus far, Iroh has been built as an implementation of the InterPlanetary File System (IPFS) focused on interoperability with Kubo, the reference implementation of IPFS. **Starting with this release Iroh  breaks interoperability with Kubo.** Iroh will still be an IPFS implementation in a loose sense of the term, but moving forward our exclusive focus is on hitting numbers that make Iroh a reliable piece of technology that just works. Rather than delete the IPFS implementation we’ve built so far we will rename the project to *[Beetle](https://github.com/n0-computer/beetle)*, and put it into maintenance mode. Our rationale is outlined [in this blog post](https://www.n0.computer/blog/a-new-direction-for-iroh/)

This is the first release in our ground up rebuild of Iroh. This sets an initial foundation of functionality that we intend to layer onto as we go.

The following crates are **removed**:

- iroh-api
- iroh-bitswap
- iroh-car
- iroh-embed
- iroh-gateway
- iroh-localops
- iroh-metrics
- iroh-one
- iroh-p2p
- iroh-resolver
- iroh-rpc-client
- iroh-rpc-types
- iroh-share
- iroh-store
- iroh-util
- iroh-unixfs

The following crates still exist, **but have completely different APIs**:

- iroh

