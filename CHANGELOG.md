
# [v0.4.1](https://github.com/n0-computer/iroh/compare/v0.4.0...v0.4.1) (2023-04-03)

### Bug Fixes

* Fix for error when transferring large files ([#920](https://github.com/n0-computer/iroh/issues/920))

# [v0.4.0](https://github.com/n0-computer/iroh/compare/v0.3.0...v0.4.0) (2023-03-29)

### Bug Fixes

* Avoid other output between contents when printing ([#786](https://github.com/n0-computer/iroh/issues/786)) ([9076443](https://github.com/n0-computer/iroh/commit/907644345f1e8b6990d7d4cb278ab7c2e1be9e84))
* **ci:** format output as table ([#791](https://github.com/n0-computer/iroh/issues/791)) ([7fb888d](https://github.com/n0-computer/iroh/commit/7fb888d699b3f25b80687cbf5278ea8428009bda))
* **ci:** move from sendme to iroh ([#788](https://github.com/n0-computer/iroh/issues/788)) ([6a5c13e](https://github.com/n0-computer/iroh/commit/6a5c13e31c1a29b39c6b308b1cd7cf4c20f19a52))
* Do not send duplicate NotFound responses ([#802](https://github.com/n0-computer/iroh/issues/802)) ([c0d4984](https://github.com/n0-computer/iroh/commit/c0d4984086f443a216d51073a84ebb734c96a762))
* fix netsim bin paths ([#881](https://github.com/n0-computer/iroh/issues/881)) ([3291291](https://github.com/n0-computer/iroh/commit/3291291991deb3e268e8247f50379a43421b4095))
* Improve listening addr output ([#789](https://github.com/n0-computer/iroh/issues/789)) ([33c0482](https://github.com/n0-computer/iroh/commit/33c0482874d2c65e2ac45e11e22d5ec192608454))
* Output writing ([#804](https://github.com/n0-computer/iroh/issues/804)) ([eb18a89](https://github.com/n0-computer/iroh/commit/eb18a89fa6f2bd4fdbb49ebe0b218869bc793bbc))
* **provider:** ensure postcard buffers are appropriately sized ([c28e0a8](https://github.com/n0-computer/iroh/commit/c28e0a844797e5a21a42cab4a015fd802c30ba46))
* update to new default-net ([e2584c0](https://github.com/n0-computer/iroh/commit/e2584c007b53325e929f7d12b078ed94b9e6bfd0))
* use absolute paths everywhere ([#836](https://github.com/n0-computer/iroh/issues/836)) ([b2730ee](https://github.com/n0-computer/iroh/commit/b2730ee004890a0930d09af7d8fb7dfd483befd0))


### Features

* Add run_ticket to dial all addresses stored in a Ticket ([#888](https://github.com/n0-computer/iroh/issues/888)) ([91c7e2a](https://github.com/n0-computer/iroh/commit/91c7e2aee1f7f4059f3d391725fb49af4410a3eb))
* ci netsim integration tests ([#877](https://github.com/n0-computer/iroh/issues/877)) ([8fe1d81](https://github.com/n0-computer/iroh/commit/8fe1d8157aa68fb5ec981011ed797ac0619050c5))
* **ci:** push data to metro ([#794](https://github.com/n0-computer/iroh/issues/794)) ([1a68106](https://github.com/n0-computer/iroh/commit/1a68106d07c0faf8d6354d6c313247529e8872f6))
* cmd to list provide addrs ([#859](https://github.com/n0-computer/iroh/issues/859)) ([2c0663a](https://github.com/n0-computer/iroh/commit/2c0663a9fcf2f79989e468a0daa79c40974d92ec))
* custom configs for netsim ([#862](https://github.com/n0-computer/iroh/issues/862)) ([1078762](https://github.com/n0-computer/iroh/commit/10787624b00a7df46c42dae60b1a30f1b0ec5d0e))
* **get-ticket:** Contact provider on all listening addrs ([#893](https://github.com/n0-computer/iroh/issues/893)) ([adbb2bf](https://github.com/n0-computer/iroh/commit/adbb2bf1918087191dca8ef0cd403083e9600ea7))
* **net:** implement local address detection ([#822](https://github.com/n0-computer/iroh/issues/822)) ([9323e10](https://github.com/n0-computer/iroh/commit/9323e10c9744ef83bef476d3fc9ec0503776b145))
* **provider:** emit events about outgoing transfers ([f05ec8c](https://github.com/n0-computer/iroh/commit/f05ec8cbde836dda04b90867370ef3793a34e0f4))
* release builds ([#863](https://github.com/n0-computer/iroh/issues/863)) ([7b91c9a](https://github.com/n0-computer/iroh/commit/7b91c9ae4dbd9bda331027b38b6b5c64142eed8a))
* Set multiple addrs in the ticket ([#820](https://github.com/n0-computer/iroh/issues/820)) ([9ac4cf6](https://github.com/n0-computer/iroh/commit/9ac4cf6e770879c8b2ec0dc6666fe531469e68e3))
* Show more numbers in human readable form ([#790](https://github.com/n0-computer/iroh/issues/790)) ([a0b7c26](https://github.com/n0-computer/iroh/commit/a0b7c26e5a4b83ae4413d25065405f54920eecfe))
* **ticket:** Ensure a ticket always has at least one address ([#892](https://github.com/n0-computer/iroh/issues/892)) ([0c17958](https://github.com/n0-computer/iroh/commit/0c17958dbc88e2b2ea81cca49119d541045630ef))
* use chunk groups feature ([#798](https://github.com/n0-computer/iroh/issues/798)) ([d68f05d](https://github.com/n0-computer/iroh/commit/d68f05dc76b8e4b2d60329665e58c3a18edef51d))


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

