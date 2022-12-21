# [v0.2.0](https://github.com/n0-computer/iroh/compare/v0.1.1...v0.2.0) (2022-12-21)

### First steps for iroh as a library
Many folks have asked for iroh as a library embeddable in other rust projects, and with this release we land the the first version of `iroh-embed`. Check the [example](https://github.com/n0-computer/iroh/blob/e73a731769269c58b5d32e4a207e6577b3c50838/examples/embed/src/main.rs) for an initial guide.

We still have a _lot_ of work to do on `iroh-api` to expose a clean API to consume as a library, but if you're the kind of project that's intersted in embedded IPFS, and willing to roll up your sleeves on a moving API, Iroh is ready for you to use today.


### Gateway Subdomain & ETH domain support
Our gateway [spec compatibility](https://github.com/ipfs/specs/tree/main/http-gateways) continues to grow. Both of these features were outside contributions by [@ppodolsky](https://github.com/ppodolsky), for which we're super grateful. Be sure to check out their work on [summa](https://github.com/izihawa/summa)!

### QUIC Support
The majority of traffic on public IPFS networks runs over QUIC, which we now support within iroh thanks to a [massive push by the rust-libp2p team](https://github.com/libp2p/rust-libp2p/pull/2289). Huge thanks to the libp2p team!


### Bug Fixes

* actually resolve and check paths ([#623](https://github.com/n0-computer/iroh/issues/623)) ([8b6844f](https://github.com/n0-computer/iroh/commit/8b6844fc8dab620f0477b5e1d6b1341ef11f86b9))
* **ci:** Call cargo with beta toolchain from env var ([#622](https://github.com/n0-computer/iroh/issues/622)) ([b62030d](https://github.com/n0-computer/iroh/commit/b62030d3beb943f46b300a596a64c1c27a59ea21))
* **ci:** Set the protoc-arch matrix for weekly job ([#619](https://github.com/n0-computer/iroh/issues/619)) ([22d68df](https://github.com/n0-computer/iroh/commit/22d68df1f60fff5eb9b677bbc7a5862fdcd3588d)), closes [#618](https://github.com/n0-computer/iroh/issues/618)
* **ci:** Use beta toolchain for the clippy run ([#620](https://github.com/n0-computer/iroh/issues/620)) ([03624b5](https://github.com/n0-computer/iroh/commit/03624b55812b16c473e902a265cf7f6f1100f640))
* **iroh-one:** Wire up mem addresses to each other ([#555](https://github.com/n0-computer/iroh/issues/555)) ([ee9677d](https://github.com/n0-computer/iroh/commit/ee9677d4001f15516068bf0f376e01199a1824aa))
* **iroh:** do not use self version dep ([6f6fee0](https://github.com/n0-computer/iroh/commit/6f6fee0aed2f0d6d2381ac2b731d05cadfcfff52))
* **iroh:** exclude tests and fixtures from publishing ([6ebee5f](https://github.com/n0-computer/iroh/commit/6ebee5f3082f08d19662b8ee84b257df27d60d15))
* only use name if name is set ([#605](https://github.com/n0-computer/iroh/issues/605)) ([4dda2d0](https://github.com/n0-computer/iroh/commit/4dda2d05e4a0d230bcbf1ede35adbaa0cf5a8a00))
* unixfs seeking ([#606](https://github.com/n0-computer/iroh/issues/606)) ([51e3ddf](https://github.com/n0-computer/iroh/commit/51e3ddf4bad2f815b138c3276bb49b7e1603c94a))
* update quic-rpc to get rid of debug output ([bf4128b](https://github.com/n0-computer/iroh/commit/bf4128be1f742679dc35f061129b440c325a8c4e))
* use http when creating hyper URL ([#591](https://github.com/n0-computer/iroh/issues/591)) ([e9e932d](https://github.com/n0-computer/iroh/commit/e9e932d9df54c1d3b8468b387be9ae642ed46347))
* version handling in tests & git_version ([59c5dc7](https://github.com/n0-computer/iroh/commit/59c5dc78cf8067a3be3a19329d1998b69f9414a9))


### Features

* **ci:** improve protoc install & add code coverage checks ([#538](https://github.com/n0-computer/iroh/issues/538)) ([bcc20ce](https://github.com/n0-computer/iroh/commit/bcc20ce00fb19abc5ebbe03e9d315a01a7088881))
* enable quic transport ([18e2f40](https://github.com/n0-computer/iroh/commit/18e2f400ed79c3522e290fe1c77b289879af6154))
* **gateway:** add info page ([35955d6](https://github.com/n0-computer/iroh/commit/35955d6b9b505d2c35f99e4c618293c70bcca1a7))
* minimal iroh-embed ([#565](https://github.com/n0-computer/iroh/issues/565)) ([c216440](https://github.com/n0-computer/iroh/commit/c216440ffcf528f406064d9cd4b1e56e7181dedf))
* Send all the things ([#617](https://github.com/n0-computer/iroh/issues/617)) ([214d9ce](https://github.com/n0-computer/iroh/commit/214d9cecbc3dbb7fb425fb6ce50ca96474d38d98))
* Support `eth` domains  ([1d6b825](https://github.com/n0-computer/iroh/commit/1d6b825fe357a9fa958fdf426967516d3f689259))
* support of Gateway Subdomain spec ([#546](https://github.com/n0-computer/iroh/issues/546)) ([dfe3134](https://github.com/n0-computer/iroh/commit/dfe3134212d52811aa1ea33fdb19c2769f07be93))
* switch to released libp2p@0.50 ([ae30f9e](https://github.com/n0-computer/iroh/commit/ae30f9ebadb2e3cf7e8bb53ce955dc043d5a8cfe))
* **unixfs:** add rabin based chunking  ([b0a5783](https://github.com/n0-computer/iroh/commit/b0a57831ed4d5c2fcaeb535e6281216f81f7b108))


# [v0.1.3](https://github.com/n0-computer/iroh/compare/iroh-v0.1.2...iroh-v0.1.3) (2022-11-28)

Bug fix release, for issues discovered while publishing to crates.io.

### Bug Fixes

* **iroh:** do not use self version dep ([6f6fee0](https://github.com/n0-computer/iroh/commit/6f6fee0aed2f0d6d2381ac2b731d05cadfcfff52))
* **iroh:** exclude tests and fixtures from publishing ([6ebee5f](https://github.com/n0-computer/iroh/commit/6ebee5f3082f08d19662b8ee84b257df27d60d15))
* version handling in tests & git_version ([59c5dc7](https://github.com/n0-computer/iroh/commit/59c5dc78cf8067a3be3a19329d1998b69f9414a9))


# [v0.1.2](https://github.com/n0-computer/iroh/compare/v0.1.1...iroh-v0.1.2) (2022-11-28)

This relase brings about a couple of highlights, the first of which is the first relase of all `iroh-*` crates to crates.io. The second one being that we now support the experimental quic transport in libp2p.

### Bug Fixes

* **iroh-one:** Wire up mem addresses to each other ([#555](https://github.com/n0-computer/iroh/issues/555)) ([ee9677d](https://github.com/n0-computer/iroh/commit/ee9677d4001f15516068bf0f376e01199a1824aa))


### Features

* **ci:** improve protoc install & add code coverage checks ([#538](https://github.com/n0-computer/iroh/issues/538)) ([bcc20ce](https://github.com/n0-computer/iroh/commit/bcc20ce00fb19abc5ebbe03e9d315a01a7088881))
* enable quic transport ([18e2f40](https://github.com/n0-computer/iroh/commit/18e2f400ed79c3522e290fe1c77b289879af6154))
* **gateway:** add info page ([35955d6](https://github.com/n0-computer/iroh/commit/35955d6b9b505d2c35f99e4c618293c70bcca1a7))
* Support `eth` domains  ([1d6b825](https://github.com/n0-computer/iroh/commit/1d6b825fe357a9fa958fdf426967516d3f689259))
* switch to released libp2p@0.50 ([ae30f9e](https://github.com/n0-computer/iroh/commit/ae30f9ebadb2e3cf7e8bb53ce955dc043d5a8cfe))
* **unixfs:** add rabin based chunking  ([b0a5783](https://github.com/n0-computer/iroh/commit/b0a57831ed4d5c2fcaeb535e6281216f81f7b108))


# [v0.1.1](https://github.com/n0-computer/iroh/compare/v0.1.0...v0.1.1) (2022-11-21)

## Bitswap client mode
Iroh can now run in "client mode", which can _fetch_ content from bitswap, but not _provide_ content. This is useful if you're running on a lower-powered device or have limited bandwidth. To use client mode change your `p2p.config.toml`:
```
bitswap_server = false
```

## Use indexer nodes to find content providers
Iroh can use network indexers like [cid.contact](https://cid.contact) to find providers of a given CID. To use the cid.contact indexer adjust your `gateway.config.toml` to add an `indexer_endpoint` URL:

```
indexer_endpoint = https://cid.contact/cid/
```

## Docker support
Iroh now ships with docker images! Spin iroh up locally with:
```
$ cd iroh/docker
$ docker-compose up
```
then run `iroh status` from another terminal if you already have iroh installed. Now you're backing iroh with docker! `docker-compose down` to stop. The docker compose file also includes helpful guidance on which ports to expose from each iroh service.

We're shipping multi-arch [distroless](https://github.com/GoogleContainerTools/distroless) builds for amd64 & arm64 architectures.

## Fixed a critical bug adding files
We fixed a [known bug](https://github.com/n0-computer/iroh/issues/423) in iroh v0.1.0 that would break `iroh add` if files referenced the same CID on the way in. It's now fixed, and now we can happily do roundtrip add/get of the linux kernel, which is always fun 😊.


## Benchmarks
Benchmarks for this release coming soon. We'll update this readme once they're up.

### Production Readiness
Is this production ready? **Maybe**. Numerous projects are now using iroh in the wild. *You'll need to judge for yourself if iroh meets your needs.* Please reach out on our [discussion forums](https://github.com/n0-computer/iroh/discussions) if you have questions. We're going to keep the status at "Maybe" until we release a v1.0. v1.0 is currently slated for Q4 2023.


### Bug Fixes

* **`iroh-p2p`:** implement full local lookup ([#537](https://github.com/n0-computer/iroh/issues/537)) ([0c388b9](https://github.com/n0-computer/iroh/commit/0c388b959852a92e7955e6d2eeb1380948fb6f49))
* breadcrumb links in gateway directory template ([#513](https://github.com/n0-computer/iroh/issues/513)) ([f429baa](https://github.com/n0-computer/iroh/commit/f429baac42b845de4f47cbacd103198fcba95d50))
* **cli:** Respect the --cfg flag ([#506](https://github.com/n0-computer/iroh/issues/506)) ([e7bcac6](https://github.com/n0-computer/iroh/commit/e7bcac699dc677e94dd84d16c8b8b5e81eaa965f))
* convert v0 -> v1 before base32 conversion ([#527](https://github.com/n0-computer/iroh/issues/527)) ([ab3969c](https://github.com/n0-computer/iroh/commit/ab3969c9318b3801bf3fc2ff6c6c5ee53f63c979))
* Correct dependencies and build checks ([#484](https://github.com/n0-computer/iroh/issues/484)) ([7e9cdc3](https://github.com/n0-computer/iroh/commit/7e9cdc35918409b7c6820a5ba23ae417126cbfa9))
* docker-compose RPC ports should only listen on loopback ([#524](https://github.com/n0-computer/iroh/issues/524)) ([8471e49](https://github.com/n0-computer/iroh/commit/8471e49b2d3a9031bc44ae47e3d80034b60db806)), closes [#520](https://github.com/n0-computer/iroh/issues/520)
* iroh start service set construction ([#522](https://github.com/n0-computer/iroh/issues/522)) ([070be80](https://github.com/n0-computer/iroh/commit/070be80a56f6cf8f379cc7feeb454aa35c8f91a5))
* **iroh-store:** `put_many` bug ([#507](https://github.com/n0-computer/iroh/issues/507)) ([88f1a49](https://github.com/n0-computer/iroh/commit/88f1a49feb64b732be82b3e3cc039f703bac8865))
* Process -> Service in status command, add after help text ([#493](https://github.com/n0-computer/iroh/issues/493)) ([804255c](https://github.com/n0-computer/iroh/commit/804255cac91d637361c106bb2155df766fbbaa31))
* **store:** Make store operations atomic ([#480](https://github.com/n0-computer/iroh/issues/480)) ([ac8ec35](https://github.com/n0-computer/iroh/commit/ac8ec35f0131347ad125e82b43356e16787ecf08))
* Switch to tempfile for temporary test directories ([#509](https://github.com/n0-computer/iroh/issues/509)) ([89959cb](https://github.com/n0-computer/iroh/commit/89959cbf7b5d99de5ddc82121e85c111e5ffe055))
* verify content fetched from racing http gateways ([e281a4a](https://github.com/n0-computer/iroh/commit/e281a4a1cd053f35299da4f735b65cc117b53338))


### Features

* bitswap client mode  ([2a8a515](https://github.com/n0-computer/iroh/commit/2a8a515ad3175cdd68630c17e4a8831ff9e7af3d))
* **cli:** Environment variables to override directories  ([9a2220b](https://github.com/n0-computer/iroh/commit/9a2220b92a4bd008aaad015dea11bd651bbf4dbc))
* dockerize iroh services ([#494](https://github.com/n0-computer/iroh/issues/494)) ([f8af48a](https://github.com/n0-computer/iroh/commit/f8af48a846e46a59243a8d30963ca188a04e68a3))
* indexer resolution ([#476](https://github.com/n0-computer/iroh/issues/476)) ([f744949](https://github.com/n0-computer/iroh/commit/f7449493fb1f6b79beaa610c0c9f48224597b393))
* **p2p:** dial MDNS peers ([5bee5b7](https://github.com/n0-computer/iroh/commit/5bee5b7a836e3948c80f683e28c3f2061df6dd87))
* support lookup names in RPC addrs ([#500](https://github.com/n0-computer/iroh/issues/500)) ([144eef7](https://github.com/n0-computer/iroh/commit/144eef71681e8d56cb1441c52bd6dfe04c562e50))


# v0.1.0 - 2022-10-28

We’re on the board 🎉! This first release of iroh brings a new implementation of IPFS to the world. 

Key things to highlight about the first release of iroh:

* **Exchange Data with Kubo**. Iroh can interoperate with [kubo](https://github.com/ipfs/kubo) nodes on the IPFS network, pushing & fetching data.
* **Service Oriented architecture**. Don't want p2p? Turn it off! Iroh will still work without it.
* **Single CLI to control all services**. 
* **Built for efficiency**. Iroh's memory footprint & CPU usage are either on par or better than the best interoperable IPFS implementations out there.
* **Runs well on a laptop**. We have a custom installer script that will configure iroh for your laptop. See our [install docs](https://iroh.computer/docs/install)

v0.1.0 ships as 4 binaries for Linux & macOS with zero external dependencies:
* **iroh** - command line client
* **iroh-store** - data storage daemon
* **iroh-p2p** - peer 2 peer networking
* **iroh-gateway** - IPFS-to-HTTP bridge

You'll need to download all of them & put them on your $PATH to work with iroh. Our [install docs](https://iroh.computer/docs/install) have more info.

Please do give iroh a try, we'd love to [hear your feedback](https://github.com/n0-computer/iroh/issues/new). Thanks!

### Benchmarks
We're runnning benchmarks on a relatively stock AWS box for ease-of-replication. We don't have benchmarks for IPFS network retrieval this round.

### Adding Single Files
Add a single file with `iroh add --no-wrap --offline`:

| file size  | real (s) |	user(s) |	sys(s)   |	cpu %      |	cpu/total % |
| ---------- | -------- | ------- | -------- | ----------- | ------------ |   
| 100K       |	0.0102	| 0.0162  | 0.0317   | 469.6078431 | 7.337622549  |
| 1M  	     |  0.0167	| 0.004	  | 0.0519   | 334.7305389 | 5.230164671  |
| 10M        |	0.01345	| 0.0101  | 0.0418	 | 385.87	     | 6.03         |
| 100M       |	0.01345	| 0.0101  |	0.0418	 | 385.87	     | 6.03         |
| 1G         |	0.01345	| 0.0101  |	0.0418   | 385.87    	 | 6.03         |

### Fetching Cached Gateway Content
Repeatedly request the same CID of different file sizes to measure cached content throughput via HTTP request

| File size   | cpu/total (%)  | rps       | throughput/s  | avg latency  |
|-------------|----------------|-----------|---------------|--------------|
| 100K        | 90.48072917    | 40,064.27 | 3.85GB        | 5.08ms       |
| 1M          | 87.66614583    | 6,926.95  | 6.77GB        | 29.08ms      |
| 10M         | 87.34010417    | 711.55    | 6.98GB        | 278.86ms     |
| 100M        | 88.00885417    | 66.52     | 6.82GB        | 2.85s        |
| 1G          | 87.84947917    | 6.65      | 6.85GB        | 0.00s        |

### Production Readiness
Is this production ready? **No. We need your help to kick tires & find bugs!**.

The v0.1.0 moniker should testify to just how new this software is. Please don't deploy it anywhere mission critical until we've had at least a month or two to address bugs & write tests.

### Things you should know about this release:
There are two problems we couldn't properly address
* _There is no delete command._ Data added to iroh will stay there until a future release where we add content removal.  See [issue #432](https://github.com/n0-computer/iroh/issues/432) for details. The workaround for now is to blow away the storage database.
* _We have one particularly nasty known bug that can cause iroh to not persist data for highly nested directories upon add_ we plan to address ASAP in a patch release. See [issue #423](https://github.com/n0-computer/iroh/issues/423).

### Bug Fixes

* `check` and `watch` should display the same service names ([#101](https://github.com/n0-computer/iroh/issues/101)) ([ef99fe5](https://github.com/n0-computer/iroh/commit/ef99fe5c6d519eca6f8ad972323526345dd155fb))
* add --no-metrics support to p2p ([#65](https://github.com/n0-computer/iroh/issues/65)) ([a782fcb](https://github.com/n0-computer/iroh/commit/a782fcbb92af1e6b3a7f20ed0e40ee60b2670cbf))
* add macos builds to ci ([#33](https://github.com/n0-computer/iroh/issues/33)) ([a0e79fb](https://github.com/n0-computer/iroh/commit/a0e79fb4d70dd56c152dcbd5433ab840ed386c47))
* add missing metrics and update to fixed libp2p ([0f4f467](https://github.com/n0-computer/iroh/commit/0f4f4671369c12d7e08a6e1968dc96ad87eeb17c))
* allow `Raw` as `UnixfsType` ([#327](https://github.com/n0-computer/iroh/issues/327)) ([275d88b](https://github.com/n0-computer/iroh/commit/275d88b2f49df0269e384b90a093b4d3f78b8229))
* allow concurrent rpc calls & de-duplicate provider requests ([#60](https://github.com/n0-computer/iroh/issues/60)) ([a74f8dd](https://github.com/n0-computer/iroh/commit/a74f8dda299b4c58198267ff7921a203c2361eed))
* auto-raise FD limits where possible ([#215](https://github.com/n0-computer/iroh/issues/215)) ([9e429bb](https://github.com/n0-computer/iroh/commit/9e429bbfbeb12cc0cc050cdc4b973a0deda9d1de))
* avoid 0 divisions ([#76](https://github.com/n0-computer/iroh/issues/76)) ([8f491d5](https://github.com/n0-computer/iroh/commit/8f491d57c73e2ccc5b5c9d011ed38bfc03622953))
* bitswap sessions shutdown  ([6de85c9](https://github.com/n0-computer/iroh/commit/6de85c93bd541862558d498392256c091626d919))
* **bitswap:** fetch provider loop  ([93517a3](https://github.com/n0-computer/iroh/commit/93517a3157787eecc49b90a5815745adc2ffbce8))
* ci release aarch64 linux ([#184](https://github.com/n0-computer/iroh/issues/184)) ([4cc66aa](https://github.com/n0-computer/iroh/commit/4cc66aa19877ae66869c395208012eed408f7af2))
* CI, add macOS & windows builds, cargo audit ([5dbd907](https://github.com/n0-computer/iroh/commit/5dbd9074b8ee1b1945afb3345df21df39bc348ce))
* correctly check headers parse result ([#227](https://github.com/n0-computer/iroh/issues/227)) ([82a1b82](https://github.com/n0-computer/iroh/commit/82a1b82e035de4210aa5355d798f4e13953c47b9))
* correctly map memory channels ([0742fb2](https://github.com/n0-computer/iroh/commit/0742fb21cce63d2f3a1e9cc354ad511c69b226dc)), closes [#165](https://github.com/n0-computer/iroh/issues/165)
* default off metrics & tracing ([#174](https://github.com/n0-computer/iroh/issues/174)) ([bbc2ec1](https://github.com/n0-computer/iroh/commit/bbc2ec19ebb082a758d948cb64d0277e71bdb6a0))
* don't error on empty providers in the wrong place ([414a8f2](https://github.com/n0-computer/iroh/commit/414a8f2470962690b516be1cb015864565d571b7))
* drop openssl requirement ([#72](https://github.com/n0-computer/iroh/issues/72)) ([b72ce04](https://github.com/n0-computer/iroh/commit/b72ce044bc32f0ccde02946cdd4fa34e577ad42f))
* error when someone tries to start an unknown service ([#431](https://github.com/n0-computer/iroh/issues/431)) ([9a57fb7](https://github.com/n0-computer/iroh/commit/9a57fb7f36c78a1a395faed7fc984b1da1248f3c))
* extend metrics ([#32](https://github.com/n0-computer/iroh/issues/32)) ([34c53da](https://github.com/n0-computer/iroh/commit/34c53da9069351821b0c9c56f1f5fc3dc5449074))
* fix builds ([#173](https://github.com/n0-computer/iroh/issues/173)) ([932161c](https://github.com/n0-computer/iroh/commit/932161cab2b2991af278f0af131318fc7f703979))
* Fix test that for some reason assumes sort order in a vec ([d57b12a](https://github.com/n0-computer/iroh/commit/d57b12a9ce8ead2a0ddaa1b0ab0e700a6292b8dd))
* gateway readme ([#31](https://github.com/n0-computer/iroh/issues/31)) ([e94a7e0](https://github.com/n0-computer/iroh/commit/e94a7e055d567c6e2320c4d244d3c84f8bbc3899))
* gateway upgrade ([#36](https://github.com/n0-computer/iroh/issues/36)) ([0bb4fe9](https://github.com/n0-computer/iroh/commit/0bb4fe915c28e0278c91b83801aed422f30517bf))
* **gateway:** do not panic on missing location info ([c518ce7](https://github.com/n0-computer/iroh/commit/c518ce7c2ad7dbade6d87da62fbb94f868600e66))
* **gateway:** populate directory listings ([c7217f1](https://github.com/n0-computer/iroh/commit/c7217f1a864e96c2e45b096245a477295976c5dd))
* gha disk space hacks ([#387](https://github.com/n0-computer/iroh/issues/387)) ([a9d9c25](https://github.com/n0-computer/iroh/commit/a9d9c25af31795fa9ada3ee94c0757cc9024f19b))
* hamt directory listings  ([5187773](https://github.com/n0-computer/iroh/commit/5187773bfdb07a30c0e33c731105d3add9770fd1)), closes [#192](https://github.com/n0-computer/iroh/issues/192)
* histogram metric assignment ([#119](https://github.com/n0-computer/iroh/issues/119)) ([b75bbbd](https://github.com/n0-computer/iroh/commit/b75bbbda08604c8174e5c0d3e69dcf9d4eb507f8))
* Improve error handling  ([#379](https://github.com/n0-computer/iroh/issues/379)) ([7a945ed](https://github.com/n0-computer/iroh/commit/7a945ed602af50f1a5f0d15f2079f351a3037650))
* Improve error management and reporting when using unix domain sockets ([#228](https://github.com/n0-computer/iroh/issues/228)) ([8d13e4f](https://github.com/n0-computer/iroh/commit/8d13e4f691bd3eab5a8af93c34e2b93bc5c52995))
* **iroh-car:** limit to 4MiB not 4GiB ([34eedb8](https://github.com/n0-computer/iroh/commit/34eedb83f39cf9fd581a62c7c91ed7f668a14bc8))
* **iroh-gateway:** add `FileType::Raw` option ([#332](https://github.com/n0-computer/iroh/issues/332)) ([ff4ef02](https://github.com/n0-computer/iroh/commit/ff4ef0254cc663d1bb757559aed032bc38f25ea5))
* **iroh-gateway:** increase timeouts ([c3d56c6](https://github.com/n0-computer/iroh/commit/c3d56c6c52a209e1cd850f9c5e89aede8a8073ee))
* **iroh-one:** use default store path when no --store-path flag present ([#317](https://github.com/n0-computer/iroh/issues/317)) ([643fd43](https://github.com/n0-computer/iroh/commit/643fd43a2256db9e9bf622dcf4981d81b1ff48ff)), closes [#255](https://github.com/n0-computer/iroh/issues/255) [#309](https://github.com/n0-computer/iroh/issues/309)
* limit max memory allocations per node ([9817b5a](https://github.com/n0-computer/iroh/commit/9817b5a77106a12225b457ff42a64b5628737a2e))
* loger only on p2p ([b24c5fe](https://github.com/n0-computer/iroh/commit/b24c5fe2c8db05e4b75d4893192ba81d7e173ab9))
* macos releases ([#34](https://github.com/n0-computer/iroh/issues/34)) ([2fc0109](https://github.com/n0-computer/iroh/commit/2fc0109830ba1edfb3d4daa2ddbbfce0e62b5d10))
* make trace_id visible only if in use ([#359](https://github.com/n0-computer/iroh/issues/359)) ([c29bf85](https://github.com/n0-computer/iroh/commit/c29bf85d2d2a02e2a45bd4e3387c139c9693d20a))
* metrics rework & update ([#69](https://github.com/n0-computer/iroh/issues/69)) ([6c1d003](https://github.com/n0-computer/iroh/commit/6c1d0035d480592271ddcc13a4f0d9d434a13326))
* metrics toggle on store ([2b12158](https://github.com/n0-computer/iroh/commit/2b1215833bcea718f4e0ba47a3b9b71ffa0b8181))
* move bitswap msg counters out of encode/decode ([#374](https://github.com/n0-computer/iroh/issues/374)) ([85d80b9](https://github.com/n0-computer/iroh/commit/85d80b9d5fc9441e1912d07adc67130f9b0fa6b2))
* p2p subcommand output cleanup ([#427](https://github.com/n0-computer/iroh/issues/427)) ([0ca029c](https://github.com/n0-computer/iroh/commit/0ca029c143f5d6f9a9f5ebbfaafc0ccdd18340ad))
* **p2p:** cleanup sessions when they are canceled ([#419](https://github.com/n0-computer/iroh/issues/419)) ([efa9e82](https://github.com/n0-computer/iroh/commit/efa9e820a8288746b6196dc3eb25fe64c4c32e63))
* **p2p:** do not panic on shutdown of bs req ([b05b94a](https://github.com/n0-computer/iroh/commit/b05b94a124f81e8ca9eb180b751688d7c0cd3ba5))
* **p2p:** enable rsa key keys again ([afeafb4](https://github.com/n0-computer/iroh/commit/afeafb4383b4428936b0bb14f50b95e623e29557))
* **p2p:** ensure default grpc connections work ([eec218d](https://github.com/n0-computer/iroh/commit/eec218d1a7548aaac40a41b1cbd009babcd3d868))
* **p2p:** Increase the size of the kad mem store ([#320](https://github.com/n0-computer/iroh/issues/320)) ([00f5660](https://github.com/n0-computer/iroh/commit/00f56604e2bd85cd418018d349a17105aaffbf03))
* **p2p:** record Kad, Identify and Ping metrics ([af8eaa9](https://github.com/n0-computer/iroh/commit/af8eaa96b7f5a751ed703cbc61a3eaa76a025962))
* **p2p:** remove debug logs ([#420](https://github.com/n0-computer/iroh/issues/420)) ([23e1b3a](https://github.com/n0-computer/iroh/commit/23e1b3aedf1efaa566db5495bb691cbb4a8ba487))
* parameters and connection handling ([96514d3](https://github.com/n0-computer/iroh/commit/96514d36d54e604d97db8994805246838412e005))
* params ([#128](https://github.com/n0-computer/iroh/issues/128)) ([1f47d7c](https://github.com/n0-computer/iroh/commit/1f47d7c946a2e4497d5c17058908cc34c03cad4b))
* pass links to store when adding data ([#299](https://github.com/n0-computer/iroh/issues/299)) ([9476d9c](https://github.com/n0-computer/iroh/commit/9476d9ca3272e95630dc041400e0f6fadcd3d4a9))
* prom metrics no longer ping on --no-metrics ([#44](https://github.com/n0-computer/iroh/issues/44)) ([7f9c81a](https://github.com/n0-computer/iroh/commit/7f9c81adc4ef186ea7d215ccadd379e1a83348d6))
* properly saves filenames for hamt dirs ([#422](https://github.com/n0-computer/iroh/issues/422)) ([1fe8e69](https://github.com/n0-computer/iroh/commit/1fe8e69f690b1e28d20cc2f407054caca04663a1))
* properly setup the default config for iroh-one ([#256](https://github.com/n0-computer/iroh/issues/256)) ([a1e4940](https://github.com/n0-computer/iroh/commit/a1e494055ceb06a07347e94c733acb0246544ef5))
* protoc from release bins ([#42](https://github.com/n0-computer/iroh/issues/42)) ([28cc3ab](https://github.com/n0-computer/iroh/commit/28cc3ab8f761173795be00d933ebee60c1ef859c))
* require passing providers to fetch_bitswap ([771ee00](https://github.com/n0-computer/iroh/commit/771ee001361ec19a3d8f62ea4edbe71308b144df)), closes [#73](https://github.com/n0-computer/iroh/issues/73)
* **resolver:** handle trailing slashes in the path with more sense ([#414](https://github.com/n0-computer/iroh/issues/414)) ([9ef95e8](https://github.com/n0-computer/iroh/commit/9ef95e81f034cc9c36ed3e35367992fde8d1a8c0))
* **resolver:** ipld, double-fetching, and trailing slash fixes ([#408](https://github.com/n0-computer/iroh/issues/408)) ([f861102](https://github.com/n0-computer/iroh/commit/f861102becd3d2f20f073c29e181805d01b8932d))
* **resolver:** stop sessions when requests are done ([9c46cb0](https://github.com/n0-computer/iroh/commit/9c46cb07cb52a57e41d0a51296fd0b781d1861d7))
* rpc creation no longer blocks the gateway ([#111](https://github.com/n0-computer/iroh/issues/111)) ([8f1d93c](https://github.com/n0-computer/iroh/commit/8f1d93c4955e95ed19f470176e76219982a066b9))
* **rpc-client:** correct address format for clients ([8cde5cf](https://github.com/n0-computer/iroh/commit/8cde5cf4d405f1230acd1464c6b190ad12fe6973))
* **rpc-client:** use multihash to query providers ([2b11a14](https://github.com/n0-computer/iroh/commit/2b11a142de5fa0fc7d68528909e3c1bb6846cdb2))
* stop preventing any directory or file `foo` from existing in the project ([#334](https://github.com/n0-computer/iroh/issues/334)) ([3ef7ccc](https://github.com/n0-computer/iroh/commit/3ef7cccea1475bd288d53b70f753ca37c8b47944))
* switch back to rust-libp2p master ([1336e9e](https://github.com/n0-computer/iroh/commit/1336e9ee1f56b4233659b36c49d52bf5b4199bcb))
* tracing on request level ([#85](https://github.com/n0-computer/iroh/issues/85)) ([562e6d8](https://github.com/n0-computer/iroh/commit/562e6d8cc702c9ba1c82a61ae42031d2a760532a))
* undo label change ([#219](https://github.com/n0-computer/iroh/issues/219)) ([3433340](https://github.com/n0-computer/iroh/commit/34333403f99d593276561fbbe43a35d8160cb048))
* Update ipld in iroh-car to limit prost duplicates ([#307](https://github.com/n0-computer/iroh/issues/307)) ([ee43bd7](https://github.com/n0-computer/iroh/commit/ee43bd7063fcf6174025aea023151f519bd4b4fc))
* use rustls ([#64](https://github.com/n0-computer/iroh/issues/64)) ([0c37cef](https://github.com/n0-computer/iroh/commit/0c37cef26981807aee1cb3b60122ba15c05f09cd))
* use the uds-gateway feature only to control the http uds endpoint ([#252](https://github.com/n0-computer/iroh/issues/252)) ([9bcbb59](https://github.com/n0-computer/iroh/commit/9bcbb59ec0282ae3dfa962d20ceb25dfff5505b5))
* windows symlink support ([#386](https://github.com/n0-computer/iroh/issues/386)) ([563aac0](https://github.com/n0-computer/iroh/commit/563aac0bfc42c662b69c418c2f1004d1c5f82e12))


### Features

* `iroh-ctl add` & `iroh-ctl get` ([#164](https://github.com/n0-computer/iroh/issues/164)) ([979a36f](https://github.com/n0-computer/iroh/commit/979a36f15ad982015743b288ec35d92510d6620a))
* `iroh-ctl status -w` watches the health of each iroh process ([#84](https://github.com/n0-computer/iroh/issues/84)) ([22b2bb5](https://github.com/n0-computer/iroh/commit/22b2bb5cfd4a4cae0f2a58bd0872a34aef5b95fe))
* abstract over internal rpc mechanism & add support for UDS & Mem RPC  ([6e859c2](https://github.com/n0-computer/iroh/commit/6e859c2c3d4e12e1dfd1e795ec139b47cdee140a))
* add car importer ([aabfb9a](https://github.com/n0-computer/iroh/commit/aabfb9a4df18ab8dc3bd9394fd73007704958817))
* add iroh-car ([#27](https://github.com/n0-computer/iroh/issues/27)) ([26a1b86](https://github.com/n0-computer/iroh/commit/26a1b86b785f2dda1cf0d8027ec1549383b35336)), closes [#9](https://github.com/n0-computer/iroh/issues/9)
* add placeholder iroh-bitswap and iroh-p2p crates ([9c4ab10](https://github.com/n0-computer/iroh/commit/9c4ab108796a4fb4179c95b3787bb8591eff3e47))
* add rust-toolchain@1.61 ([b08ac2b](https://github.com/n0-computer/iroh/commit/b08ac2b52aa8078d3403f5458c85f204685a0340))
* add trace id to responses ([#28](https://github.com/n0-computer/iroh/issues/28)) ([9d9c89e](https://github.com/n0-computer/iroh/commit/9d9c89e946096b5736e39917a1b2a696dd695bc7))
* Allow to pass custom resolvers ([#220](https://github.com/n0-computer/iroh/issues/220)) ([9d319c5](https://github.com/n0-computer/iroh/commit/9d319c58468e583a809f058d82c0146b3ddacff8))
* bad bits implementation ([#172](https://github.com/n0-computer/iroh/issues/172)) ([bda0173](https://github.com/n0-computer/iroh/commit/bda01739d6678d491726594a07c7e98679f41c30))
* **bitswap:** add dial timeouts ([06e0104](https://github.com/n0-computer/iroh/commit/06e0104e4ba520252bf18130ca5d7620c0c0509b))
* **bitswap:** add query errors and start cleanups ([72ae431](https://github.com/n0-computer/iroh/commit/72ae431c704bb4f20820f039050bd3d666cdf365))
* **bitswap:** allow tracking queries based on ids ([21f75d5](https://github.com/n0-computer/iroh/commit/21f75d5c2967e001a3246ba89487e8fc5519e290))
* **bitswap:** custom protocol handler for bitswap ([ff2ebc3](https://github.com/n0-computer/iroh/commit/ff2ebc3cedbd583632b753af10b2a7fb94d51a88))
* **bitswap:** refactor & improve general strategy ([0747310](https://github.com/n0-computer/iroh/commit/07473107dc92419573d97c10cf132c1630eca5b2))
* CLI get command improvements ([#331](https://github.com/n0-computer/iroh/issues/331)) ([b18b6c8](https://github.com/n0-computer/iroh/commit/b18b6c835af523ba8b300392af0d74cd4ad9f7a6)), closes [#269](https://github.com/n0-computer/iroh/issues/269)
* CLI tests for iroh add, and API changes ([#343](https://github.com/n0-computer/iroh/issues/343)) ([fdf2170](https://github.com/n0-computer/iroh/commit/fdf2170bb62a646537aa976e18c1e01f9895dd47))
* connect the dots ([4b15df5](https://github.com/n0-computer/iroh/commit/4b15df5a2a003ff28ebf843197cc204dcd57dc97))
* connection pooling ([#404](https://github.com/n0-computer/iroh/issues/404)) ([b499751](https://github.com/n0-computer/iroh/commit/b4997515edadcbbba85d6ad1e8f1aa5c16c3d84f))
* ctl ci ([#175](https://github.com/n0-computer/iroh/issues/175)) ([b7ebf02](https://github.com/n0-computer/iroh/commit/b7ebf021d4160c5ec1dad8288086f7c06084b7b2))
* **deps:** update libp2p to 0.47 ([9dadadc](https://github.com/n0-computer/iroh/commit/9dadadca25c518b1f6bf21853c8ebd52dad8dbdb))
* distributed tracing ([#46](https://github.com/n0-computer/iroh/issues/46)) ([3e555bc](https://github.com/n0-computer/iroh/commit/3e555bcab38faee61ff4da6689d28710f0e68018))
* don't run 'dht_nice_tick()' when kadmelia is disabled ([#242](https://github.com/n0-computer/iroh/issues/242)) ([050ad48](https://github.com/n0-computer/iroh/commit/050ad4862c95f7535cae062d31b7014c5c0a00d9))
* Enable the CompressionLayer middleware ([#236](https://github.com/n0-computer/iroh/issues/236)) ([9151fc1](https://github.com/n0-computer/iroh/commit/9151fc13daaf5c2535c2708ec81d69fe6a234ed2))
* fetch providers via bitswap ([b16be5a](https://github.com/n0-computer/iroh/commit/b16be5a98430374ac7b86d93e4a70f170621c309))
* gateway upgrade ([#87](https://github.com/n0-computer/iroh/issues/87)) ([4732a76](https://github.com/n0-computer/iroh/commit/4732a76a435b7b46b23d574c337ee9b81cee2449))
* **gateway:** initial directory listing support ([#328](https://github.com/n0-computer/iroh/issues/328)) ([3316a53](https://github.com/n0-computer/iroh/commit/3316a53776311a38287b92126fdbacb21ad35897))
* get config from files, environment vars, & command line flags ([#112](https://github.com/n0-computer/iroh/issues/112)) ([652b7ff](https://github.com/n0-computer/iroh/commit/652b7ffd3750b2bc40f8a305bb0626e446f4fc3c))
* implement basic iroh-store ([a1b9586](https://github.com/n0-computer/iroh/commit/a1b9586a3b9829c0989232c9e910c4d6945b7802))
* implement iroh-ctl find-provs ([#182](https://github.com/n0-computer/iroh/issues/182)) ([ec06238](https://github.com/n0-computer/iroh/commit/ec06238fe137c7e0fcd51a5f48aa1a9a9ba34d65))
* import flatfs-store and rocks-store crates ([4ac82a8](https://github.com/n0-computer/iroh/commit/4ac82a88c5f2fe8566cca2d7ae6f265a96e00375))
* **importer:** add hash verification ([96eda12](https://github.com/n0-computer/iroh/commit/96eda1247683d5f23be60381d7bb9dd8fc7b31da))
* improve add experience ([#401](https://github.com/n0-computer/iroh/issues/401)) ([4f86388](https://github.com/n0-computer/iroh/commit/4f8638816d0fc4e8260ce06781b22baa4dbc2f44))
* improve CLI texts and flags ([#342](https://github.com/n0-computer/iroh/issues/342)) ([9e0a03e](https://github.com/n0-computer/iroh/commit/9e0a03e7cc207e7ac76d7659db4a5500f97d131e))
* improve provider fetching ([38ce246](https://github.com/n0-computer/iroh/commit/38ce24653261469c74ee354b4071340907bdd804))
* iroh-api rename, iroh get basics, rpc client construction ([d24edc1](https://github.com/n0-computer/iroh/commit/d24edc1344fb2c14e58cd5272d9d968009d187de))
* **iroh-api:** implement lookup & connect ([#372](https://github.com/n0-computer/iroh/issues/372)) ([a93dfb4](https://github.com/n0-computer/iroh/commit/a93dfb4eb77d5eb5d53a1504b3aed7fa19027e73))
* **iroh-ctl:** implement available commands ([#123](https://github.com/n0-computer/iroh/issues/123)) ([c6bdca3](https://github.com/n0-computer/iroh/commit/c6bdca30401ac85be1076ce6cee574a8fc57efd6))
* iroh-one ([#212](https://github.com/n0-computer/iroh/issues/212)) ([11fe705](https://github.com/n0-computer/iroh/commit/11fe705496e3b450aa677368bc32f5b1c5a3c0b1))
* **iroh-resolver:** create a balanced tree dag  ([3285d1f](https://github.com/n0-computer/iroh/commit/3285d1f50f170721e7c1abbe778f71f85621854c))
* **iroh-resolver:** implement unixfs dir listing ([263b3c2](https://github.com/n0-computer/iroh/commit/263b3c2c91b53d00fa675a47f00946e2c85ea5f8))
* **iroh-store:** add minimal main implementation ([b1c49a1](https://github.com/n0-computer/iroh/commit/b1c49a19c6436a3c2e89e9880fb5250fb22f4daf))
* Map id to cid instead of multihash ([#336](https://github.com/n0-computer/iroh/issues/336)) ([092bdf7](https://github.com/n0-computer/iroh/commit/092bdf72b32e01099a6e3fd8ded818e3eeeebe41)), closes [#335](https://github.com/n0-computer/iroh/issues/335)
* offline adding ([#415](https://github.com/n0-computer/iroh/issues/415)) ([7725508](https://github.com/n0-computer/iroh/commit/772550834f3861d3c38c2e9a0b97a24440df778d))
* p2p api service calls with a p2p-specific error, better feedback ([#402](https://github.com/n0-computer/iroh/issues/402)) ([b565231](https://github.com/n0-computer/iroh/commit/b56523103224f3b77bf0b6d455911cf87b628c4f))
* **p2p:** add `gossipsub` to p2p node & `gossipsub` rpc methods ([#132](https://github.com/n0-computer/iroh/issues/132)) ([f18d726](https://github.com/n0-computer/iroh/commit/f18d726c4f26f9ad91a3f28ed428a884a5583140))
* **p2p:** improve default configurations for dht and bs ([791181a](https://github.com/n0-computer/iroh/commit/791181a9b11fdbcbedcad5c367f935a9762fb261))
* **p2p:** integrate autonat protocol ([5c5c1b0](https://github.com/n0-computer/iroh/commit/5c5c1b046f55c5eaeb600dff882010c376854e02))
* **p2p:** integrate relay and dcutr ([6555090](https://github.com/n0-computer/iroh/commit/6555090245c688f232d95a90338f2b277b0bfefe))
* **p2p:** make bitswap toglable ([648bcbf](https://github.com/n0-computer/iroh/commit/648bcbffc8d08f7bb5d57644954063e8d3566c38))
* **p2p:** make gossipsub configurable  ([071fd1b](https://github.com/n0-computer/iroh/commit/071fd1bad42c8d3228a478a92af74bf321195dd8))
* **p2p:** persist identity ([8f57278](https://github.com/n0-computer/iroh/commit/8f57278e2738baac0d528a28da5fcd89d6a658c3))
* **p2p:** refresh kad buckets & rebootstrap regularly ([339ed13](https://github.com/n0-computer/iroh/commit/339ed13789352eb0abf56e18ea1e23593647e9c7))
* **p2p:** respond to bitswap requests ([965e21c](https://github.com/n0-computer/iroh/commit/965e21c68d10e381e20f771e948e96ebf7a39c85))
* progress bar for iroh add command ([#368](https://github.com/n0-computer/iroh/issues/368)) ([bff3560](https://github.com/n0-computer/iroh/commit/bff3560a22e4240e61d4558c7cf1f11b129b30df))
* provide a mechanism to check if an iroh program is already running. ([#293](https://github.com/n0-computer/iroh/issues/293)) ([bddbae9](https://github.com/n0-computer/iroh/commit/bddbae90f49c7ea45a2900ad1fa4560d9482bd60))
* provide only root, and only at the end of add ([#406](https://github.com/n0-computer/iroh/issues/406)) ([96c6148](https://github.com/n0-computer/iroh/commit/96c614839127a0b881ac100e3102abca70cb3a87))
* race a http gateway with p2p in iroh-one's content loader ([#338](https://github.com/n0-computer/iroh/issues/338)) ([40cb232](https://github.com/n0-computer/iroh/commit/40cb232dc3ff69bfed90242eb986f853cab093c6))
* range request support ([#330](https://github.com/n0-computer/iroh/issues/330)) ([074f0c6](https://github.com/n0-computer/iroh/commit/074f0c664578ff4f9108cb388aeb376f0baf3b9c))
* recursive directories & directory link limits ([#213](https://github.com/n0-computer/iroh/issues/213)) ([be4e931](https://github.com/n0-computer/iroh/commit/be4e9311b3bf28ad3ae97bdffd8aa20164a0873c))
* relases for p2p, store & some refactoring ([#45](https://github.com/n0-computer/iroh/issues/45)) ([d101e5a](https://github.com/n0-computer/iroh/commit/d101e5a5883dfaf378d2e15b384ae61c37dae1d7))
* rename the iroh-ctl crate to the iroh crate ([#321](https://github.com/n0-computer/iroh/issues/321)) ([8b02977](https://github.com/n0-computer/iroh/commit/8b0297792cffb9cebf84ed1c64d2ff48b64aaf41))
* **resolver:** add support for raw leaves in unixfs ([1d6d57d](https://github.com/n0-computer/iroh/commit/1d6d57d9de1c0ef1328bf1e5e982544d89982040))
* **resolver:** expose metadata about the resolution result ([a229875](https://github.com/n0-computer/iroh/commit/a229875b1585e122552c3117c38aedae93fa07dd))
* **resolver:** expose way to get directory content ([9b59326](https://github.com/n0-computer/iroh/commit/9b5932624b12866527310e6886354a201ed998a3))
* **resolver:** handle symlinks properly ([5cc84ea](https://github.com/n0-computer/iroh/commit/5cc84eaa655f6f4ac3dfb1209877aed3f9b1ea18))
* **resolver:** implement dsnlink resolution ([5fa893d](https://github.com/n0-computer/iroh/commit/5fa893d0d7550ddc541763f0b52670a15a2acf34))
* **resolver:** stream content ([3d419b5](https://github.com/n0-computer/iroh/commit/3d419b5f59ea05badf95d90a25a52afbc6ba1e2b))
* **resolver:** support raw codec ([25d5b28](https://github.com/n0-computer/iroh/commit/25d5b283387b7594b92e5f3579fd86ce3836840a))
* **resolver:** unixfs: resolve simple multi chunk files ([fa94b6d](https://github.com/n0-computer/iroh/commit/fa94b6d064a8f1df65eea4b1bf622415e7203ac0))
* rpc client that can handle out-going commands and incoming requests ([#26](https://github.com/n0-computer/iroh/issues/26)) ([f2fd5cb](https://github.com/n0-computer/iroh/commit/f2fd5cbae5ac7023f8e5c304323fe8f8be3ab946))
* **rpc:** add rpc client and server for `store` process ([#41](https://github.com/n0-computer/iroh/issues/41)) ([854b605](https://github.com/n0-computer/iroh/commit/854b605e80c311152ecff54ceccf6b0f91b18e3c))
* streaming providers ([a810e07](https://github.com/n0-computer/iroh/commit/a810e0744a66825413ae5772ae7445a4df4d922a))
* switch to libp2p@0.45 ([f1dd5f7](https://github.com/n0-computer/iroh/commit/f1dd5f73341f0c8c71c21bc5d69f026fd3482267))
* Unixfs Improvements  ([42dee06](https://github.com/n0-computer/iroh/commit/42dee0644fe3605bbf6df3bd2415409fccb6bfe2))
* **unixfs:** add `filesize` and `blocksizes` for `UnixfsNode::File` nodes ([#254](https://github.com/n0-computer/iroh/issues/254)) ([6ba6b57](https://github.com/n0-computer/iroh/commit/6ba6b576de067c44fc3fea80e67a5edcf05ec2c9))
* **unixfs:** add symlink support ([#337](https://github.com/n0-computer/iroh/issues/337)) ([3157c15](https://github.com/n0-computer/iroh/commit/3157c15fb1dc359f3d45b53744d29f1dd548a1ec))
* update libp2p to latest ([39b25e8](https://github.com/n0-computer/iroh/commit/39b25e874284d8f4218f75b82a6c73fcb10a25df))
* update rust-libp2p  ([c595c4d](https://github.com/n0-computer/iroh/commit/c595c4dbdeeb61b9bdd2aa1fba44e890e7eeb529))
* update to libp2p@0.50 ([#391](https://github.com/n0-computer/iroh/issues/391)) ([8a906ee](https://github.com/n0-computer/iroh/commit/8a906eeb9889c28c28c3a6fd3802065ad5aadf82))
* upload gateway builds to s3 (linux/amd64) ([#29](https://github.com/n0-computer/iroh/issues/29)) ([1918a83](https://github.com/n0-computer/iroh/commit/1918a8386dd90ac5e7c0c5b634ebb3e849719ed9))
* use the store to cache received data ([9dac53a](https://github.com/n0-computer/iroh/commit/9dac53ae689e3ef46a4800aa5c1df22913daf1c3))


### Performance Improvements

* add parallelism to hashing ([#411](https://github.com/n0-computer/iroh/issues/411)) ([12db7ed](https://github.com/n0-computer/iroh/commit/12db7ede56ed16ecc18e83ec1e9f5b9f507239b9))
* impl put_many and reuse column families ([#412](https://github.com/n0-computer/iroh/issues/412)) ([4cab5c7](https://github.com/n0-computer/iroh/commit/4cab5c79f5ba7c206be92729aad337ad3274e81e))
* **resolver:** avoid some allocations ([9f2d718](https://github.com/n0-computer/iroh/commit/9f2d718b3e3717e9a8971b3d28652fa4434273e6))
* use content_bytes instead of content_reader ([9dd0c22](https://github.com/n0-computer/iroh/commit/9dd0c228af91712a4a948a24e79068061078dbb9))
* Use the libipld built in way to scrape references ([93546b1](https://github.com/n0-computer/iroh/commit/93546b11139bd54cfd4792613a3000d1ec8c8a27))


### Reverts

* Revert "fix dial metrics" ([5f4c063](https://github.com/n0-computer/iroh/commit/5f4c063cbd29aa1231c56334b4197cca0ff536a2))
* Revert "update to libp2p@0.49 (#266)" ([59d7a3d](https://github.com/n0-computer/iroh/commit/59d7a3d4833001d1d22a54819337d80136183a80)), closes [#266](https://github.com/n0-computer/iroh/issues/266)
