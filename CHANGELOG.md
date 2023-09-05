# [v0.6.0-alpha.1](https://github.com/n0-computer/iroh/compare/v0.6.0-alpha.0...v0.6.0-alpha.1) (2023-09-05)

This release includes important fixes and improvements based on recent testing. Document sync is now more correct and faster!

### Bug Fixes

* **iroh-net:** dns fallback to default config ([#1438](https://github.com/n0-computer/iroh/issues/1438)) ([b89f4e1](https://github.com/n0-computer/iroh/commit/b89f4e1528339528f6b620f9dece524ffcdfa977)), closes [#1436](https://github.com/n0-computer/iroh/issues/1436)
* **iroh:** update example to use correct subscription API ([#1452](https://github.com/n0-computer/iroh/issues/1452)) ([2522fca](https://github.com/n0-computer/iroh/commit/2522fcabfcc1edcd492ae5f4696a69530e2dee7d)), closes [#1451](https://github.com/n0-computer/iroh/issues/1451)


### Features

* get list of `ConnectionInfo`s or an individual node's `ConnectionInfo` ([#1435](https://github.com/n0-computer/iroh/issues/1435)) ([bdf966e](https://github.com/n0-computer/iroh/commit/bdf966ef04de18966c6cced7c32983675bea1471))
* **iroh-sync:** validate timestamps and move validation up ([#1439](https://github.com/n0-computer/iroh/issues/1439)) ([4e8ff56](https://github.com/n0-computer/iroh/commit/4e8ff5653d8a6dd4548bef7886060525c3025acd))



# [v0.6.0-alpha.0](https://github.com/n0-computer/iroh/compare/v0.5.1...v0.6.0-alpha.0) (2023-08-28)

_This is the first alpha preview of iroh v0.6.0. iroh v0.6.0 is targeting a Sept 25th release date._

v0.6.0 is a big step toward iroh 1.0. It introduces documents, the See our [docs pages](https://iroh.computer/docs) for a detailed look at the new iroh.

## Introducing documents

Documents are mutable key-value stores that authors read from, write to, and sync with, subscribing to live updates in real time. For more on documents, see the [docmuents, uh, documentation](https://iroh.computer/docs/layers/documents)

## Iroh console is here to help

this release includes `iroh console` an admin, debugging, and API exploration tool. It's a REPL that can give live feedback as documents change, users sync, etc. For a detailed rundown on console commands, see the [iroh command documentation](https://iroh.computer/docs/commands)


### Bug Fixes

* **ci:** correctly detect forks ([#1327](https://github.com/n0-computer/iroh/issues/1327)) ([80c54aa](https://github.com/n0-computer/iroh/commit/80c54aa2ba1d16914dc9b09ca283136fe16a46a1))
* enable derp metrics ([#1268](https://github.com/n0-computer/iroh/issues/1268)) ([faad31a](https://github.com/n0-computer/iroh/commit/faad31ad84212da608851b228fe4d05e7d0e5811))
* **iroh-bytes:** Hash should be serialized as array not bytes ([#1410](https://github.com/n0-computer/iroh/issues/1410)) ([116eea9](https://github.com/n0-computer/iroh/commit/116eea9eaf40d81ebaadd62c5f0f6259781c57f8))
* **iroh-bytes:** range spec seq identification of single blobs ([#1421](https://github.com/n0-computer/iroh/issues/1421)) ([c3e701f](https://github.com/n0-computer/iroh/commit/c3e701f18140c1f96ca99276d223ae0a5c737752))
* **iroh-net:** do not panic on RIB issues ([#1313](https://github.com/n0-computer/iroh/issues/1313)) ([8ede947](https://github.com/n0-computer/iroh/commit/8ede9473b15c46eef16a444767480360894ba70c))
* **iroh-net:** portmapper priority follows described priority strategy ([#1324](https://github.com/n0-computer/iroh/issues/1324)) ([f60101a](https://github.com/n0-computer/iroh/commit/f60101a8ab75acd2ead1d5c62fbd5d179e948fac))
* **iroh-net:** remove `transparent` attribute from mapping debug + log bump ([#1339](https://github.com/n0-computer/iroh/issues/1339)) ([2878e79](https://github.com/n0-computer/iroh/commit/2878e797163661cb921978d5a68139968b6f7e5c))
* **iroh-net:** split packets on send ([#1380](https://github.com/n0-computer/iroh/issues/1380)) ([57a2dee](https://github.com/n0-computer/iroh/commit/57a2dee84af44d2877b8bddf7f0b790f4be879d8))
* **iroh-net:** use base32 encoding in the derper config for SecretKey ([#1385](https://github.com/n0-computer/iroh/issues/1385)) ([b8a1de8](https://github.com/n0-computer/iroh/commit/b8a1de8a39e28b4c02a9904374a43037d70f834c))
* **iroh:** atomically write keyfile ([7752b5a](https://github.com/n0-computer/iroh/commit/7752b5a663876f9af293d5aea5fdfd3fe53ee1fa))
* **iroh:** pass derp map when setting up provider ([#1347](https://github.com/n0-computer/iroh/issues/1347)) ([391db92](https://github.com/n0-computer/iroh/commit/391db92a64e877eff4c61fcdb7e4a099aba0c4c0))
* **iroh:** Try to fix flaky test_token_passthrough test ([#1419](https://github.com/n0-computer/iroh/issues/1419)) ([a1d4a4d](https://github.com/n0-computer/iroh/commit/a1d4a4d71b7f8c954c8b5627f31617ddef6bcdf6))
* **netcheck:** Build test ProbePlan from fake interface data ([#1266](https://github.com/n0-computer/iroh/issues/1266)) ([f671aa5](https://github.com/n0-computer/iroh/commit/f671aa509a92f96b63404815acbbbe479c888aa4)), closes [#1263](https://github.com/n0-computer/iroh/issues/1263)
* Remove obsolete and unused module ([#1279](https://github.com/n0-computer/iroh/issues/1279)) ([4c67385](https://github.com/n0-computer/iroh/commit/4c67385982d8e0c57399c9f275a2aaf3e19ac9b5))
* **tests:** bring back MagicEndpoint connect-close test ([#1282](https://github.com/n0-computer/iroh/issues/1282)) ([4b1f79c](https://github.com/n0-computer/iroh/commit/4b1f79c5aedd44fe8e703f67d916368ba35e917f)), closes [#1183](https://github.com/n0-computer/iroh/issues/1183)


### Features

* add iroh-sync and integrate into iroh node ([#1333](https://github.com/n0-computer/iroh/issues/1333)) ([3f141be](https://github.com/n0-computer/iroh/commit/3f141be6fd2951f10c97ff8434fd78fc40a1afcc)), closes [#1216](https://github.com/n0-computer/iroh/issues/1216) [#1149](https://github.com/n0-computer/iroh/issues/1149) [#1344](https://github.com/n0-computer/iroh/issues/1344) [#1356](https://github.com/n0-computer/iroh/issues/1356) [#1366](https://github.com/n0-computer/iroh/issues/1366) [#1334](https://github.com/n0-computer/iroh/issues/1334) [#1354](https://github.com/n0-computer/iroh/issues/1354) [#1354](https://github.com/n0-computer/iroh/issues/1354)
* Iroh console (REPL) and restructured CLI ([#1356](https://github.com/n0-computer/iroh/issues/1356)) ([b73d950](https://github.com/n0-computer/iroh/commit/b73d9504d64ac09bbd7c675d1047d948edbfd0f6)), closes [#1216](https://github.com/n0-computer/iroh/issues/1216) [/github.com/clap-rs/clap/discussions/5070#discussioncomment-6721310](https://github.com//github.com/clap-rs/clap/discussions/5070/issues/discussioncomment-6721310)
* **iroh-bytes:** remove unneeded u64 length prefix ([#1408](https://github.com/n0-computer/iroh/issues/1408)) ([6d9eac7](https://github.com/n0-computer/iroh/commit/6d9eac7fef834ceb5fd980c9031aea722b08ac2f))
* iroh-gossip ([#1149](https://github.com/n0-computer/iroh/issues/1149)) ([7f8463f](https://github.com/n0-computer/iroh/commit/7f8463f48587e2173f7d8fb8851e4beea148d7de))
* **iroh-net:** add `DEV_DERP_ONLY` env variable for testing the derp relay ([#1378](https://github.com/n0-computer/iroh/issues/1378)) ([34c97bb](https://github.com/n0-computer/iroh/commit/34c97bb688cbf3ffd096246b22fa85d11402738b))
* **iroh-net:** Nat-PMP probes and mappings ([#1283](https://github.com/n0-computer/iroh/issues/1283)) ([5c38730](https://github.com/n0-computer/iroh/commit/5c387308a14e17738efed2e4bcefee02141e13cd))
* **iroh-net:** PCP mappings ([#1261](https://github.com/n0-computer/iroh/issues/1261)) ([84e2f72](https://github.com/n0-computer/iroh/commit/84e2f721a0505ee44d04c01df0daa54dcbd400ab))
* methods to check if a hash is complete or partial ([#1359](https://github.com/n0-computer/iroh/issues/1359)) ([8006629](https://github.com/n0-computer/iroh/commit/800662957f67030014102653004e6490ebc4ea3b))
* **tests:** Improve test_utils to warn about mutli-runtime tests ([#1280](https://github.com/n0-computer/iroh/issues/1280)) ([62522dc](https://github.com/n0-computer/iroh/commit/62522dccaefaeca9ac13393329d3fbe7db48b203))



# [v0.5.1](https://github.com/n0-computer/iroh/compare/v0.4.1...v0.5.1) (2023-08-28)

## Connectivity Intensifies 

> First you have to find one another, before you can interact.

This release is all about finding and connecting with your peers. Before iroh could only connect with peers that were directly reachable, eg. static IP address or local LAN peers. Thanks to NATs and the various complications of IPv4 and IPv6 these are not that many machines in the world, and especially mobile devices are hard to discover.

So we are proud to present the first version of iroh with builtin NAT traversal, hole punching and automatic relaying when everything fails.

If you want to find out the details on how all of this works, header over to the [Iroh Hole Punching doc](https://iroh.computer/docs/layers/connections/holepunching).

Of course that is not all, we have also fixed some pesky bugs, as well added some more features, like generic collections and pluggable authentication.

On a practical side, iroh is now split into multiple crates:

- `iroh` - The CLI and main library entry point.
- `iroh-bytes` - The core data transfer protocol, including resume.
- `iroh-net` - Nat traversal, peer management and general networking tools.
- `iroh-metrics` - Metrics collection using prometheus

This should open up more possibilities when integrating just the pieces you need from iroh into your app.

[Note: this ended up being 0.5.1 for iroh and iroh-net due to a publish issue with iroh-net@0.5.0]


### Bug Fixes

* add entry in peer_map for unknown ping sender ([648210c](https://github.com/n0-computer/iroh/commit/648210c6c23b4e637df574441ef06f0294960d62))
* allow dialing by peer id only ([6fb17d1](https://github.com/n0-computer/iroh/commit/6fb17d1efb23b56c01ac2f43d62e42507a1c2010))
* avoid dualstack bindings ([34322a6](https://github.com/n0-computer/iroh/commit/34322a6be04028a1d6fdfe5e8c3b03d0f09b260d))
* avoid polling future after completion ([1f812fd](https://github.com/n0-computer/iroh/commit/1f812fd1b853c9bf699d1c678bb27122ce2f58df))
* avoid using tokio::block_in_place ([db5ad3e](https://github.com/n0-computer/iroh/commit/db5ad3e0976cd2f66fcc2dc773b74f6cd7ea1ba8))
* better handling of ipv4 only setups ([547662b](https://github.com/n0-computer/iroh/commit/547662b1526df58378157d61a1855eb38ba95e3d))
* checkout correct branch on netsim comment ([#934](https://github.com/n0-computer/iroh/issues/934)) ([fa2ae68](https://github.com/n0-computer/iroh/commit/fa2ae68a9a2b9968216de445c206492d518e1d42))
* **ci:** Also run doc tests ([#1095](https://github.com/n0-computer/iroh/issues/1095)) ([97d24a6](https://github.com/n0-computer/iroh/commit/97d24a6a873420455ad0ca71da2bdaea6c35725f))
* **ci:** move chuck out of the workspace ([0b8d22d](https://github.com/n0-computer/iroh/commit/0b8d22d75fba45ba827e6464ec36b9677dbff466))
* cleanup ping sending logic ([7896d37](https://github.com/n0-computer/iroh/commit/7896d37accd80a89f9bd67318e313cb04fdfcfb5))
* **clippy:** Clean up clippy again ([#1061](https://github.com/n0-computer/iroh/issues/1061)) ([4e1ba3e](https://github.com/n0-computer/iroh/commit/4e1ba3e77f79524a112b9ac2c55be61175fbe2a3))
* compile on linux ([02d8803](https://github.com/n0-computer/iroh/commit/02d880366ce42ced01552ca4c55ff814f9ae7a56))
* correct ipv4 and ipv6 port mappings on rebind and endpoints ([6a1e405](https://github.com/n0-computer/iroh/commit/6a1e405ecaa4ecca4883a053d1e3f409b641bf0a))
* correct ref on checkout ([#936](https://github.com/n0-computer/iroh/issues/936)) ([f58df87](https://github.com/n0-computer/iroh/commit/f58df87f34a8bd1110a835adfaccf2979e3867bb))
* cross builds ([#1174](https://github.com/n0-computer/iroh/issues/1174)) ([739ee07](https://github.com/n0-computer/iroh/commit/739ee072d28b848e999d6c84ed301cb7bbf0a5eb))
* **database:** Handle finding beetle data directory ([#960](https://github.com/n0-computer/iroh/issues/960)) ([909ea9a](https://github.com/n0-computer/iroh/commit/909ea9abda3217973d1313016656febc4bfd7b6b))
* default netsim branch ([#1208](https://github.com/n0-computer/iroh/issues/1208)) ([01da61d](https://github.com/n0-computer/iroh/commit/01da61d4389905ac57a144548dd00ae8c0c7c801))
* **derper:** small derper fixes ([#1083](https://github.com/n0-computer/iroh/issues/1083)) ([4fb925a](https://github.com/n0-computer/iroh/commit/4fb925ae865ed7ee291b454aad9cf9f732765ba4))
* **derp:** Filter DNS results by address family ([#1227](https://github.com/n0-computer/iroh/issues/1227)) ([b6f9df3](https://github.com/n0-computer/iroh/commit/b6f9df3bdd12f7f6d1840ab0427583c6658d2364))
* **derp:** remove client cleanup bug ([f6287c1](https://github.com/n0-computer/iroh/commit/f6287c17bf484bef0d6d63a20364424f1af5f64a))
* do not use magicsock for rpc ([7717243](https://github.com/n0-computer/iroh/commit/7717243e6b6ae2bab55cb9e685e528dfd1732fe1))
* don't crash the derper ([#1110](https://github.com/n0-computer/iroh/issues/1110)) ([e1752bc](https://github.com/n0-computer/iroh/commit/e1752bc07184ec9e0801cde0e0d86065c25e3cbb))
* don't spam re-connect attempts if something goes wrong connecting to a derp server ([#1113](https://github.com/n0-computer/iroh/issues/1113)) ([92e8fc3](https://github.com/n0-computer/iroh/commit/92e8fc3bc2628cf33306a21661ce7e7188c2cdf7))
* endpoint update scheduler ([93ca0e4](https://github.com/n0-computer/iroh/commit/93ca0e436054c9f2e7ff98268976a017dc1da21a))
* ensure endpoints are always discovered or timeout ([58538e0](https://github.com/n0-computer/iroh/commit/58538e005322c838736f25b8ec74a25dea70cff5))
* ensure provider building waits for an endpoint update ([c858f36](https://github.com/n0-computer/iroh/commit/c858f361195e486f721f7fea7002b196b7654874))
* fetch PR details on issue comment ([#931](https://github.com/n0-computer/iroh/issues/931)) ([9272adb](https://github.com/n0-computer/iroh/commit/9272adb37af1154112506956c4df97a165f052da))
* format socket addr so that it does not need to be escaped ([#1019](https://github.com/n0-computer/iroh/issues/1019)) ([7c87b94](https://github.com/n0-computer/iroh/commit/7c87b944da095c096880c56c6bb36be605710899))
* handle hairpining timeout properly ([#1049](https://github.com/n0-computer/iroh/issues/1049)) ([3867b72](https://github.com/n0-computer/iroh/commit/3867b720f94da91c5c6cf6aa7f1689c6e60b7dc7))
* handle multiple transmit destinations ([050e49f](https://github.com/n0-computer/iroh/commit/050e49f24c54faaf12bfff26a589dd2657113f27))
* improve binding and rebinding of sockets ([156560a](https://github.com/n0-computer/iroh/commit/156560aec24f20d06deafca425e5f18d338ec9ff))
* improve connectivity   ([8e2d947](https://github.com/n0-computer/iroh/commit/8e2d94782549e47de4215394772186eed64e2f44))
* improve local addr output and start fixing cli tests ([f76d650](https://github.com/n0-computer/iroh/commit/f76d6504c8df76154aa5489ffa8bee8ebf662609))
* **iroh-net:** allow derp only connections to upgrade ([25b35a3](https://github.com/n0-computer/iroh/commit/25b35a3c8e828ed1c11b1b5286508d8c90e00ba5))
* **iroh-net:** better logic for initial derp connection ([6e6b97e](https://github.com/n0-computer/iroh/commit/6e6b97eb90d2e68098145468774cfc1a7d4f45e0))
* **iroh-net:** handle non git environments in build ([a645cbe](https://github.com/n0-computer/iroh/commit/a645cbed0458e4f1dc438a307d4b1b2263c5103b))
* **iroh-net:** no * deps ([b1ff368](https://github.com/n0-computer/iroh/commit/b1ff36885be7dbcffbed86b84982867cdf54f654))
* **iroh:** error when path does not exist ([#1146](https://github.com/n0-computer/iroh/issues/1146)) ([c1b674f](https://github.com/n0-computer/iroh/commit/c1b674f9edc80e720291802b15f869378abf81cf)), closes [#1068](https://github.com/n0-computer/iroh/issues/1068)
* **iroh:** pass derp-map on get-options  ([b7fd889](https://github.com/n0-computer/iroh/commit/b7fd889e7806feeb941c0f611bbb3aa33a718b40))
* make sure to clean up any lingering processes ([#1214](https://github.com/n0-computer/iroh/issues/1214)) ([f782fef](https://github.com/n0-computer/iroh/commit/f782fef3217dc01c58381f9beb184481b829f7a1))
* make sure to use the config by default in iroh doctor report ([#1057](https://github.com/n0-computer/iroh/issues/1057)) ([fcc74b8](https://github.com/n0-computer/iroh/commit/fcc74b80f6daf7185292e87e086b5e899f5d0d1a))
* **netcheck:** Do not read from main Conn sockets ([#1017](https://github.com/n0-computer/iroh/issues/1017)) ([5e997a4](https://github.com/n0-computer/iroh/commit/5e997a4a64cb4686dd3674315d6e2a1ca19619be))
* **netcheck:** If no STUN sockets supplied allow bind to fail ([#1041](https://github.com/n0-computer/iroh/issues/1041)) ([726cace](https://github.com/n0-computer/iroh/commit/726cace060f0a3a8b042a8605801eacaa9599d48))
* **netcheck:** Integrate https and icmp probes in probeplan ([#1220](https://github.com/n0-computer/iroh/issues/1220)) ([a0ae228](https://github.com/n0-computer/iroh/commit/a0ae22851453ea9e277adba8d52fe55f90edcef3))
* **netcheck:** Make ICMP ping optional ([#1137](https://github.com/n0-computer/iroh/issues/1137)) ([ac6bb1a](https://github.com/n0-computer/iroh/commit/ac6bb1a43571fd335f37631f7320d200495b23b1))
* **netcheck:** reduce locking and improved task tracking ([5a733ff](https://github.com/n0-computer/iroh/commit/5a733ff63400a40bd155c4ac710d5057e0422069))
* **netcheck:** Stable derp-region sorting ([#1250](https://github.com/n0-computer/iroh/issues/1250)) ([899efd2](https://github.com/n0-computer/iroh/commit/899efd29362e539722869b2013b2058704098547))
* netsim branch CI default ([#1205](https://github.com/n0-computer/iroh/issues/1205)) ([a8435eb](https://github.com/n0-computer/iroh/commit/a8435ebb594b93282e90959e702f11baabfd44c5))
* online stun test ([#1065](https://github.com/n0-computer/iroh/issues/1065)) ([bec1bbe](https://github.com/n0-computer/iroh/commit/bec1bbeadab93195094a3ee5cd22c7e261db2459))
* process incoming IP packets in a seperate task ([#1020](https://github.com/n0-computer/iroh/issues/1020)) ([96b882a](https://github.com/n0-computer/iroh/commit/96b882a80a129810682c2885f513dbcec81b3189)), closes [#1021](https://github.com/n0-computer/iroh/issues/1021)
* release netsim should ignore some tests ([#1096](https://github.com/n0-computer/iroh/issues/1096)) ([9b981c4](https://github.com/n0-computer/iroh/commit/9b981c4c4b75d76cd7fd4b9ac83d2d9d1e9edd1a))
* remove build-data dependency  ([26e9937](https://github.com/n0-computer/iroh/commit/26e99375a7b058adb4a682b7014a3c2407b590ae)), closes [#1035](https://github.com/n0-computer/iroh/issues/1035)
* remove derp route on peergone ([cefc8ba](https://github.com/n0-computer/iroh/commit/cefc8ba47cffe6565b963ed8e7efa5e150a7b188))
* send early ping if needed ([d0755c7](https://github.com/n0-computer/iroh/commit/d0755c7fc0595216833d0d7a13924b0e3fe034d8))
* show all listening addrs ([b84ed59](https://github.com/n0-computer/iroh/commit/b84ed59ad39c807b30a138803dfd1891705694ee))
* store udpstate ([f0bde56](https://github.com/n0-computer/iroh/commit/f0bde56c8d72b9d6e7dbe280632ab903ebe83133))
* switch to derive_more_preview  ([a0392c6](https://github.com/n0-computer/iroh/commit/a0392c6b9e518a707b341f67e69065eaf26404cc)), closes [#1035](https://github.com/n0-computer/iroh/issues/1035)
* update bao-tree dependency to get rid of ouroboros in dependency tree ([#1104](https://github.com/n0-computer/iroh/issues/1104)) ([7840e1c](https://github.com/n0-computer/iroh/commit/7840e1ceceb8f787455fd4804d54248145fb9a7a))
* update Cargo.lock after rebase ([56fd099](https://github.com/n0-computer/iroh/commit/56fd099573f31075afd41c6613aa4342217f38ed))
* update integration tests ([#1082](https://github.com/n0-computer/iroh/issues/1082)) ([36cd904](https://github.com/n0-computer/iroh/commit/36cd904c1eafaac5bf75d48eca57220a0f9bf441))
* use correct endpoint for derp connections ([07d919f](https://github.com/n0-computer/iroh/commit/07d919faf8a58e911af2ae2223a5e7d615fb5e3c))
* use listen_addresses instead of local_address ([#1044](https://github.com/n0-computer/iroh/issues/1044)) ([c4a1890](https://github.com/n0-computer/iroh/commit/c4a1890b5c2f905c0780d9dccf1bee70847f599d))
* use simulated time in timer tests  ([b80ef52](https://github.com/n0-computer/iroh/commit/b80ef5229cdb177bb8a7bc2e5f5cfcf82f34e1af))


### Features

* `hp::derp::http::server::Server`  & TLS in the derper! ([#1077](https://github.com/n0-computer/iroh/issues/1077)) ([6f40e14](https://github.com/n0-computer/iroh/commit/6f40e14e26b2313998db9f75f0bc979cc6abe47e))
* add api to list collections ([7b0a7c7](https://github.com/n0-computer/iroh/commit/7b0a7c7b7ef9aab4b12970d91e615c74eeb792be))
* add configuration for derp regions ([96903e7](https://github.com/n0-computer/iroh/commit/96903e776e03c7f72155db3c2e105f33389cb06f))
* Add iroh doctor utility ([#986](https://github.com/n0-computer/iroh/issues/986)) ([4fc70f5](https://github.com/n0-computer/iroh/commit/4fc70f5915ac4d3e3d3a2dc0b8a869e8428637d4)), closes [#1008](https://github.com/n0-computer/iroh/issues/1008)
* add MagicEndpoint to iroh-net  ([4597cb3](https://github.com/n0-computer/iroh/commit/4597cb36e0be5ffcb5ae21a42e4a37648d455aad))
* add metrics to the derp server ([#1260](https://github.com/n0-computer/iroh/issues/1260)) ([d1b4e18](https://github.com/n0-computer/iroh/commit/d1b4e183b7fd8af8a4566ede92021aa34bdbac67))
* allow node to accept different ALPNs ([34e02d0](https://github.com/n0-computer/iroh/commit/34e02d02baa9100bb13b58fadb76aa06856541be))
* begin impl Server side of derp, starting with the server side of the client connection ([#826](https://github.com/n0-computer/iroh/issues/826)) ([94590ae](https://github.com/n0-computer/iroh/commit/94590ae0d1b548e055c8c7b9f40db04a52753947))
* **ci:** allow running netsim from another branch ([#1186](https://github.com/n0-computer/iroh/issues/1186)) ([0f77e4e](https://github.com/n0-computer/iroh/commit/0f77e4e3e88025078433b7946035c68fb99395a3))
* **ci:** record dump uploads ([#1101](https://github.com/n0-computer/iroh/issues/1101)) ([e289465](https://github.com/n0-computer/iroh/commit/e2894653506ed4cef2bcd7fd29a010b80c599448))
* **conn:** improve shutdown of IO loop ([dbe0228](https://github.com/n0-computer/iroh/commit/dbe02287707f53454c815f829b5b1ace7626d779))
* derp mesh network & derper cli & config cleanup ([#1130](https://github.com/n0-computer/iroh/issues/1130)) ([3dca612](https://github.com/n0-computer/iroh/commit/3dca6125064044907bc7da9dc19fe5a26e12567a))
* disable bailing out when temp dir is missing ([#1251](https://github.com/n0-computer/iroh/issues/1251)) ([eae79e8](https://github.com/n0-computer/iroh/commit/eae79e8e7a672571dbffc6caec0c1fd5359120fe))
* **docs:** Check rustdoc more strictly ([#1185](https://github.com/n0-computer/iroh/issues/1185)) ([6a58800](https://github.com/n0-computer/iroh/commit/6a5880004931b492c024a1feade2878f3ce5db41))
* impl From<Url> for DerpMap ([01641a7](https://github.com/n0-computer/iroh/commit/01641a7c3bf869c71c1949eeadfc7acd97c25e68))
* implement ICMP pings ([6c19faa](https://github.com/n0-computer/iroh/commit/6c19faae7f88accf8a2225b825339e6cc63cbe75))
* integration metrics and viz dump ([#1089](https://github.com/n0-computer/iroh/issues/1089)) ([2f65bc1](https://github.com/n0-computer/iroh/commit/2f65bc1e02798af7664d515a8aaf88e8c774ed4e))
* **iroh-net:** add more details to tracked endpoints ([dfd946e](https://github.com/n0-computer/iroh/commit/dfd946ed427d5135bf2b7df2141ad7a607b05df1))
* **iroh-net:** implement `HomeRouter` detection ([b14049e](https://github.com/n0-computer/iroh/commit/b14049ec0f9f36a540a9aa6fbd315272179d683a))
* **iroh-net:** PCP probe  ([659a54a](https://github.com/n0-computer/iroh/commit/659a54aa7571cff14592a81fffc011f683a8c954)), closes [#910](https://github.com/n0-computer/iroh/issues/910)
* **iroh-net:** Upnp port mapping ([#1117](https://github.com/n0-computer/iroh/issues/1117)) ([701e9b7](https://github.com/n0-computer/iroh/commit/701e9b7c6ff57037cd3bb88a9f7e037f5ddf6b87))
* **iroh:** pass a callback to subscribe ([#1219](https://github.com/n0-computer/iroh/issues/1219)) ([c325603](https://github.com/n0-computer/iroh/commit/c325603cb317600e4ee87844fa7a73174a8d7911)), closes [#1139](https://github.com/n0-computer/iroh/issues/1139)
* **loging:** Improve logging output of provider and get ([#932](https://github.com/n0-computer/iroh/issues/932)) ([6ae709e](https://github.com/n0-computer/iroh/commit/6ae709e63a1c542c1e02640b0fa85cb0a92ebcd7))
* metrics collection ([#900](https://github.com/n0-computer/iroh/issues/900)) ([d4a01f7](https://github.com/n0-computer/iroh/commit/d4a01f7aa0de1a208abf7809d79ff0a8403dc143))
* prefer configured port to be used for ipv4 ([3a292e5](https://github.com/n0-computer/iroh/commit/3a292e555d0f035950f90c3df463abed93475ac3))
* print local endpoints on provide ([b3c22bd](https://github.com/n0-computer/iroh/commit/b3c22bd12ec3d18b3c75af316f29075e72e8fa4e))
* **provider:** add 'CollectionAdded' Provider event ([#1131](https://github.com/n0-computer/iroh/issues/1131)) ([8b6a5bc](https://github.com/n0-computer/iroh/commit/8b6a5bc43d3bd602ff38bc8810ee72af5b5ac8de))
* reduce dependency bloat for derper ([07d7205](https://github.com/n0-computer/iroh/commit/07d72059404c169c17438a570cb5e3301f1c3351))
* remove AuthToken ([96d9378](https://github.com/n0-computer/iroh/commit/96d93787d8905a527cee374cf1d3ccc78504e309))
* specify a DERP region for the peer you are trying to connect to ([#1222](https://github.com/n0-computer/iroh/issues/1222)) ([456f963](https://github.com/n0-computer/iroh/commit/456f96305954a23299d02ed65b8838ba168232e1))
* unify MSRV to 1.66 ([090f6d8](https://github.com/n0-computer/iroh/commit/090f6d8c2a9939913881ddce6683bfc2d6a0a771))

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

