# Changelog

All notable changes to iroh will be documented in this file.

## [0.93.2](https://github.com/n0-computer/iroh/compare/v0.93.1..0.93.2) - 2025-10-13

### 🐛 Bug Fixes

- *(iroh)* Ensure initial addresses are published via discovery ([#3525](https://github.com/n0-computer/iroh/issues/3525)) - ([ca85faa](https://github.com/n0-computer/iroh/commit/ca85faac23d8509030a956000e56ae25f5610fcd))

## [0.93.1](https://github.com/n0-computer/iroh/compare/v0.93.0..v0.93.1) - 2025-10-09

### 📚 Documentation

- Fix docs.rs docs generation ([#3514](https://github.com/n0-computer/iroh/issues/3514)) - ([5f54493](https://github.com/n0-computer/iroh/commit/5f54493cc90fc12209c2ea942bb2594929827f82))

### ⚙️ Miscellaneous Tasks

- Release - ([8677fd8](https://github.com/n0-computer/iroh/commit/8677fd8e899726bce46ef44f3216fe96770198f2))

## [0.93.0](https://github.com/n0-computer/iroh/compare/v0.92.0..v0.93.0) - 2025-10-09

### ⛰️  Features

- *(iroh)* [**breaking**] Add `MdnsDiscoveryBuilder::service_name` method ([#3482](https://github.com/n0-computer/iroh/issues/3482)) - ([9a88cc5](https://github.com/n0-computer/iroh/commit/9a88cc5072cd2395a0e257fb7458a10ee354fb8c))
- *(iroh)* [**breaking**] Introduce `online` method ([#3467](https://github.com/n0-computer/iroh/issues/3467)) - ([d815cae](https://github.com/n0-computer/iroh/commit/d815cae72bcd59a6b420c4ba3bab9e28db2a7552))
- *(iroh)* [**breaking**] Make direct_addresses always be initialised ([#3505](https://github.com/n0-computer/iroh/issues/3505)) - ([33aca18](https://github.com/n0-computer/iroh/commit/33aca18b79679bff516fbcf93a3582ea22e4ffae))
- Make fmt_short return an impl Display so we can avoid an allocation. ([#3460](https://github.com/n0-computer/iroh/issues/3460)) - ([5285cc0](https://github.com/n0-computer/iroh/commit/5285cc07dff44af0330fea1aa391b0e44114c805))
- Upgrade redb to v3 compatible format ([#3483](https://github.com/n0-computer/iroh/issues/3483)) - ([2b36b77](https://github.com/n0-computer/iroh/commit/2b36b777fbadb2e5cee82bd2fccae12639383afa))
- Add a DNS resolver trait ([#3473](https://github.com/n0-computer/iroh/issues/3473)) - ([7bd657e](https://github.com/n0-computer/iroh/commit/7bd657e2a3d8bb58d05f2cd4e5d202753b8f683a))
- Add a builder for DnsResolver ([#3475](https://github.com/n0-computer/iroh/issues/3475)) - ([1fb68ef](https://github.com/n0-computer/iroh/commit/1fb68efa3f03276e0466c04f321c276e0fd285f7))
- Upgrade to rand@0.9 ([#3465](https://github.com/n0-computer/iroh/issues/3465)) - ([78649a3](https://github.com/n0-computer/iroh/commit/78649a3650791e1232512f0ea9f8f866043ce299))
- Congestion metrics ([#3491](https://github.com/n0-computer/iroh/issues/3491)) - ([b6c60d3](https://github.com/n0-computer/iroh/commit/b6c60d39ca2234fbe5fa45812d6733a2ba96fad2))

### 🐛 Bug Fixes

- *(iroh)* Convert to canonical IP address in IpSender ([#3506](https://github.com/n0-computer/iroh/issues/3506)) - ([44c3c27](https://github.com/n0-computer/iroh/commit/44c3c27cc5b86dd3bca07f3deffc6adba2b6de00))
- *(iroh)* Updated relays, and transfer example fixes ([#3510](https://github.com/n0-computer/iroh/issues/3510)) - ([da311a6](https://github.com/n0-computer/iroh/commit/da311a6a480a4a75cb3e4752048efb6d990972f6))
- *(relay)* Respect enable_relay flag ([#3481](https://github.com/n0-computer/iroh/issues/3481)) - ([427fcad](https://github.com/n0-computer/iroh/commit/427fcadd56070cfcedcf2332c2a12d337aad60e4))
- Force reqwest to always use rustls backend ([#3486](https://github.com/n0-computer/iroh/issues/3486)) - ([60d5310](https://github.com/n0-computer/iroh/commit/60d5310dfe42179f6b3a20e38da4e7144008e541))
- `impl<T: Discovery> Discovery for Arc<T>` ([#3495](https://github.com/n0-computer/iroh/issues/3495)) - ([f5381bc](https://github.com/n0-computer/iroh/commit/f5381bcfc6c0ec59bb20812e4372d03e7d4d9341))
- 0rtt flakes ([#3496](https://github.com/n0-computer/iroh/issues/3496)) - ([9e61af5](https://github.com/n0-computer/iroh/commit/9e61af52a9a7960dc00d89137d0649fedfb5044d))

### 🚜 Refactor

- *(iroh)* [**breaking**] Remove Endpoint::add_node_addr ([#3485](https://github.com/n0-computer/iroh/issues/3485)) - ([0ffadef](https://github.com/n0-computer/iroh/commit/0ffadef09a83ae0a5c98b90654980c9ab5333378))
- Rename last two `local_endpoints` usages to `direct_addresses` ([#3472](https://github.com/n0-computer/iroh/issues/3472)) - ([9c8540f](https://github.com/n0-computer/iroh/commit/9c8540fad98c3bde4cb9398a2bb82febab5c96a7))
- [**breaking**] Switch to iroh headers for captive portal checks ([#3488](https://github.com/n0-computer/iroh/issues/3488)) - ([d6f33f9](https://github.com/n0-computer/iroh/commit/d6f33f9e808aee8f4f3edbf82d2782ddee2de833))
- [**breaking**] Move examples deps to non-wasm dev deps ([#3509](https://github.com/n0-computer/iroh/issues/3509)) - ([81e340f](https://github.com/n0-computer/iroh/commit/81e340f7d6a24d8b97c684066faae0ec783ba058))

### 📚 Documentation

- *(iroh)* Add screening-connection example ([#3360](https://github.com/n0-computer/iroh/issues/3360)) - ([797fae6](https://github.com/n0-computer/iroh/commit/797fae6e8601d95a96254aeb3b4a2610a7ff3f38))

### ⚙️ Miscellaneous Tasks

- Bump some spans up to warn, to ensure they are logged ([#3466](https://github.com/n0-computer/iroh/issues/3466)) - ([2e42085](https://github.com/n0-computer/iroh/commit/2e4208579a33f4ed9c61573728e3a486582b0c41))
- Enable dependabot for crates and docker ([#3497](https://github.com/n0-computer/iroh/issues/3497)) - ([968a70b](https://github.com/n0-computer/iroh/commit/968a70bc2f7e3bf608647793acbfa80e6b960658))
- Release - ([7a8b97c](https://github.com/n0-computer/iroh/commit/7a8b97cbe5748ae7deed798d3b4dc7aae9dd4bac))

## [0.92.0](https://github.com/n0-computer/iroh/compare/v0.91.2..v0.92.0) - 2025-09-18

### ⛰️  Features

- *(iroh)* [**breaking**] Add passive mode for mdns discovery ([#3401](https://github.com/n0-computer/iroh/issues/3401)) ([#3403](https://github.com/n0-computer/iroh/issues/3403)) - ([c5a623c](https://github.com/n0-computer/iroh/commit/c5a623c102490a92df0f9ece73f0b0c94ed68b2d))
- *(iroh)* [**breaking**] Emit mDNS expiry events ([#3409](https://github.com/n0-computer/iroh/issues/3409)) - ([150b841](https://github.com/n0-computer/iroh/commit/150b8411435c5f49c5242ae3018d7be15f263ba6))
- *(iroh-base)* Impl Deref for PublicKey ([#3438](https://github.com/n0-computer/iroh/issues/3438)) - ([fa1e946](https://github.com/n0-computer/iroh/commit/fa1e946c528d31ff305c675401e82747367ac5bd))
- Allow configuring the max number of TLS tickets ([#3442](https://github.com/n0-computer/iroh/issues/3442)) - ([d6f4fa9](https://github.com/n0-computer/iroh/commit/d6f4fa98ab60512830cb533d6f6f63dd80093ef8))

### 🐛 Bug Fixes

- *(iroh)* Add jitter to dns retry calls ([#3447](https://github.com/n0-computer/iroh/issues/3447)) - ([f3da758](https://github.com/n0-computer/iroh/commit/f3da7586b6d1c9a625ff3923ddff7c7ebd843ef1))

### 🚜 Refactor

- *(iroh)* Re-batch datagrams inside `RelayTransport` instead of the `ActiveRelayActor` ([#3421](https://github.com/n0-computer/iroh/issues/3421)) - ([b791123](https://github.com/n0-computer/iroh/commit/b791123fc6657167b02aa37e489321f3abf35ef9))

### 📚 Documentation

- *(iroh-relay)* Remove incorrect help text about default config file creation ([#3258](https://github.com/n0-computer/iroh/issues/3258)) ([#3446](https://github.com/n0-computer/iroh/issues/3446)) - ([4583b12](https://github.com/n0-computer/iroh/commit/4583b1280b8f5ab9d264940102382956ddbbb1a8))

### ⚙️ Miscellaneous Tasks

- *(github)* Update issue template ([#3450](https://github.com/n0-computer/iroh/issues/3450)) - ([5e185bd](https://github.com/n0-computer/iroh/commit/5e185bdd53086f2ee916fecfedf1ce7e9ccf77eb))
- Update some dependencies ([#3453](https://github.com/n0-computer/iroh/issues/3453)) - ([048001d](https://github.com/n0-computer/iroh/commit/048001d0362a6465101d66654a2e797e74f782ca))
- Make net reports serde ([#3454](https://github.com/n0-computer/iroh/issues/3454)) - ([e8eb1dd](https://github.com/n0-computer/iroh/commit/e8eb1dd9d9008874b0ad48c3d05f5ee8cb8ec2e3))
- Add `test-utils` cfg for `insecure_cert` call in the transfer example ([#3458](https://github.com/n0-computer/iroh/issues/3458)) - ([c81fe21](https://github.com/n0-computer/iroh/commit/c81fe21538b976d7bb3f900cfb0c452d55c77631))
- Release - ([b7cd352](https://github.com/n0-computer/iroh/commit/b7cd35200113a7727de2ece40d062c4565eb1c61))

### Cargo

- Add aarch64-linux-gnu-gcc linker ([#3441](https://github.com/n0-computer/iroh/issues/3441)) - ([fb37550](https://github.com/n0-computer/iroh/commit/fb37550c859cc87bb03256fbe1b3071b9c21b608))

## [0.91.2](https://github.com/n0-computer/iroh/compare/v0.91.1..v0.91.2) - 2025-08-18

### ⛰️  Features

- *(iroh-base)* Derive Hash for NodeAddr ([#3428](https://github.com/n0-computer/iroh/issues/3428)) - ([2308388](https://github.com/n0-computer/iroh/commit/2308388da774ea0c796e68ef920c586230704dbe))

### 🐛 Bug Fixes

- *(iroh)* Fix very slow initial connection establishment ([#3434](https://github.com/n0-computer/iroh/issues/3434)) - ([59d1432](https://github.com/n0-computer/iroh/commit/59d1432a10e6c6414f355947aecd0d8927b72b6c))
- *(iroh-relay)* Don't double-count connection accepts ([#3436](https://github.com/n0-computer/iroh/issues/3436)) - ([8c558a1](https://github.com/n0-computer/iroh/commit/8c558a1c2e6d53ca0a20b0c2a4d78efe3beab45a))

### ⚙️ Miscellaneous Tasks

- Release - ([d9dbbe6](https://github.com/n0-computer/iroh/commit/d9dbbe6aaff3f06d21de1951110b4741af8eda3c))

## [0.91.1](https://github.com/n0-computer/iroh/compare/v0.91.0..v0.91.1) - 2025-08-04

### 🐛 Bug Fixes

- *(iroh)* Always update the best addr after changes ([#3422](https://github.com/n0-computer/iroh/issues/3422)) - ([36842d5](https://github.com/n0-computer/iroh/commit/36842d5c601c66fd1c06a17b4195170020d0c05d))
- *(iroh)* Use valid available IPv6 address, ignoring `have_ipv6` ([#3419](https://github.com/n0-computer/iroh/issues/3419)) - ([fe7240d](https://github.com/n0-computer/iroh/commit/fe7240dd971b791c39354cd9621b7d23edaf5b7b))

### 📚 Documentation

- Grammar nitpick ([#3383](https://github.com/n0-computer/iroh/issues/3383)) - ([026dffc](https://github.com/n0-computer/iroh/commit/026dffc6cc5229411599188bd7d6e24df7dae9d3))

### ⚙️ Miscellaneous Tasks

- Release - ([e30c788](https://github.com/n0-computer/iroh/commit/e30c788f968265bd9d181e5ca92d02eb61ef3d0d))

## [0.91.0](https://github.com/n0-computer/iroh/compare/v0.90.0..v0.91.0) - 2025-07-30

### ⛰️  Features

- *(iroh)* Update to new relay servers ([#3412](https://github.com/n0-computer/iroh/issues/3412)) - ([f3e4307](https://github.com/n0-computer/iroh/commit/f3e430718a3316dffe191498fd3d0adddb92f2b4))
- *(iroh,iroh-relay)* [**breaking**] Use stride instead of custom split protocol, send ECN bits ([#3389](https://github.com/n0-computer/iroh/issues/3389)) - ([f3fd988](https://github.com/n0-computer/iroh/commit/f3fd988adfcab26023d7987f2fa6bf60975beb3c))
- *(iroh-relay)* [**breaking**] Implement new handshake protocol, refactor frame types ([#3331](https://github.com/n0-computer/iroh/issues/3331)) - ([3a1592a](https://github.com/n0-computer/iroh/commit/3a1592ac752bff2b71b85a7be8afb71edc92d6be))
- [**breaking**] Update to edition 2024 and update deps to latest ([#3386](https://github.com/n0-computer/iroh/issues/3386)) - ([e2cfde7](https://github.com/n0-computer/iroh/commit/e2cfde779cf3d04b15aafe5d193c171454463220))
- Add the timeout duration to the relay dial error ([#3406](https://github.com/n0-computer/iroh/issues/3406)) - ([db36c65](https://github.com/n0-computer/iroh/commit/db36c659a9d8725e44ef6751b85d2f604ec2f379))

### 🐛 Bug Fixes

- *(iroh)* Use std Mutex instead of tokio Mutex ([#3374](https://github.com/n0-computer/iroh/issues/3374)) - ([eb383a6](https://github.com/n0-computer/iroh/commit/eb383a61db4ca3645a445fcf0424fd516cd32c3f))
- *(iroh)* Track path validity for all paths and replace `BestAddr` with `PathValidity` ([#3400](https://github.com/n0-computer/iroh/issues/3400)) - ([a3187ca](https://github.com/n0-computer/iroh/commit/a3187caee475e83c2f6ad8cb57bbfd3825a7c917))
- *(iroh)* Re-batch received relay datagram batches in case they exceed `max_receive_segments` ([#3414](https://github.com/n0-computer/iroh/issues/3414)) - ([a8485ad](https://github.com/n0-computer/iroh/commit/a8485ad101c30babda1cb76343d5d242447bf049))
- *(iroh)* Only clear `last_call_me_maybe` when the best addr became invalid ([#3415](https://github.com/n0-computer/iroh/issues/3415)) - ([bcb60d4](https://github.com/n0-computer/iroh/commit/bcb60d42fecd79fcc5e4d064f410367a3f7aa0b2))
- *(iroh-relay)* Fix proptests, make `Datagrams::segment_size` be an `Option<NonZeroU16>` ([#3404](https://github.com/n0-computer/iroh/issues/3404)) - ([75fd57c](https://github.com/n0-computer/iroh/commit/75fd57c8e0fb2e47ed424f0926d3bb816cc4018b))
- Fix dht publishing at startup ([#3397](https://github.com/n0-computer/iroh/issues/3397)) - ([dd1d692](https://github.com/n0-computer/iroh/commit/dd1d692661b3ba6ee133b7d80500837444482385))
- Better tracing spans ([#3399](https://github.com/n0-computer/iroh/issues/3399)) - ([f8f7f95](https://github.com/n0-computer/iroh/commit/f8f7f959cb6f5e6273ab0c57fe23a7c6b326fa0a))
- Add missing use<> for wasm_browser ([#3411](https://github.com/n0-computer/iroh/issues/3411)) - ([91c2e63](https://github.com/n0-computer/iroh/commit/91c2e636c6d248857418ad918df63d7a667735ee))
- Wait for at least one ipv6 and ipv4 qad report ([#3413](https://github.com/n0-computer/iroh/issues/3413)) - ([b755db4](https://github.com/n0-computer/iroh/commit/b755db460d77c3b9b8eb2c6e25f1841a7236a89d))

### 🚜 Refactor

- *(iroh,iroh-relay)* Remove legacy relay path, make websocket connections default ([#3384](https://github.com/n0-computer/iroh/issues/3384)) - ([0776687](https://github.com/n0-computer/iroh/commit/0776687e982050c7a7c46e8d430b350a24481718))

### 📚 Documentation

- *(iroh)* Use `iroh::Watcher` reexport in docs ([#3375](https://github.com/n0-computer/iroh/issues/3375)) - ([9c023bf](https://github.com/n0-computer/iroh/commit/9c023bf4d7d1c3c10a9cc3b10df7e1a22c6ab7a4))

### 🧪 Testing

- *(iroh)* Make `endpoint_relay_connect_loop` not flaky ([#3402](https://github.com/n0-computer/iroh/issues/3402)) - ([8426241](https://github.com/n0-computer/iroh/commit/84262418d7597d0435b9e5f437dac119598880f2))

### ⚙️ Miscellaneous Tasks

- *(iroh)* Update `n0-watcher` ([#3405](https://github.com/n0-computer/iroh/issues/3405)) - ([2ce6a73](https://github.com/n0-computer/iroh/commit/2ce6a73412ec8a0343696a11fa531601bc5a76a1))
- *(iroh)* Update portmapper ([#3410](https://github.com/n0-computer/iroh/issues/3410)) - ([ee08341](https://github.com/n0-computer/iroh/commit/ee08341b3e621f3ff311f7d77cc6d73e49c70bd7))
- Release - ([36ddb5b](https://github.com/n0-computer/iroh/commit/36ddb5bfc5805085efab667630721ea755d96654))

## [0.90.0](https://github.com/n0-computer/iroh/compare/v0.35.0..v0.90.0) - 2025-06-26

### ⛰️  Features

- *(iroh)* Allow protocols to gracefully shutdown connections ([#3319](https://github.com/n0-computer/iroh/issues/3319)) - ([da571c1](https://github.com/n0-computer/iroh/commit/da571c19591fee13504e5a226b5cc0dc4dc1435e))
- *(iroh)* [**breaking**] Make ProtocolHandler use async functions ([#3320](https://github.com/n0-computer/iroh/issues/3320)) - ([e36ac77](https://github.com/n0-computer/iroh/commit/e36ac776fec2d5aabec8300e13b30b6f81ed4721))
- *(iroh)* [**breaking**] Remove deprecated x509 libp2p TLS authentication ([#3330](https://github.com/n0-computer/iroh/issues/3330)) - ([136b855](https://github.com/n0-computer/iroh/commit/136b855087900fd65638833aae1513267955fcf6))
- *(iroh)* [**breaking**] Introduce transport abstraction ([#3279](https://github.com/n0-computer/iroh/issues/3279)) - ([d915bfd](https://github.com/n0-computer/iroh/commit/d915bfdff45235f90e06e7a8502bebebd6621857))
- *(iroh)* Re-export `n0_watcher::Watcher` trait ([#3356](https://github.com/n0-computer/iroh/issues/3356)) - ([bc6e9e3](https://github.com/n0-computer/iroh/commit/bc6e9e3077a62f61f25efcd0bc93540006222e18))
- *(iroh)* [**breaking**] Expose `DynProtocolHandler` ([#3366](https://github.com/n0-computer/iroh/issues/3366)) - ([056df1d](https://github.com/n0-computer/iroh/commit/056df1de3ccd01b918d95c0140a36c13b42758dd))
- Make `Endpoint::node_addr` watchable and add `trait Watcher` & combinators ([#3045](https://github.com/n0-computer/iroh/issues/3045)) - ([7911255](https://github.com/n0-computer/iroh/commit/79112552b71301db4e17795862b5e06865644a93))
- [**breaking**] Concrete errors ([#3161](https://github.com/n0-computer/iroh/issues/3161)) - ([75eae87](https://github.com/n0-computer/iroh/commit/75eae87c5b14b7f919f1d3e3a083e97547e11a6e))
- Add methods to create variants of the `iroh-base::ticket::ParseError` enum. ([#3362](https://github.com/n0-computer/iroh/issues/3362)) - ([1859de3](https://github.com/n0-computer/iroh/commit/1859de331e9df01eecea2ede1143edb19005c9a6))

### 🐛 Bug Fixes

- *(iroh)* Correctly hook up ipv6 addr lookups ([#3342](https://github.com/n0-computer/iroh/issues/3342)) - ([b8b5bc3](https://github.com/n0-computer/iroh/commit/b8b5bc36b63e43d06ba494135b1ad549c619f202))
- *(iroh-base)* [**breaking**] Remove display impl for SecretKey ([#3364](https://github.com/n0-computer/iroh/issues/3364)) - ([19323e6](https://github.com/n0-computer/iroh/commit/19323e6f5a892f7c9648b934be0e993b6e9c574c))
- Remove unneeded lifetime bound for watcher in wasm ([#3354](https://github.com/n0-computer/iroh/issues/3354)) - ([84dd511](https://github.com/n0-computer/iroh/commit/84dd511c1057d5e68ee8c35cf5ca77df4fee86f6))

### 🚜 Refactor

- *(iroh)* [**breaking**] Simplify discovery errors ([#3340](https://github.com/n0-computer/iroh/issues/3340)) - ([fad99ab](https://github.com/n0-computer/iroh/commit/fad99ab551117ebea2f391605243ee864128ee1e))
- *(iroh)* [**breaking**] Rename ProtocolError to AcceptError ([#3339](https://github.com/n0-computer/iroh/issues/3339)) - ([d4de591](https://github.com/n0-computer/iroh/commit/d4de591cb54be888e587320e6fb705648036ab38))
- *(iroh)* [**breaking**] Rework net_report ([#3314](https://github.com/n0-computer/iroh/issues/3314)) - ([dcbebe9](https://github.com/n0-computer/iroh/commit/dcbebe93f90b2b6408496869fc61503297ba9b86))
- *(iroh)* [**breaking**] Add `IntoDiscovery` trait ([#3327](https://github.com/n0-computer/iroh/issues/3327)) - ([7f2cdd1](https://github.com/n0-computer/iroh/commit/7f2cdd17fd8a01ab4a7d1b48c6e82e5d7520233e))
- *(iroh-relay,iroh)* Slightly clean up staggered DNS errors ([#3337](https://github.com/n0-computer/iroh/issues/3337)) - ([444c76b](https://github.com/n0-computer/iroh/commit/444c76b54680b748684242a34f5a880212509ab0))

### 🧪 Testing

- *(iroh-relay)* Add 300ms timeout to the `test_qad_client_closes_unresponsive_fast` test ([#3332](https://github.com/n0-computer/iroh/issues/3332)) - ([b647af9](https://github.com/n0-computer/iroh/commit/b647af998c8705abaf3183fd7682291350c47225))

### ⚙️ Miscellaneous Tasks

- *(*)* Upgrade to the latest `iroh-metrics`, `portmapper`, and `swarm-discovery` ([#3369](https://github.com/n0-computer/iroh/issues/3369)) - ([79bc05b](https://github.com/n0-computer/iroh/commit/79bc05bdfcb8829adbc8c9ea55c72861556ff846))
- *(iroh)* [**breaking**] Change default relays to new "canary" relays ([#3368](https://github.com/n0-computer/iroh/issues/3368)) - ([6e72f20](https://github.com/n0-computer/iroh/commit/6e72f201db1a6b5c03818a2c193d5dda4d9d03cc))
- *(iroh-relay)* Make QAD test non-flaky by using tokio's paused time ([#3341](https://github.com/n0-computer/iroh/issues/3341)) - ([2b6c258](https://github.com/n0-computer/iroh/commit/2b6c2589b08a516086d4e9aa807d98983085b719))
- *(iroh-relay)* Fix cargo check warning ([#3346](https://github.com/n0-computer/iroh/issues/3346)) - ([c7cf08d](https://github.com/n0-computer/iroh/commit/c7cf08da74ce547c87601a05b309d5e3110d8161))
- Make clippy 1.87 happy ([#3318](https://github.com/n0-computer/iroh/issues/3318)) - ([02acba9](https://github.com/n0-computer/iroh/commit/02acba96985808d6243036965a37021180bf1515))
- Update project_sync workflow ([#3325](https://github.com/n0-computer/iroh/issues/3325)) - ([518400b](https://github.com/n0-computer/iroh/commit/518400b0d7fa1851b49da3598995ff9f0aeece3b))
- Release - ([ac2a3f2](https://github.com/n0-computer/iroh/commit/ac2a3f29cec9a933965cfb3c4ea8f543ccf7a706))

### Bugfix

- Use staging relay in n0_dns_pkarr_relay ([#3335](https://github.com/n0-computer/iroh/issues/3335)) - ([aebbc72](https://github.com/n0-computer/iroh/commit/aebbc727ffbb72d738f8c76b489e034fdd6a5cc8))

### Example

- Example for 0rtt that can also serve as a benchmark ([#3323](https://github.com/n0-computer/iroh/issues/3323)) - ([b0b11f0](https://github.com/n0-computer/iroh/commit/b0b11f0a52951215bb4e39404a79d3ddabfa60c3))

### Iroh

- *(deps)* Dedupe lru and webpki ([#3306](https://github.com/n0-computer/iroh/issues/3306)) - ([ba07bcc](https://github.com/n0-computer/iroh/commit/ba07bcc2b6180ef55bc41e8e277fb0cf000fb434))

## [0.35.0](https://github.com/n0-computer/iroh/compare/v0.34.1..v0.35.0) - 2025-05-12

### ⛰️  Features

- *(iroh)* Allow connecting with "fallback" ALPNs ([#3282](https://github.com/n0-computer/iroh/issues/3282)) - ([839bfaa](https://github.com/n0-computer/iroh/commit/839bfaa35d6ba8635192ca1ab44c9604be7d3941))
- *(iroh)* Add `net-report` method on the `iroh::Endpoint` that returns a `Watchable<Report>` ([#3293](https://github.com/n0-computer/iroh/issues/3293)) - ([3448b4b](https://github.com/n0-computer/iroh/commit/3448b4bce4d32ade8ad7129030a0b2474aaf3409))
- *(iroh,iroh-relay)* Enable proxying and test-utils support for websockets, allow configuring websockets in `endpoint::Builder` ([#3217](https://github.com/n0-computer/iroh/issues/3217)) - ([8a24a95](https://github.com/n0-computer/iroh/commit/8a24a95691484f42707d899000721b7f1c79256e))
- *(iroh-relay)* [**breaking**] Adjust APIs to make it easier to create `RelayMap`s from lists of `RelayUrls` ([#3292](https://github.com/n0-computer/iroh/issues/3292)) - ([cd0a47a](https://github.com/n0-computer/iroh/commit/cd0a47ad53c9ba2cc08705597430ddefe39c519b))
- Update to axum@0.8 ([#3274](https://github.com/n0-computer/iroh/issues/3274)) - ([1d79f92](https://github.com/n0-computer/iroh/commit/1d79f9250f980f477415bcfec964096f2dc0e3e1))
- [**breaking**] Metrics refactor ([#3262](https://github.com/n0-computer/iroh/issues/3262)) - ([1957ca8](https://github.com/n0-computer/iroh/commit/1957ca8237ce6fa5adbe42ece15e0baad53cdc0c))
- Fix minimal crates selection ([#3255](https://github.com/n0-computer/iroh/issues/3255)) - ([a62a2bd](https://github.com/n0-computer/iroh/commit/a62a2bd25f5280a8d1512bcd261e666731de5d95))
- Improve transfer, publish, resolve examples ([#3296](https://github.com/n0-computer/iroh/issues/3296)) - ([30577d3](https://github.com/n0-computer/iroh/commit/30577d3094f7ea59a2ac53c78d7b63e807bd4d43))

### 🐛 Bug Fixes

- *(iroh)* [**breaking**] Update dependencies & fix 0-RTT with newer rustls by pulling the expected `NodeId` out of the `ServerName` in verifiers ([#3290](https://github.com/n0-computer/iroh/issues/3290)) - ([af882a6](https://github.com/n0-computer/iroh/commit/af882a66e52b1838b93c0c2a4ea000ee723d80a4))
- *(iroh-dns-server)* Backwards compatibility for packets stored with iroh-dns-server v0.34 or lower ([#3295](https://github.com/n0-computer/iroh/issues/3295)) - ([74b8baa](https://github.com/n0-computer/iroh/commit/74b8baa2a0ec11fd5ee621583fb3f4e9aa391b54))
- *(iroh-dns-server)* Fixes for packet expiry ([#3297](https://github.com/n0-computer/iroh/issues/3297)) - ([146f423](https://github.com/n0-computer/iroh/commit/146f423a6805ab0147703832ad98ee6c52797174))
- *(iroh-relay)* Don't stop relay client actor if queues become full ([#3294](https://github.com/n0-computer/iroh/issues/3294)) - ([f3c9af3](https://github.com/n0-computer/iroh/commit/f3c9af35542a7f2e00303090d1ca5273f86bc375))

### ⚙️ Miscellaneous Tasks

- *(iroh)* Add `echo-no-router.rs` example ([#3267](https://github.com/n0-computer/iroh/issues/3267)) - ([7e13aa3](https://github.com/n0-computer/iroh/commit/7e13aa3ea76204f7ee4d59be84ed454dff73766c))
- Update to mozilla-actions/sccache-action@v0.0.9 ([#3268](https://github.com/n0-computer/iroh/issues/3268)) - ([792e6c4](https://github.com/n0-computer/iroh/commit/792e6c4148a4a721189f16d453a365f7663e2439))
- Release - ([31895bf](https://github.com/n0-computer/iroh/commit/31895bf09ee58c2d7ae38d7f65698f3f983c12e9))

### Deps

- [**breaking**] Update pkarr to v3 ([#3186](https://github.com/n0-computer/iroh/issues/3186)) - ([7b4bce8](https://github.com/n0-computer/iroh/commit/7b4bce8c0f1364d1eb4f1ec22cd82527a79376ab))

## [0.34.1](https://github.com/n0-computer/iroh/compare/v0.34.0..v0.34.1) - 2025-04-07

### ⛰️  Features

- *(iroh)* Move `iroh-net-report` back into `iroh` ([#3251](https://github.com/n0-computer/iroh/issues/3251)) - ([d6bc83f](https://github.com/n0-computer/iroh/commit/d6bc83faa23666ecbc4c3a7506004ace9f95614f))
- *(iroh-relay)* Allow to authenticate nodes via a HTTP POST request ([#3246](https://github.com/n0-computer/iroh/issues/3246)) - ([592c3b5](https://github.com/n0-computer/iroh/commit/592c3b541d4bf9081ed364875d514950490dd88b))

### 🐛 Bug Fixes

- *(iroh)* Reduce log-level of unknown pong message ([#3242](https://github.com/n0-computer/iroh/issues/3242)) - ([cf3e650](https://github.com/n0-computer/iroh/commit/cf3e650694ba94224adfe0ee961d9f471a042650))
- *(iroh)* Reap ActiveRelayActor handles for idle relays ([#3249](https://github.com/n0-computer/iroh/issues/3249)) - ([528a32c](https://github.com/n0-computer/iroh/commit/528a32c215289e622367bb0cbdb2dee543d8e217))
- Backoff before retry if relay connection terminates ([#3254](https://github.com/n0-computer/iroh/issues/3254)) - ([bc6e98c](https://github.com/n0-computer/iroh/commit/bc6e98cae6f1893f4888eae613b7645e941365a6))

### ⚙️ Miscellaneous Tasks

- *(iroh)* Update from alpha to release 0.25 hickory ([#3256](https://github.com/n0-computer/iroh/issues/3256)) - ([26289ca](https://github.com/n0-computer/iroh/commit/26289ca230cf21f188f92638adecc43d9ca1bfd1))
- *(iroh)* Don't depend on unused `rustls-platform-verifier` dependency ([#3257](https://github.com/n0-computer/iroh/issues/3257)) - ([42b605e](https://github.com/n0-computer/iroh/commit/42b605e53d89c89faf0f63a86bf48d0039ea53b4))
- *(iroh-relay)* Fix README.md instuctions to enable `server` feature ([#3239](https://github.com/n0-computer/iroh/issues/3239)) - ([7588135](https://github.com/n0-computer/iroh/commit/7588135441b72f718ca4ed460d351441e89c4a8b))
- Release - ([b43e013](https://github.com/n0-computer/iroh/commit/b43e0130c7e708467e5b8d3441b6aa92d8044ab5))

### Deps

- Bump tokio to 1.44.2 ([#3259](https://github.com/n0-computer/iroh/issues/3259)) - ([e109e6d](https://github.com/n0-computer/iroh/commit/e109e6de2ab5ab9118dcabadfadd2744762a0672))

## [0.34.0](https://github.com/n0-computer/iroh/compare/v0.33.0..v0.34.0) - 2025-03-17

### ⛰️  Features

- *(iroh)* Enable `netwatch::netmon::Monitor` and the `metrics` feature in Wasm ([#3206](https://github.com/n0-computer/iroh/issues/3206)) - ([7acfe39](https://github.com/n0-computer/iroh/commit/7acfe395429edc5810efa5136fbd77e7ae9d4952))
- *(iroh)* [**breaking**] Allow for limiting incoming connections on the router ([#3157](https://github.com/n0-computer/iroh/issues/3157)) - ([3e16848](https://github.com/n0-computer/iroh/commit/3e168483b08d3e9705f616812b567634ed35cf9b))
- *(iroh)* [**breaking**] Switch TLS authentication to raw public keys ([#2937](https://github.com/n0-computer/iroh/issues/2937)) - ([d8c8c8e](https://github.com/n0-computer/iroh/commit/d8c8c8e393243a1858f84354b7e92443ed665146))
- [**breaking**] Add `DiscoveryItem::user_data` method and adjust `locally-discovered-nodes` example ([#3215](https://github.com/n0-computer/iroh/issues/3215)) - ([f6b5f5c](https://github.com/n0-computer/iroh/commit/f6b5f5cf0d8b6e75e2f87707b71855f32b12481f))

### 🐛 Bug Fixes

- *(iroh)* Don't cause re-stuns all the time in browsers ([#3234](https://github.com/n0-computer/iroh/issues/3234)) - ([ef3645e](https://github.com/n0-computer/iroh/commit/ef3645e8b7d5700e309de3cd13b745bbf352f151))
- *(iroh-base)* [**breaking**] Remove unused `getrandom` dependency ([#3202](https://github.com/n0-computer/iroh/issues/3202)) - ([0c7a122](https://github.com/n0-computer/iroh/commit/0c7a1227cf1b9f640145c059c7581f2c502e6691))
- *(iroh-relay)* Report round-trip-latency instead of single-trip for QAD ([#3230](https://github.com/n0-computer/iroh/issues/3230)) - ([00f8309](https://github.com/n0-computer/iroh/commit/00f8309b00158fdb7a4565d4cd85c404262cd19b))
- *(relay)* [**breaking**] Change default cert format from der to pem ([#3204](https://github.com/n0-computer/iroh/issues/3204)) - ([4930837](https://github.com/n0-computer/iroh/commit/493083765083c77fd74c7575236d8b7696b61754))
- Update project_sync ([#3213](https://github.com/n0-computer/iroh/issues/3213)) - ([aa7463b](https://github.com/n0-computer/iroh/commit/aa7463bcc025aae69b164c101e8d7d52c96184db))

### 🚜 Refactor

- *(iroh)* Factor out socket-related state & construction into `magicsock::SocketState` and `ActorSocketState` ([#3203](https://github.com/n0-computer/iroh/issues/3203)) - ([2a49265](https://github.com/n0-computer/iroh/commit/2a492652b3c322dfd05c5f43a90d368195d6d121))
- *(iroh, iroh-net-report)* [**breaking**] Make ports more private ([#3207](https://github.com/n0-computer/iroh/issues/3207)) - ([906250b](https://github.com/n0-computer/iroh/commit/906250bb28244ad62c23399c9b10494226610c5a))

### 📚 Documentation

- *(iroh)* Fix quicwg.org link ([#3235](https://github.com/n0-computer/iroh/issues/3235)) - ([f09c89e](https://github.com/n0-computer/iroh/commit/f09c89e8bda4a7d09a5335b9439bede5eec73d5d))

### ⚙️ Miscellaneous Tasks

- Switch from `backoff` to `backon` ([#3227](https://github.com/n0-computer/iroh/issues/3227)) - ([14795ab](https://github.com/n0-computer/iroh/commit/14795ab89747ec72868fad07f91424b8a408b45c))
- Release - ([82eb549](https://github.com/n0-computer/iroh/commit/82eb5492cc973ed8cd00aa3254761561a419908b))

## [0.33.0](https://github.com/n0-computer/iroh/compare/v0.32.1..v0.33.0) - 2025-02-24

### ⛰️  Features

- *(iroh)* Enable applications to establish 0-RTT connections ([#3163](https://github.com/n0-computer/iroh/issues/3163)) - ([f0abede](https://github.com/n0-computer/iroh/commit/f0abede7be34a850a420648b43ba92174d623eff))
- *(iroh)* Add subscription stream to watch all discovery results ([#3181](https://github.com/n0-computer/iroh/issues/3181)) - ([695f7c1](https://github.com/n0-computer/iroh/commit/695f7c15966366397a4c20c5149a8cfcce36da37))
- *(iroh)* Publish and resolve user-defined data in discovery ([#3176](https://github.com/n0-computer/iroh/issues/3176)) - ([ac78cf2](https://github.com/n0-computer/iroh/commit/ac78cf2c77a605ec17834d465cda7f1635514279))
- *(iroh)* Make `iroh` compile to `wasm32-unknown-unknown` ([#3189](https://github.com/n0-computer/iroh/issues/3189)) - ([247b891](https://github.com/n0-computer/iroh/commit/247b89191da6d2f46fb25859c9bf83edef44337d))
- *(iroh-net-report)* Support wasm32 building & running ([#3139](https://github.com/n0-computer/iroh/issues/3139)) - ([6f923a3](https://github.com/n0-computer/iroh/commit/6f923a34cd3bab2b7a996f0bc4c5b0dcac6399fc))
- *(iroh-relay)* Make `Endpoint::close` faster by aborting QAD connections faster ([#3182](https://github.com/n0-computer/iroh/issues/3182)) - ([f640e83](https://github.com/n0-computer/iroh/commit/f640e835494c36b7715a275fd154b86272235bcb))

### 🐛 Bug Fixes

- *(iroh)* Allow gracefully closing connections ([#3170](https://github.com/n0-computer/iroh/issues/3170)) - ([d9a5b8e](https://github.com/n0-computer/iroh/commit/d9a5b8e7f277204242af43fb658a384e54fdc942))
- *(iroh-relay)* Fix the number of active relay connections ([#3194](https://github.com/n0-computer/iroh/issues/3194)) - ([397d08d](https://github.com/n0-computer/iroh/commit/397d08d6d5ac64ba4c19792dc07da4dffdbd09d4))
- *(iroh-relay)* Bring back unique node counts ([#3197](https://github.com/n0-computer/iroh/issues/3197)) - ([892c767](https://github.com/n0-computer/iroh/commit/892c767970d8f2e0ff96e437f8c8a7695801ddf3))
- Update hickory resolver to 0.25.0-.alpha.5 ([#3178](https://github.com/n0-computer/iroh/issues/3178)) - ([a4fcaaa](https://github.com/n0-computer/iroh/commit/a4fcaaa1cb28f5017566a4858b32b14865c4a875))

### 🚜 Refactor

- *(iroh)* Store quic config, instead of recreating ([#3171](https://github.com/n0-computer/iroh/issues/3171)) - ([9eccb05](https://github.com/n0-computer/iroh/commit/9eccb0540a6759bfea0b1d2b263a1506b1e70fea))
- [**breaking**] Use a single DNS resolver ([#3167](https://github.com/n0-computer/iroh/issues/3167)) - ([c39b998](https://github.com/n0-computer/iroh/commit/c39b998309efc942edc6f26894ba5b46cf489156))
- [**breaking**] Streamline discovery and node info types ([#3175](https://github.com/n0-computer/iroh/issues/3175)) - ([3e3798f](https://github.com/n0-computer/iroh/commit/3e3798f7e95fe7442dfa319e7f0943cfa96b0080))

### 🧪 Testing

- *(iroh-net-report)* Do not ping hosts on the internet ([#3172](https://github.com/n0-computer/iroh/issues/3172)) - ([d43d474](https://github.com/n0-computer/iroh/commit/d43d47411a952087d50847f0fe61e0a14bceb30b))

### ⚙️ Miscellaneous Tasks

- Add additional todos in the "change checklist" ([#3180](https://github.com/n0-computer/iroh/issues/3180)) - ([31efead](https://github.com/n0-computer/iroh/commit/31efead8e8de8fc24af0594d80148d9281eee995))
- Release - ([d551ead](https://github.com/n0-computer/iroh/commit/d551ead06543b3e05b05db1d1c1fbaeacb57b5b8))

## [0.32.1](https://github.com/n0-computer/iroh/compare/v0.32.0..v0.32.1) - 2025-02-05

### 🐛 Bug Fixes

- *(iroh)* Ensure passing a crpyto provider to rustls clients ([#3169](https://github.com/n0-computer/iroh/issues/3169)) - ([34c10bc](https://github.com/n0-computer/iroh/commit/34c10bc5d86937c0b23e9c4c4e8acc1d0e6ff438))

### ⚙️ Miscellaneous Tasks

- Release - ([fc24a92](https://github.com/n0-computer/iroh/commit/fc24a92eb411f1cdd11011833eab672ae23b946f))

## [0.32.0](https://github.com/n0-computer/iroh/compare/v0.31.0..v0.32.0) - 2025-02-04

### ⛰️  Features

- *(iroh)* Allow customising the TransportConfig for connections ([#3111](https://github.com/n0-computer/iroh/issues/3111)) - ([2b92db4](https://github.com/n0-computer/iroh/commit/2b92db44b5f740229de8801a3bc626025f14fff4))
- *(iroh)* [**breaking**] Wrap the Connection struct so we own the type ([#3110](https://github.com/n0-computer/iroh/issues/3110)) - ([2e61ff2](https://github.com/n0-computer/iroh/commit/2e61ff2c9aae6a13f1aa574684ed5a2798c3fb4a))
- *(iroh)* [**breaking**] Remove access to local and remote IP addresses ([#3148](https://github.com/n0-computer/iroh/issues/3148)) - ([08bd2a1](https://github.com/n0-computer/iroh/commit/08bd2a1e52b2e0d0815cbfe0abdb311d2980b817))
- *(iroh-relay)* Make the client side of `iroh-relay` compile & run in browsers ([#3119](https://github.com/n0-computer/iroh/issues/3119)) - ([03e3e3c](https://github.com/n0-computer/iroh/commit/03e3e3cc2cef7cb4cb9dd332b4a8a8531dd4a4e0))
- [**breaking**] Add QUIC Address Discovery to iroh ([#3049](https://github.com/n0-computer/iroh/issues/3049)) - ([243a04a](https://github.com/n0-computer/iroh/commit/243a04abf61620965b62b6c0863eefc4617cedfc))

### 🐛 Bug Fixes

- *(iroh)* Remove `quinn::Endpoint::wait_idle` from `iroh::Endpoint::close` process ([#3165](https://github.com/n0-computer/iroh/issues/3165)) - ([a1d21c6](https://github.com/n0-computer/iroh/commit/a1d21c673d3449a31a32262bb5453c4ec8ce6bd5))
- *(iroh-net-report)* Only add QUIC ipv6 probes if we have an ipv6 interface ([#3133](https://github.com/n0-computer/iroh/issues/3133)) - ([9275d22](https://github.com/n0-computer/iroh/commit/9275d22dea6c14a1a2090be1985fd97a7de4801d))
- *(iroh-relay)* Fix client actors not closing ([#3134](https://github.com/n0-computer/iroh/issues/3134)) - ([e5bbbe1](https://github.com/n0-computer/iroh/commit/e5bbbe1c3c1275a61ea81b5f24a64001d133d6f1))
- Handle invalid input length when parsing a node id ([#3155](https://github.com/n0-computer/iroh/issues/3155)) - ([a8d058f](https://github.com/n0-computer/iroh/commit/a8d058fb1558741537521912d60199730482acbe))

### 🚜 Refactor

- *(iroh)* Replace `timer` module with `AbortOnDropHandle` and sleep ([#3141](https://github.com/n0-computer/iroh/issues/3141)) - ([43e9805](https://github.com/n0-computer/iroh/commit/43e9805fc329df3d1d081922e843ecd397e0ebeb))
- Use `n0-future` in favor of `futures-*` libraries and `tokio::{spawn,task,time}` ([#3156](https://github.com/n0-computer/iroh/issues/3156)) - ([617fa50](https://github.com/n0-computer/iroh/commit/617fa500a0d9113dca683321ed793a3e3a3af2bc))
- [**breaking**] Remove iroh-test crate ([#3162](https://github.com/n0-computer/iroh/issues/3162)) - ([7b6884f](https://github.com/n0-computer/iroh/commit/7b6884f8444d80665c048f9d4961defea713581d))
- Cleaning up unnecessary logs ([#3164](https://github.com/n0-computer/iroh/issues/3164)) - ([9a75d14](https://github.com/n0-computer/iroh/commit/9a75d14211e38dac2bcc4549ee8b982bb919e0aa))

### 📚 Documentation

- Fix typos in README ([#3144](https://github.com/n0-computer/iroh/issues/3144)) - ([c532de3](https://github.com/n0-computer/iroh/commit/c532de35c03aed13f82deaccf5d4e5e83bddee7a))

### ⚙️ Miscellaneous Tasks

- Remove individual repo project tracking ([#3135](https://github.com/n0-computer/iroh/issues/3135)) - ([eadc76b](https://github.com/n0-computer/iroh/commit/eadc76b51522f79b7afe05e48981f9b1ea045980))
- New project syncing setup ([#3136](https://github.com/n0-computer/iroh/issues/3136)) - ([96e6220](https://github.com/n0-computer/iroh/commit/96e622039e1dd7337fd935348a866eee708a1090))
- Update broken echo.rs link ([#3151](https://github.com/n0-computer/iroh/issues/3151)) - ([e049965](https://github.com/n0-computer/iroh/commit/e049965bd238e78d3a33b90a16077472377c860e))
- Release - ([fa66d88](https://github.com/n0-computer/iroh/commit/fa66d883a2e95fab6e3c664ad33a947364bdb4e0))

## [0.31.0](https://github.com/n0-computer/iroh/compare/v0.30.0..v0.31.0) - 2025-01-14

### ⛰️  Features

- *(iroh)* Implement Discovery for Arc'ed Discovery types ([#3107](https://github.com/n0-computer/iroh/issues/3107)) - ([f675525](https://github.com/n0-computer/iroh/commit/f675525bba5bb70b3723983fe5692652c441351d))
- *(iroh-relay)* [**breaking**] Implement authentication ([#3086](https://github.com/n0-computer/iroh/issues/3086)) - ([2c42eff](https://github.com/n0-computer/iroh/commit/2c42effa0918962e730e92aabd9dde97f887cd70))
- *(iroh-relay)* Send regular pings to check the connection ([#3113](https://github.com/n0-computer/iroh/issues/3113)) - ([cd12da3](https://github.com/n0-computer/iroh/commit/cd12da362bdc58fd37cc71177cc665f3cde4546c))
- *(relay)* [**breaking**] Relay only mode now configurable ([#3056](https://github.com/n0-computer/iroh/issues/3056)) - ([5aba17e](https://github.com/n0-computer/iroh/commit/5aba17efacc348bb658310d184159b77a65df7f2))
- Make `Endpoint::close` infallible ([#3112](https://github.com/n0-computer/iroh/issues/3112)) - ([870c76e](https://github.com/n0-computer/iroh/commit/870c76edebe92fe06effa774c25677da43589351))
- Allow dns discovery in transfer example ([#3121](https://github.com/n0-computer/iroh/issues/3121)) - ([a5bb926](https://github.com/n0-computer/iroh/commit/a5bb9268b26655a5a9c2aa696fc3fbd4c28485ff))

### 🐛 Bug Fixes

- *(dns)* Segfaults in pkarr ([#3120](https://github.com/n0-computer/iroh/issues/3120)) - ([04d43a6](https://github.com/n0-computer/iroh/commit/04d43a6526e29dc9e149999e2f207512af762127))
- *(iroh)* Set MaybeFuture to None on Poll::Ready ([#3090](https://github.com/n0-computer/iroh/issues/3090)) - ([6599ea6](https://github.com/n0-computer/iroh/commit/6599ea656de5a35be7c866a45c1d9f6ab5392df5))
- *(iroh)* Parse DNS answer with multiple records into a proper `NodeAddr` ([#3104](https://github.com/n0-computer/iroh/issues/3104)) - ([024ab7f](https://github.com/n0-computer/iroh/commit/024ab7f3f958528e183bb0d6489691518a0c40eb))
- *(iroh)* Remove superflious info log ([#3080](https://github.com/n0-computer/iroh/issues/3080)) - ([423a986](https://github.com/n0-computer/iroh/commit/423a9868a7386274dfe335e95622c7486dfeeb4f))
- *(iroh)* Implement Clone for StaticProvider discovery ([#3108](https://github.com/n0-computer/iroh/issues/3108)) - ([65cf688](https://github.com/n0-computer/iroh/commit/65cf6886eca1930b42de043f927a2c2cd5d518cc))
- *(iroh)* Queue sent datagrams longer ([#3129](https://github.com/n0-computer/iroh/issues/3129)) - ([e756710](https://github.com/n0-computer/iroh/commit/e756710b5d1c51b534c3ee280f3392c59420f34d))
- *(iroh)* Return error if disco send via relay fails ([#3130](https://github.com/n0-computer/iroh/issues/3130)) - ([35af23e](https://github.com/n0-computer/iroh/commit/35af23e259d66bde842a0f0b6708415b8562e4e0))
- *(iroh, iroh-relay)* [**breaking**] Optimise the relay datagram path through the MagicSock ([#3062](https://github.com/n0-computer/iroh/issues/3062)) - ([7ad531e](https://github.com/n0-computer/iroh/commit/7ad531ebfb4764861c0197eaf65249c232d23e8d))
- *(iroh-relay)* Removes deadlock in `Clients` ([#3099](https://github.com/n0-computer/iroh/issues/3099)) - ([c650ea8](https://github.com/n0-computer/iroh/commit/c650ea83dae8e25165c9eb9b502d58113c7febc5))
- *(iroh-relay)* Cleanup client connections in all cases ([#3105](https://github.com/n0-computer/iroh/issues/3105)) - ([f08d560](https://github.com/n0-computer/iroh/commit/f08d560669f64ff4b4e88a5e22970edac472b8cc))
- [**breaking**] Cleanup dead and unused dependencies ([#3070](https://github.com/n0-computer/iroh/issues/3070)) - ([a37dcfc](https://github.com/n0-computer/iroh/commit/a37dcfcb7ef4355603fb5192e0753b257f81aa36))
- Correctly set publishing details for pkarr records ([#3082](https://github.com/n0-computer/iroh/issues/3082)) - ([7bdae88](https://github.com/n0-computer/iroh/commit/7bdae88cb38cf312744f355d46223442842810e7))
- Try improving `relay_datagram_send_channel()` ([#3118](https://github.com/n0-computer/iroh/issues/3118)) - ([594b861](https://github.com/n0-computer/iroh/commit/594b86182da2481aa5b6885a38d6c19a16db25df))

### 🚜 Refactor

- *(iroh)* Magical pin projections ([#3060](https://github.com/n0-computer/iroh/issues/3060)) - ([a4d4e7d](https://github.com/n0-computer/iroh/commit/a4d4e7de7e0f5506bd48cbcbbb6bafcb342b9557))
- *(iroh)* ActiveRelayActor terminates itself ([#3061](https://github.com/n0-computer/iroh/issues/3061)) - ([693922a](https://github.com/n0-computer/iroh/commit/693922a407e9ed0ed6e2a3c16c4e19ad85582df3))
- *(iroh)* Simplify RTT actor ([#3072](https://github.com/n0-computer/iroh/issues/3072)) - ([1cd0e96](https://github.com/n0-computer/iroh/commit/1cd0e96e849de4c5c920098141a55122d56e18b0))
- *(iroh)* Remove CancellationToken from Endpoint ([#3101](https://github.com/n0-computer/iroh/issues/3101)) - ([9cef520](https://github.com/n0-computer/iroh/commit/9cef5204f6799d8b3f8547e77a9696407e496dfc))
- *(iroh, iroh-relay)* [**breaking**] Do reconnection in ActiveRelayActor ([#3058](https://github.com/n0-computer/iroh/issues/3058)) - ([272b6c4](https://github.com/n0-computer/iroh/commit/272b6c46a5d0cf25eca9db446725514da2a4138e))
- *(iroh-base)* Introduce an `Arc` into `RelayUrl` ([#3065](https://github.com/n0-computer/iroh/issues/3065)) - ([834ab78](https://github.com/n0-computer/iroh/commit/834ab785c192efb1dfad4975a0752c69a0dec68b))
- *(iroh-relay)* Rename DerpCodec to RelayCodec ([#3059](https://github.com/n0-computer/iroh/issues/3059)) - ([dfa0a2c](https://github.com/n0-computer/iroh/commit/dfa0a2c5e321304936e46feb42be0d67dc078a3b))
- *(iroh-relay)* [**breaking**] Server actor task is not a task or actor anymore ([#3093](https://github.com/n0-computer/iroh/issues/3093)) - ([f50db17](https://github.com/n0-computer/iroh/commit/f50db17d2d96ee86f0cf0f67f998dc89b320a09f))

### 📚 Documentation

- *(iroh)* Update discovery docs, mostly StaticProvider ([#3109](https://github.com/n0-computer/iroh/issues/3109)) - ([eb90bfc](https://github.com/n0-computer/iroh/commit/eb90bfc9bc9e9beaf8fd5a32dfb38da49399d729))
- *(iroh-relay)* README.md: config.toml must use [tls] instead of [tlsconfig] ([#3126](https://github.com/n0-computer/iroh/issues/3126)) - ([4e2641d](https://github.com/n0-computer/iroh/commit/4e2641d043a6b1b26918b892a052604d95ea050d))

### 🧪 Testing

- *(iroh)* Make `test_relay_datagram_queue` less timing dependent ([#3106](https://github.com/n0-computer/iroh/issues/3106)) - ([3fedee9](https://github.com/n0-computer/iroh/commit/3fedee95049b24895e5323a74ac676536420fb7c))
- *(iroh)* Add some context to test errors ([#3066](https://github.com/n0-computer/iroh/issues/3066)) - ([1ae820d](https://github.com/n0-computer/iroh/commit/1ae820d00e5062cf2a709f36d9f913c7cb2ef933))

### ⚙️ Miscellaneous Tasks

- *(*)* Run flaky tests with --verbose and use ci profile ([#3063](https://github.com/n0-computer/iroh/issues/3063)) - ([bc4f3ca](https://github.com/n0-computer/iroh/commit/bc4f3cac85bf63a55bea6dfb497dc822d409fe62))
- Pin an older nextest version ([#3088](https://github.com/n0-computer/iroh/issues/3088)) - ([8873190](https://github.com/n0-computer/iroh/commit/88731908276b3acdd1fd79becdb3d329dd5d14e4))
- Add project tracking ([#3094](https://github.com/n0-computer/iroh/issues/3094)) - ([d236e04](https://github.com/n0-computer/iroh/commit/d236e045017becd2dadf86ee0091d7a13d093592))
- Bug Report issue template ([#3085](https://github.com/n0-computer/iroh/issues/3085)) - ([60ba9ac](https://github.com/n0-computer/iroh/commit/60ba9ac75f81f8dcd4c49a5606ae96cc86cdbd3b))
- Use variable to construct URL ([#3122](https://github.com/n0-computer/iroh/issues/3122)) - ([3891778](https://github.com/n0-computer/iroh/commit/3891778af99f373f34c5d684489d06392bf6cd4e))
- Upgrade `portmapper` and `netwatch` deps ([#3127](https://github.com/n0-computer/iroh/issues/3127)) - ([7ba6321](https://github.com/n0-computer/iroh/commit/7ba63218b282641ab2f8065773992362ddaf44c2))
- Release - ([87e25f9](https://github.com/n0-computer/iroh/commit/87e25f961b6e1e287658f387d95ef34414e7a1a9))

## [0.30.0](https://github.com/n0-computer/iroh/compare/v0.29.0..v0.30.0) - 2024-12-16

### ⛰️  Features

- *(iroh)* [**breaking**] Remove get_protocol and the plumbing required for it ([#3009](https://github.com/n0-computer/iroh/issues/3009)) - ([1323c9a](https://github.com/n0-computer/iroh/commit/1323c9afa26c12ef0fabf6fb1c13917d124f008f))
- *(iroh)* Remove `Arc` requirements from `ProtocolHandler` ([#3010](https://github.com/n0-computer/iroh/issues/3010)) - ([8dfbc35](https://github.com/n0-computer/iroh/commit/8dfbc35d1bd5ad1ad47e1be54d4f63b62ea26108))
- *(iroh, iroh-relay)* [**breaking**] Remove `Endpoint::connect_by_node_id` and add `#[doc(cfg(...))]` annotations ([#3015](https://github.com/n0-computer/iroh/issues/3015)) - ([95bcb62](https://github.com/n0-computer/iroh/commit/95bcb62beaa72e46ce657d9becafca12663a579f))
- *(iroh-dns-server)* [**breaking**] Eviction of stale zonestore entries ([#2997](https://github.com/n0-computer/iroh/issues/2997)) - ([74884f1](https://github.com/n0-computer/iroh/commit/74884f1d2cb8bee737e052af5d86cb9d02bc5bbc))
- *(iroh-net)* Add a Watchable struct for use in the Endpoint API ([#2806](https://github.com/n0-computer/iroh/issues/2806)) - ([1a79a19](https://github.com/n0-computer/iroh/commit/1a79a194d9184dcaa81428d79cb7babb30700010))
- *(iroh-net-report)* [**breaking**] Add QUIC address discovery probes ([#3028](https://github.com/n0-computer/iroh/issues/3028)) - ([cf0f8cc](https://github.com/n0-computer/iroh/commit/cf0f8cc4f7d842a41aed0a22cb5687315ca8f967))
- *(iroh-relay)* [**breaking**] Use explicit key cache ([#3053](https://github.com/n0-computer/iroh/issues/3053)) - ([d4f72fa](https://github.com/n0-computer/iroh/commit/d4f72fa848f328f61f4928b6984d7ff424297ff2))
- *(net-report)* [**breaking**] Add `net_report::Options` to specify which probes you want to run ([#3032](https://github.com/n0-computer/iroh/issues/3032)) - ([ac74c53](https://github.com/n0-computer/iroh/commit/ac74c53a26aada4ce87660dcf5452838943e2dd7))
- *(relay)* Reloading certificate resolver ([#2999](https://github.com/n0-computer/iroh/issues/2999)) - ([c37895b](https://github.com/n0-computer/iroh/commit/c37895bfccb716d44a0e23f997555f0689e9b5a9))
- Implement `RelayDatagramsQueue` ([#2998](https://github.com/n0-computer/iroh/issues/2998)) - ([b76500d](https://github.com/n0-computer/iroh/commit/b76500d15c77fd7d154542194395305fe47aea8f))
- [**breaking**] Reduce default feature dependents ([#3005](https://github.com/n0-computer/iroh/issues/3005)) - ([321d8ff](https://github.com/n0-computer/iroh/commit/321d8ffd3d2bde2f1a80e78eab1ad83687484fc2))
- [**breaking**] Bump MSRV to 1.81 ([#3033](https://github.com/n0-computer/iroh/issues/3033)) - ([6e009a8](https://github.com/n0-computer/iroh/commit/6e009a8bc874ead210b9e00e2598c27b5a8d7df4))
- [**breaking**] Update to iroh-metrics@0.30.0 and portmapper@0.3.0 ([#3054](https://github.com/n0-computer/iroh/issues/3054)) - ([dcd0b40](https://github.com/n0-computer/iroh/commit/dcd0b401b1738a4ea6be66cdbfe48a0a7ed1aadc))

### 🐛 Bug Fixes

- *(iroh)* Poll all AsyncUdpSocket sources fairly ([#2996](https://github.com/n0-computer/iroh/issues/2996)) - ([26c5248](https://github.com/n0-computer/iroh/commit/26c5248bb4ebcb70c98c3297c29855676e18776f))
- *(iroh, iroh-relay)* [**breaking**] Bypass magicsock::Actor for datagrams from the relay ([#2986](https://github.com/n0-computer/iroh/issues/2986)) - ([0d06320](https://github.com/n0-computer/iroh/commit/0d06320bda68e87af04e784ee7f607939729639d))
- *(iroh-dns-server)* Remove accidental blocking from store ([#2985](https://github.com/n0-computer/iroh/issues/2985)) - ([647b2fd](https://github.com/n0-computer/iroh/commit/647b2fd032c66d06f1efe6f63b92374b7557b21c))

### 🚜 Refactor

- *(iroh)* Remove with_cancel, use run_until_cancelled ([#3000](https://github.com/n0-computer/iroh/issues/3000)) - ([f75a04b](https://github.com/n0-computer/iroh/commit/f75a04b0cacdda9947d0b38e7179c8693708f9d1))
- *(iroh)* Remove unused rate limiter ([#3007](https://github.com/n0-computer/iroh/issues/3007)) - ([b2b070f](https://github.com/n0-computer/iroh/commit/b2b070fefeeb59da438f81bef451eb3f6fd14524))
- *(iroh)* Rename the relay-is-ready-to-send waker ([#3014](https://github.com/n0-computer/iroh/issues/3014)) - ([79bf3c3](https://github.com/n0-computer/iroh/commit/79bf3c37aa391c974369499220b46943ca4075b1))
- *(iroh)* [**breaking**] Remove dialer::Dialer ([#3022](https://github.com/n0-computer/iroh/issues/3022)) - ([6a62c80](https://github.com/n0-computer/iroh/commit/6a62c8081ddb5f4ba6c9cd08c53f4dd8954475ce))
- *(iroh)* [**breaking**] Make iroh::tls private ([#3018](https://github.com/n0-computer/iroh/issues/3018)) - ([0fe7e8b](https://github.com/n0-computer/iroh/commit/0fe7e8b8a2138e64e0d59bff1d846d768d16532a))
- *(iroh)* [**breaking**] Improve reexport structure ([#3023](https://github.com/n0-computer/iroh/issues/3023)) - ([d9fb470](https://github.com/n0-computer/iroh/commit/d9fb4700dfaf6468187e58a53add460c9f463b42))
- *(iroh)* Add send queue between relay actor and relays ([#3026](https://github.com/n0-computer/iroh/issues/3026)) - ([af5a8c2](https://github.com/n0-computer/iroh/commit/af5a8c2364aebe8e3d93628e40342eab2e08425e))
- *(iroh)* Rename ConnectedRelayActor to ActiveRelayActor ([#3027](https://github.com/n0-computer/iroh/issues/3027)) - ([80bc8a3](https://github.com/n0-computer/iroh/commit/80bc8a360a1d5a2dd86fc57e33bbc4f9d3848e08))
- *(iroh)* Newtype the packet sent over relay servers ([#3030](https://github.com/n0-computer/iroh/issues/3030)) - ([e7503c0](https://github.com/n0-computer/iroh/commit/e7503c05ccfc9691fd3604d10d0ac0ac6300d388))
- *(iroh)* Remove genawaiter usage from dht discovery ([#3048](https://github.com/n0-computer/iroh/issues/3048)) - ([738c773](https://github.com/n0-computer/iroh/commit/738c7730df2af03747ec4c2c8a51b5da2e173733))
- *(iroh)* Remove ActiveRelayMessage::GetClient ([#3041](https://github.com/n0-computer/iroh/issues/3041)) - ([1ba140f](https://github.com/n0-computer/iroh/commit/1ba140f143a472821f989aa9d05b057909bbc6fd))
- *(iroh, iroh-relay)* JoinSet disabling in tokio::select! ([#3052](https://github.com/n0-computer/iroh/issues/3052)) - ([a6f502c](https://github.com/n0-computer/iroh/commit/a6f502cb4222c341a3b2d1acf35aa209bf14af2c))
- *(iroh-base)* [**breaking**] Remove hash and BlobTicket ([#3036](https://github.com/n0-computer/iroh/issues/3036)) - ([ee72f6d](https://github.com/n0-computer/iroh/commit/ee72f6da7caed23c24d34c611b5de222898dcbd0))
- *(iroh-base)* [**breaking**] Remove base32 module ([#3042](https://github.com/n0-computer/iroh/issues/3042)) - ([542f56d](https://github.com/n0-computer/iroh/commit/542f56d5b290d521c81b10a55a97eec2ec2615cd))
- *(iroh-base)* [**breaking**] Reduce dependencies ([#3046](https://github.com/n0-computer/iroh/issues/3046)) - ([4a774f1](https://github.com/n0-computer/iroh/commit/4a774f1fd1dd592038ee83aaa9e9b1a2557a4c9a))
- *(iroh-base)* Remove automatic key caching ([#3051](https://github.com/n0-computer/iroh/issues/3051)) - ([58df1d8](https://github.com/n0-computer/iroh/commit/58df1d88a5ee73fa1c2824779bb8391c13c07548))
- *(iroh-dns-server)* Move db ops into an actor and implement write batching ([#2995](https://github.com/n0-computer/iroh/issues/2995)) - ([cd9c188](https://github.com/n0-computer/iroh/commit/cd9c188068c3e81e9f241ee755499f09c53906c9))
- *(iroh-relay)* [**breaking**] Always allow acking pings ([#3011](https://github.com/n0-computer/iroh/issues/3011)) - ([97082ec](https://github.com/n0-computer/iroh/commit/97082ec6ac3904f65681c87ddfd42a9113eea4cb))
- *(iroh-relay)* [**breaking**] Remove usesed errors. ([#3012](https://github.com/n0-computer/iroh/issues/3012)) - ([c5d9e68](https://github.com/n0-computer/iroh/commit/c5d9e683273d59edc208ca7fc5a520fbb647928f))
- *(iroh-relay)* [**breaking**] Remove async requirement from address_family_selector ([#3044](https://github.com/n0-computer/iroh/issues/3044)) - ([8ec0d73](https://github.com/n0-computer/iroh/commit/8ec0d73f97e76bc76774b92963094de0d22f9f74))
- Remove `AddrInfo` ([#3024](https://github.com/n0-computer/iroh/issues/3024)) - ([6a988a5](https://github.com/n0-computer/iroh/commit/6a988a5b448ba36dc48873275eb0bd8805ef3879))
- Remove parking-lot dependency ([#3034](https://github.com/n0-computer/iroh/issues/3034)) - ([08671bb](https://github.com/n0-computer/iroh/commit/08671bb4dadc8ac4d0996a7ca2393b5efb7dc7bb))
- [**breaking**] Make PUBLIC_KEY_LENGTH a const that is on PublicKey ([#3043](https://github.com/n0-computer/iroh/issues/3043)) - ([218aad3](https://github.com/n0-computer/iroh/commit/218aad30b42f01b132d5c513d414efeb7b7f47d1))
- Unify hex encoding with data-encoding ([#3047](https://github.com/n0-computer/iroh/issues/3047)) - ([a338289](https://github.com/n0-computer/iroh/commit/a338289affb41569b76eefb4a197fd38462f51e4))

### 📚 Documentation

- *(*)* Use doc-auto-cfg feature ([#3029](https://github.com/n0-computer/iroh/issues/3029)) - ([3e31196](https://github.com/n0-computer/iroh/commit/3e31196ff79db884bf179c9774fe62a29ebb6195))
- Update README.md ([#3019](https://github.com/n0-computer/iroh/issues/3019)) - ([ad6c535](https://github.com/n0-computer/iroh/commit/ad6c535d33f54678e08ef548e0117b09e15f49e2))

### 🧪 Testing

- *(iroh)* Packet loss is expected with socket rebinding ([#3001](https://github.com/n0-computer/iroh/issues/3001)) - ([e575af2](https://github.com/n0-computer/iroh/commit/e575af2a7fcb54fabcafd16e1b7edf29b3ef784b))

### ⚙️ Miscellaneous Tasks

- *(iroh, iroh-relay)* Avoid a duplicate tungstenite dependency ([#3006](https://github.com/n0-computer/iroh/issues/3006)) - ([566d7eb](https://github.com/n0-computer/iroh/commit/566d7eb5797ab173028deacc075635110bdf221e))
- Bump netsim setup ([#3004](https://github.com/n0-computer/iroh/issues/3004)) - ([a3f0497](https://github.com/n0-computer/iroh/commit/a3f0497ba8c3a1a478280681b476ccc6fd8d7eb0))
- Update to hickory =0.25.0-alpha.4 ([#3021](https://github.com/n0-computer/iroh/issues/3021)) - ([9f4ca84](https://github.com/n0-computer/iroh/commit/9f4ca8458fd4c6d67467633551cd9a645d549f3d))
- (Deps) Update swarm-discovery to avoid idna <= 0.5 dep ([#3025](https://github.com/n0-computer/iroh/issues/3025)) - ([095fcc7](https://github.com/n0-computer/iroh/commit/095fcc7f3487cc1f2e90e407f9bddde8f941bcd2))
- Don't log expected errors ([#3016](https://github.com/n0-computer/iroh/issues/3016)) - ([fdb687f](https://github.com/n0-computer/iroh/commit/fdb687ff8c2e70d4e33ebee5e3f557e240202cc1))
- Clean up some bits ([#3039](https://github.com/n0-computer/iroh/issues/3039)) - ([3be22f3](https://github.com/n0-computer/iroh/commit/3be22f3bee414a0019be778b0e7f731849b1079e))
- Remove version from local dev-deps - ([2275bee](https://github.com/n0-computer/iroh/commit/2275bee10ed33a6de0e422a3f16fc6020d13928c))
- Release - ([9be85dd](https://github.com/n0-computer/iroh/commit/9be85dd84d03470fced2504177f7ba2c365f6c53))

## [0.29.0](https://github.com/n0-computer/iroh/compare/v0.28.1..v0.29.0) - 2024-12-02

### ⛰️  Features

- *(iroh)* Make all important iroh_base types available ([#2975](https://github.com/n0-computer/iroh/issues/2975)) - ([73c9b75](https://github.com/n0-computer/iroh/commit/73c9b75b5f37a916a2e046077963e519865a9b29))
- *(iroh)* Improve Router shutdown ([#2978](https://github.com/n0-computer/iroh/issues/2978)) - ([fbcaaa5](https://github.com/n0-computer/iroh/commit/fbcaaa56a46b4d2511d65da0330b0cebd89640d1))
- *(iroh)* Improve shutdown interactions ([#2980](https://github.com/n0-computer/iroh/issues/2980)) - ([e461cca](https://github.com/n0-computer/iroh/commit/e461cca8cd3bcf3b3d51095a2a8ddeffd0af8893))
- *(iroh-base, iroh-net-report)* [**breaking**] Intro net-report as a crate ([#2921](https://github.com/n0-computer/iroh/issues/2921)) - ([a5e9283](https://github.com/n0-computer/iroh/commit/a5e92833f7a7569575241e31ca67f9ae64e092c9))
- *(iroh-net)* Implement the https probe ([#2903](https://github.com/n0-computer/iroh/issues/2903)) - ([91d44dc](https://github.com/n0-computer/iroh/commit/91d44dc4061b071847f0797a7c638aa4405dd3f7))
- *(iroh-net)* Allow the underlying UdpSockets to be rebound ([#2946](https://github.com/n0-computer/iroh/issues/2946)) - ([cc9e4e6](https://github.com/n0-computer/iroh/commit/cc9e4e6e883777dcd428265c22bdbd6cdb8e5660))
- *(iroh-relay)* Rate-limit client connections ([#2961](https://github.com/n0-computer/iroh/issues/2961)) - ([c999770](https://github.com/n0-computer/iroh/commit/c999770e808fb2a40215612c6ed3260d9fd40330))
- *(iroh-relay)* [**breaking**] Add a QUIC server for QUIC address discovery to the iroh relay. ([#2965](https://github.com/n0-computer/iroh/issues/2965)) - ([b2cb0ca](https://github.com/n0-computer/iroh/commit/b2cb0cae8b896d10e7a6f7adfff2f2b3a2fed1d4))
- [**breaking**] Add iroh-relay crate ([#2873](https://github.com/n0-computer/iroh/issues/2873)) - ([59b5bf9](https://github.com/n0-computer/iroh/commit/59b5bf9d26645c2c5e598167b350eba04be52ca5))
- Simple iroh ([#2968](https://github.com/n0-computer/iroh/issues/2968)) - ([32f1fcd](https://github.com/n0-computer/iroh/commit/32f1fcdd11af70ded2785ab7b1ed15ee74991586))
- Update to iroh-metrics@0.29.0 ([#2992](https://github.com/n0-computer/iroh/issues/2992)) - ([078d1a6](https://github.com/n0-computer/iroh/commit/078d1a645f49d36317d76700b32b36072367fac8))
- Extract iroh-node-util ([#2993](https://github.com/n0-computer/iroh/issues/2993)) - ([92d9864](https://github.com/n0-computer/iroh/commit/92d9864eb228dbd639b29bfb87956e1072d302f4))

### 🐛 Bug Fixes

- *(ci)* Try to reuse msys2 dep ([#2956](https://github.com/n0-computer/iroh/issues/2956)) - ([4e58b1f](https://github.com/n0-computer/iroh/commit/4e58b1f8cf7ac6a36ececfb51e834feea75b2133))
- *(iroh)* Remove iroh dev self dep ([#2974](https://github.com/n0-computer/iroh/issues/2974)) - ([7057d72](https://github.com/n0-computer/iroh/commit/7057d72181a2cdeb3581d85009babd815b16647d))
- *(iroh-dns-server)* Actually use async fs in load_secret_key ([#2943](https://github.com/n0-computer/iroh/issues/2943)) - ([7c19da4](https://github.com/n0-computer/iroh/commit/7c19da4fdd75301c7f6fb6cf4364c23d83b42c1b))
- *(iroh-net)* Do not return a port for reqwest DNS resolver ([#2906](https://github.com/n0-computer/iroh/issues/2906)) - ([81c8ff7](https://github.com/n0-computer/iroh/commit/81c8ff7bfadf0bb7b389be149d338977b5c14156))
- *(iroh-net)* Make sure the rtt-actor is shutdown correctly ([#2914](https://github.com/n0-computer/iroh/issues/2914)) - ([c96b032](https://github.com/n0-computer/iroh/commit/c96b032090d1a49fc82a5e853e2c4abec4ca2431))
- *(iroh-net)* Fix memory leaks in the iroh-relay server ([#2915](https://github.com/n0-computer/iroh/issues/2915)) - ([e2c3c98](https://github.com/n0-computer/iroh/commit/e2c3c98bc3907cc41098749a3ec36b313a012100))
- *(iroh-relay)* Do not use spawn_blocking in stun handler ([#2924](https://github.com/n0-computer/iroh/issues/2924)) - ([1084400](https://github.com/n0-computer/iroh/commit/1084400e215769ff4d58cf2bc00fc2336e278dba))
- *(netwatch)* BSD rebind socket on errors ([#2913](https://github.com/n0-computer/iroh/issues/2913)) - ([c451750](https://github.com/n0-computer/iroh/commit/c451750677df794dd0d6c0f0818a4629780ab1ce))
- *(netwatch)* Hold on to netmon sender reference in android ([#2923](https://github.com/n0-computer/iroh/issues/2923)) - ([4bd4df7](https://github.com/n0-computer/iroh/commit/4bd4df7a128f896982797dd39d07275cbc986694))
- Update to patched iroh-gossip 0.28.1 - ([bd44719](https://github.com/n0-computer/iroh/commit/bd4471912ab696e8d9119a5b9d3c2bcdb80c43f7))
- Enforce cc@1.1.31 ([#2907](https://github.com/n0-computer/iroh/issues/2907)) - ([68c6184](https://github.com/n0-computer/iroh/commit/68c618443c37af9e0a57539b14e652f83edfe603))
- Remove problematic usage of `else` branches in `tokio::select`s ([#2940](https://github.com/n0-computer/iroh/issues/2940)) - ([ccfc700](https://github.com/n0-computer/iroh/commit/ccfc700494f693b9a21dea155942f65e0fdd2d01))

### 🚜 Refactor

- *(iroh)* [**breaking**] Move blobs and tags rpc client and server to iroh-blobs ([#2874](https://github.com/n0-computer/iroh/issues/2874)) - ([d6a32f4](https://github.com/n0-computer/iroh/commit/d6a32f482e3de8bce846562a22ea589e3b4a2173))
- *(iroh)* Extract docs RPC into iroh-docs ([#2868](https://github.com/n0-computer/iroh/issues/2868)) - ([289b4cf](https://github.com/n0-computer/iroh/commit/289b4cf5f0a00837214ca3b189da17df226eea8a))
- *(iroh)* [**breaking**] Get rid of some dependencies ([#2948](https://github.com/n0-computer/iroh/issues/2948)) - ([73e7d44](https://github.com/n0-computer/iroh/commit/73e7d44560eb60e16773ac9143f7d5704fc31b52))
- *(iroh)* [**breaking**] Extract net and node rpc ([#2927](https://github.com/n0-computer/iroh/issues/2927)) - ([f174c8e](https://github.com/n0-computer/iroh/commit/f174c8eaa7aaf946be247a416389b9f0f45208d3))
- *(iroh-cli)* [**breaking**] Use blobs and tags cli from iroh-blobs crate ([#2942](https://github.com/n0-computer/iroh/issues/2942)) - ([f9e883d](https://github.com/n0-computer/iroh/commit/f9e883d39761b225057d28b7a53927687c4c6951))
- *(iroh-cli)* [**breaking**] Use docs and authors cli from iroh-docs crate ([#2947](https://github.com/n0-computer/iroh/issues/2947)) - ([ad91831](https://github.com/n0-computer/iroh/commit/ad9183112a6d47a53a1722d8be8bf68dec11400b))
- *(iroh-cli)* [**breaking**] Use gossip cli from iroh-gossip crate ([#2945](https://github.com/n0-computer/iroh/issues/2945)) - ([fcc105b](https://github.com/n0-computer/iroh/commit/fcc105bb8e6bfbabb5f99033b6f9e89f48943ddb))
- *(iroh-cli)* [**breaking**] Use config and logging from iroh-node-utils ([#2953](https://github.com/n0-computer/iroh/issues/2953)) - ([3ff914d](https://github.com/n0-computer/iroh/commit/3ff914da907513e20fc5298a154623f2de0d6222))
- *(iroh-cli)* [**breaking**] Move net and node cli into iroh-node-util under the cli feature ([#2954](https://github.com/n0-computer/iroh/issues/2954)) - ([cbf7fd0](https://github.com/n0-computer/iroh/commit/cbf7fd0722219e3bf1d924b8cc42c72fc291f851))
- *(iroh-net)* Remove dead code in relay http-server ([#2908](https://github.com/n0-computer/iroh/issues/2908)) - ([23b874c](https://github.com/n0-computer/iroh/commit/23b874c0d52dab340ce7fe03263d3e26e605e772))
- *(iroh-relay)* Improve overall server structure ([#2922](https://github.com/n0-computer/iroh/issues/2922)) - ([0e57292](https://github.com/n0-computer/iroh/commit/0e5729255bbe6f150cc1550b2c340670f9f00a8f))
- *(iroh-router)* [**breaking**] Change accept to take an AsRef<[u8]> ([#2963](https://github.com/n0-computer/iroh/issues/2963)) - ([4e3b431](https://github.com/n0-computer/iroh/commit/4e3b4312381350de5ac29a79ce4df2ebf433744a))
- [**breaking**] Remove default protocols and iroh-cli ([#2928](https://github.com/n0-computer/iroh/issues/2928)) - ([a956319](https://github.com/n0-computer/iroh/commit/a956319277f0613175378c3e756f6c6b5ab1529f))
- Move `iroh-router` into `iroh-net` and rename `iroh-net` to `iroh` ([#2973](https://github.com/n0-computer/iroh/issues/2973)) - ([f7764ef](https://github.com/n0-computer/iroh/commit/f7764ef130a0f2fd4938339178372a7176bd5def))
- Cleanup internal dependency references ([#2976](https://github.com/n0-computer/iroh/issues/2976)) - ([fb20176](https://github.com/n0-computer/iroh/commit/fb20176763f5a59727ad3c553641c830bb847cfb))
- Extract iroh-metrics into its own repo ([#2989](https://github.com/n0-computer/iroh/issues/2989)) - ([df591bc](https://github.com/n0-computer/iroh/commit/df591bcea3f8ef3cc403f03d3cf3478d4ae90d73))
- Extract net-tools ([#2991](https://github.com/n0-computer/iroh/issues/2991)) - ([574337a](https://github.com/n0-computer/iroh/commit/574337ad466698b743c954450306bc6b9d406d9a))

### 📚 Documentation

- *(iroh-dns-server)* Fixup rate limit config docs ([#2894](https://github.com/n0-computer/iroh/issues/2894)) - ([8d8baf5](https://github.com/n0-computer/iroh/commit/8d8baf56a2ab03fa8d6cce27ac733adb4bf8aa95))
- *(iroh-net)* Explain when sockets are closed ([#2892](https://github.com/n0-computer/iroh/issues/2892)) - ([a4ad7a2](https://github.com/n0-computer/iroh/commit/a4ad7a2b99e905d166a00faf05f063052da2147a))
- Format code in doc comments ([#2895](https://github.com/n0-computer/iroh/issues/2895)) - ([b17b1f2](https://github.com/n0-computer/iroh/commit/b17b1f20b4c5e584e1fa4219ce5e375b37e9dbf1))
- Fixup changelog for 0.28.1 ([#2899](https://github.com/n0-computer/iroh/issues/2899)) - ([0a7a534](https://github.com/n0-computer/iroh/commit/0a7a534128bf1234a326fcfba134d878e796c377))
- Rewrite README (& add `echo.rs` example) ([#2960](https://github.com/n0-computer/iroh/issues/2960)) - ([4abfd61](https://github.com/n0-computer/iroh/commit/4abfd61fb662ab5b3cfbc2eeea2a23e8ee3c79d7))

### 🧪 Testing

- *(iroh)* Feature-flag the doc test ([#2983](https://github.com/n0-computer/iroh/issues/2983)) - ([b30f218](https://github.com/n0-computer/iroh/commit/b30f2189cf9ca8583c0030b415104272a357aa23))
- *(iroh-cli)* Increase wait on windows resumption tests ([#2919](https://github.com/n0-computer/iroh/issues/2919)) - ([f80dd3f](https://github.com/n0-computer/iroh/commit/f80dd3fb467e0a275d0ee50cd642c283800085da))
- *(iroh-relay, netcheck)* Move tests to use local relays ([#2935](https://github.com/n0-computer/iroh/issues/2935)) - ([8edaee9](https://github.com/n0-computer/iroh/commit/8edaee9b5c618709e6d79ba924d11a3c1b814c88))

### ⚙️ Miscellaneous Tasks

- *(ci)* Easy manual builds for binaries ([#2890](https://github.com/n0-computer/iroh/issues/2890)) - ([fcf89a6](https://github.com/n0-computer/iroh/commit/fcf89a69071915f076ab3d07c02123083e0499a2))
- *(ci)* Fix uploads of release artifacts ([#2891](https://github.com/n0-computer/iroh/issues/2891)) - ([1409bc4](https://github.com/n0-computer/iroh/commit/1409bc4b5ddb29d9bec1184b9541d0f88db57015))
- *(ci)* Fix uploads of release artifacts again ([#2893](https://github.com/n0-computer/iroh/issues/2893)) - ([258eb33](https://github.com/n0-computer/iroh/commit/258eb33ed598c25be98986463fc1f798b374848a))
- *(ci)* Fix for asset bundles ([#2898](https://github.com/n0-computer/iroh/issues/2898)) - ([911d7a6](https://github.com/n0-computer/iroh/commit/911d7a6f942cd0970c64110ef76994d9216cc1d1))
- *(ci)* Reduce sccache size ([#2988](https://github.com/n0-computer/iroh/issues/2988)) - ([8c00f7b](https://github.com/n0-computer/iroh/commit/8c00f7b68ea3b6acaaf8958560ab04341aeaf411))
- *(iroh)* Rename target for events ([#2977](https://github.com/n0-computer/iroh/issues/2977)) - ([43d0ea4](https://github.com/n0-computer/iroh/commit/43d0ea45b950a69aa3a3340b60275f53aa18b254))
- *(iroh-dns-server)* Cleanup some code ([#2941](https://github.com/n0-computer/iroh/issues/2941)) - ([fbcb056](https://github.com/n0-computer/iroh/commit/fbcb0562081cdc1f4c6523b4994438228c1fa94c))
- *(iroh-node-util)* Add iroh-node-util to tests ([#2955](https://github.com/n0-computer/iroh/issues/2955)) - ([63336ab](https://github.com/n0-computer/iroh/commit/63336abca7d91e8502bb2632e3f90991550659b7))
- *(iroh-relay)* Fixup docs feature config ([#2920](https://github.com/n0-computer/iroh/issues/2920)) - ([7084262](https://github.com/n0-computer/iroh/commit/708426215438de3b9be3426c507782b955d06572))
- Update Cargo.lock - ([f3398b4](https://github.com/n0-computer/iroh/commit/f3398b4eff04539a930f00a82b72d15025d92411))
- Release - ([d0994a0](https://github.com/n0-computer/iroh/commit/d0994a0fe21e849ddf2f7da7536336cc5ef00b5a))
- Release - ([30e3cb3](https://github.com/n0-computer/iroh/commit/30e3cb34aa7f8dee4c8b1077fbc969c880a39a13))
- Update deny.toml ([#2888](https://github.com/n0-computer/iroh/issues/2888)) - ([57cd2ab](https://github.com/n0-computer/iroh/commit/57cd2ab7052c84d4ccdce1500d0ff686fa01cf50))
- Accept unmaintained crate for now ([#2918](https://github.com/n0-computer/iroh/issues/2918)) - ([bf603e8](https://github.com/n0-computer/iroh/commit/bf603e8e511ef62b2af6a86fed385d2bb946f03b))
- Kill tests after 60s using nextest ([#2900](https://github.com/n0-computer/iroh/issues/2900)) - ([ba1ffa1](https://github.com/n0-computer/iroh/commit/ba1ffa1a5951b10aece1ff5e299f5422cb021457))
- Fix important readme design issue (flat square style consistency) ([#2931](https://github.com/n0-computer/iroh/issues/2931)) - ([5acce9c](https://github.com/n0-computer/iroh/commit/5acce9c461de72ba4db4f6b9d9d7ea1e18032933))
- Extend CI build job config ([#2929](https://github.com/n0-computer/iroh/issues/2929)) - ([1479b45](https://github.com/n0-computer/iroh/commit/1479b45f28edafe55ca890ce8c1a8b9d5d982914))
- Adapt to latest main in iroh-gossip and iroh-docs ([#2936](https://github.com/n0-computer/iroh/issues/2936)) - ([09c54e4](https://github.com/n0-computer/iroh/commit/09c54e41e9f9f40a59af4bea54db5b9b89c3f0b5))
- Prune some deps ([#2932](https://github.com/n0-computer/iroh/issues/2932)) - ([e675bba](https://github.com/n0-computer/iroh/commit/e675bbafacab31136b842de557385b05d7156b44))
- Remove `cc` version requirement & update lockfile to cc v1.2.1 ([#2969](https://github.com/n0-computer/iroh/issues/2969)) - ([0a5379b](https://github.com/n0-computer/iroh/commit/0a5379b27b5c652616cf15d45d02a950884c7fde))
- Release - ([80a40c0](https://github.com/n0-computer/iroh/commit/80a40c0810e051fbeb9344a7e6709c630d0ba464))

### Ref

- *(iroh)* Remove unused function ([#2984](https://github.com/n0-computer/iroh/issues/2984)) - ([4ffbd13](https://github.com/n0-computer/iroh/commit/4ffbd1328587c9290ef7dfc70d7de3a565e9939b))
- *(iroh-metrics, iroh-relay)* Remove the UsageStatsReporter ([#2952](https://github.com/n0-computer/iroh/issues/2952)) - ([8b7611e](https://github.com/n0-computer/iroh/commit/8b7611e8f4b519eec567ab96cb5430d754688886))
- *(iroh-net)* [**breaking**] Make Endpoint::close not consume self ([#2882](https://github.com/n0-computer/iroh/issues/2882)) - ([50f66dd](https://github.com/n0-computer/iroh/commit/50f66ddbbe10451f82462360635eec140cae4240))

## [0.28.1](https://github.com/n0-computer/iroh/compare/v0.28.0..v0.28.1) - 2024-11-04

### 🐛 Bug Fixes

- Switch to correctly patched quic-rpc and iroh-quinn - ([d925da4](https://github.com/n0-computer/iroh/commit/d925da442993fb79d55b905d4c17a324e9549bd2))

### 📚 Documentation

- Fixup changelog - ([5066102](https://github.com/n0-computer/iroh/commit/50661022258e607775af6e6b83c4c25fc57ed088))

### ⚙️ Miscellaneous Tasks

- Release - ([134a93b](https://github.com/n0-computer/iroh/commit/134a93b5a60103b3ce8fa4aacb52cdbcb291d00b))

## [0.28.0](https://github.com/n0-computer/iroh/compare/v0.27.0..v0.28.0) - 2024-11-04

### ⛰️  Features

- *(iroh-dns-server)* [**breaking**] Make http rate limit configurable ([#2772](https://github.com/n0-computer/iroh/issues/2772)) - ([fe684c2](https://github.com/n0-computer/iroh/commit/fe684c23e60fc8c35d3ec02bf088f36e1e248c50))
- *(iroh-net)* Add StaticDiscovery to provide static info to endpoints ([#2825](https://github.com/n0-computer/iroh/issues/2825)) - ([c9d1ba7](https://github.com/n0-computer/iroh/commit/c9d1ba7c09948fd24fee6f1aff4d772049d5a86a))
- *(iroh-net)* More Quinn re-exports ([#2838](https://github.com/n0-computer/iroh/issues/2838)) - ([9495c21](https://github.com/n0-computer/iroh/commit/9495c21a4f5ee93e1f5f7312b37c0752327100bd))
- *(iroh-net)* Send HTTP/1.1 `HOST` header on requests to relay ([#2881](https://github.com/n0-computer/iroh/issues/2881)) - ([4bfa58e](https://github.com/n0-computer/iroh/commit/4bfa58eaed49595602c64ac07155bf36c1469ffd))
- [**breaking**] Introduce iroh-router crate ([#2832](https://github.com/n0-computer/iroh/issues/2832)) - ([8f75005](https://github.com/n0-computer/iroh/commit/8f7500545ac71a151b0a8ac4389e558b64e58a4c))
- Collect metrics for direct connections & add opt-in push metrics ([#2805](https://github.com/n0-computer/iroh/issues/2805)) - ([86b494a](https://github.com/n0-computer/iroh/commit/86b494a9088e1558150d70481051227845c827e1))

### 🐛 Bug Fixes

- *(ci)* Better error reporting on netsim fails ([#2886](https://github.com/n0-computer/iroh/issues/2886)) - ([e1aab51](https://github.com/n0-computer/iroh/commit/e1aab5188c55c571fd2024b98e34b144143bd2be))
- *(iroh-net)* When switching to a direct path reset the mtu ([#2835](https://github.com/n0-computer/iroh/issues/2835)) - ([93f7900](https://github.com/n0-computer/iroh/commit/93f79009bdc1b9cb8e8db41e143a1df14fdb7f25))
- *(iroh-relay)* Respect `enable_stun` setting in `iroh-relay::Config` ([#2879](https://github.com/n0-computer/iroh/issues/2879)) - ([2507e62](https://github.com/n0-computer/iroh/commit/2507e625c0fd05924a72af1e21696ba4ff7e4dc7))
- *(metrics)* Allow external crates to encode their metrics ([#2885](https://github.com/n0-computer/iroh/issues/2885)) - ([362076e](https://github.com/n0-computer/iroh/commit/362076ee742c810ea8ccb28f415fd90e0b8171c3))
- *(portmapper)* Enforce timeouts for upnp ([#2877](https://github.com/n0-computer/iroh/issues/2877)) - ([00a3f88](https://github.com/n0-computer/iroh/commit/00a3f88cbb2a93dc15144da91674af9cb95bb06f))

### 🚜 Refactor

- *(iroh)* Move protocol relevant impls into node/protocols ([#2831](https://github.com/n0-computer/iroh/issues/2831)) - ([67df1c1](https://github.com/n0-computer/iroh/commit/67df1c148f9eee8008e0288dbc2c8829be05c891))
- *(iroh)* Move ProtocolHandler impl to iroh-gossip ([#2849](https://github.com/n0-computer/iroh/issues/2849)) - ([6c6827d](https://github.com/n0-computer/iroh/commit/6c6827d63ec12d9c9583b73b5530a7641060535c))
- *(iroh)* Move blobs protocol to iroh-blobs ([#2853](https://github.com/n0-computer/iroh/issues/2853)) - ([30f3e03](https://github.com/n0-computer/iroh/commit/30f3e03cde8a58af3b84a5f11134fb970ec3efa1))
- *(iroh)* [**breaking**] Remove gossip rpc types ([#2834](https://github.com/n0-computer/iroh/issues/2834)) - ([a55529b](https://github.com/n0-computer/iroh/commit/a55529b52e198527590493e67e7706290c9656f0))
- *(iroh-net)* Portmapper and network monitor are crates ([#2855](https://github.com/n0-computer/iroh/issues/2855)) - ([fad3e24](https://github.com/n0-computer/iroh/commit/fad3e24b3f2698ce6c1fa3fdad54201bec668298))
- Move iroh-gossip to external repo ([#2826](https://github.com/n0-computer/iroh/issues/2826)) - ([e659405](https://github.com/n0-computer/iroh/commit/e659405241692feb94030a8145e0b66a1a248641))
- Move iroh-docs to external repo ([#2830](https://github.com/n0-computer/iroh/issues/2830)) - ([3e17210](https://github.com/n0-computer/iroh/commit/3e17210c1e2ff7b8788feb3534e57e8c3af3cd4b))
- Remove iroh-blobs and use crates.io dependency ([#2829](https://github.com/n0-computer/iroh/issues/2829)) - ([d29537d](https://github.com/n0-computer/iroh/commit/d29537da6fc07ff82b8d56ff5fae9fdef9445858))
- [**breaking**] Remove iroh_base::rpc ([#2840](https://github.com/n0-computer/iroh/issues/2840)) - ([bfba7a4](https://github.com/n0-computer/iroh/commit/bfba7a42284a5b1b9065186c558bc614dba351f2))
- Move ProtocolHandler docs to iroh-docs ([#2859](https://github.com/n0-computer/iroh/issues/2859)) - ([61acd96](https://github.com/n0-computer/iroh/commit/61acd9688af60e55c62e357eb69272ea24097ffc))

### 📚 Documentation

- *(iroh-net)* Link to Endpoint in the first few paragraphs ([#2875](https://github.com/n0-computer/iroh/issues/2875)) - ([f0590be](https://github.com/n0-computer/iroh/commit/f0590be408c8dbe412897525a97a170e694dd650))

### 🧪 Testing

- *(iroh-net)* Give this a longer timeout ([#2857](https://github.com/n0-computer/iroh/issues/2857)) - ([ed13453](https://github.com/n0-computer/iroh/commit/ed13453697fbe600fdb50afb374543b69125bbc9))
- *(iroh-net)* Make dht_discovery_smoke test less flaky ([#2884](https://github.com/n0-computer/iroh/issues/2884)) - ([ce8d94d](https://github.com/n0-computer/iroh/commit/ce8d94de083d7aa997cd79936cf1606131420e6e))
- *(netwatch)* Simplify dev-deps - ([029830f](https://github.com/n0-computer/iroh/commit/029830fd75be4690a840185973ed3210692a167c))

### ⚙️ Miscellaneous Tasks

- *(ci)* Identify which repository the flakes are reported for ([#2824](https://github.com/n0-computer/iroh/issues/2824)) - ([b2e587d](https://github.com/n0-computer/iroh/commit/b2e587d7c96e84b2c2df75e33fea80ef3bd97450))
- *(iroh-net)* Fixup portmapper version - ([37f620d](https://github.com/n0-computer/iroh/commit/37f620dffa929a427374e1508737f68ee1e8f543))
- Add iroh-router to crates list ([#2850](https://github.com/n0-computer/iroh/issues/2850)) - ([2d17636](https://github.com/n0-computer/iroh/commit/2d17636d32840f09bb6f86ab91a49d9ecea07bd9))
- Release - ([860b90f](https://github.com/n0-computer/iroh/commit/860b90f1bad660a470d30f1e81ee0d6984de6106))
- Release - ([8bae5c3](https://github.com/n0-computer/iroh/commit/8bae5c3ec4465e7d6369440d1c55f7de7ca0e770))
- Release - ([d6c39c9](https://github.com/n0-computer/iroh/commit/d6c39c974f1383603e06b742c9394969b644c0f7))
- Release - ([2073bf4](https://github.com/n0-computer/iroh/commit/2073bf40176789c36a607d10a6bbaef38b16846b))
- Upgrade 0.28 iroh-net - ([13da047](https://github.com/n0-computer/iroh/commit/13da0478b89202904a8a67c9e0a1ff4ad15882b7))
- Release - ([5751521](https://github.com/n0-computer/iroh/commit/5751521cf50434c588e387ce483daf407919571b))
- Release - ([5437dbb](https://github.com/n0-computer/iroh/commit/5437dbb4e409200f66c3d97d9b277be14a2b6b33))
- Upgrade 0.28 iroh-router - ([297b874](https://github.com/n0-computer/iroh/commit/297b8743296d6103d8b0457b431597f4d6168c7d))
- Update 0.28 iroh-docs, iroh-gossip, iroh-blobs - ([7e80a92](https://github.com/n0-computer/iroh/commit/7e80a9221eb61d04a02830ed1c1794503f8113ff))
- Release - ([fa926be](https://github.com/n0-computer/iroh/commit/fa926beef29260b143f941f07dc00f1f77b4ffc5))
- Release - ([4c58bd8](https://github.com/n0-computer/iroh/commit/4c58bd8db5c90567ec3ffae9f19474887d037445))

## [0.27.0](https://github.com/n0-computer/iroh/compare/v0.26.0..v0.27.0) - 2024-10-21

### ⛰️  Features

- *(iroh-net)* Export the Ticket trait ([#2765](https://github.com/n0-computer/iroh/issues/2765)) - ([e9f98a6](https://github.com/n0-computer/iroh/commit/e9f98a65ff7a711db149940a5b443f9104714ff3))
- *(iroh-net)* [**breaking**] Allow using a NodeId directly in connect. ([#2774](https://github.com/n0-computer/iroh/issues/2774)) - ([bd5e4fa](https://github.com/n0-computer/iroh/commit/bd5e4fa1aabd186985ff5811d0f8830469aeb0de))
- *(iroh-net)* Log the crate version number ([#2746](https://github.com/n0-computer/iroh/issues/2746)) - ([12f74e2](https://github.com/n0-computer/iroh/commit/12f74e2a9a547498076ba22f3d92001549e3ad53))
- *(iroh-net)* Add helper fn to enable n0 discovery publishing and resolving ([#2775](https://github.com/n0-computer/iroh/issues/2775)) - ([ed903ae](https://github.com/n0-computer/iroh/commit/ed903ae0b5b5496aa2793e256843fec84dab81d2))

### 🐛 Bug Fixes

- *(cfg)* [**breaking**] Make sure we use correct relays ([#2778](https://github.com/n0-computer/iroh/issues/2778)) - ([844b146](https://github.com/n0-computer/iroh/commit/844b1469bab5d5f33b7de56b3d3d979ed73ae3ca))
- *(ci)* Add cleanup workflow to retain `generated-docs-preview` for only the last 25 PRs ([#2758](https://github.com/n0-computer/iroh/issues/2758)) - ([8420674](https://github.com/n0-computer/iroh/commit/8420674b32d10c6be1028515ea13027dc93800ca))
- *(ci)* Netsim commenting fixes ([#2766](https://github.com/n0-computer/iroh/issues/2766)) - ([97be9e3](https://github.com/n0-computer/iroh/commit/97be9e39770eea62971bbc2d20bd92db982cbe23))
- *(ci)* Netsim does not interact with PR comments on forks ([#2777](https://github.com/n0-computer/iroh/issues/2777)) - ([9902b2d](https://github.com/n0-computer/iroh/commit/9902b2d9f1b92c3684d8ecc24da3b899dd702498))
- *(ci)* Make sure logs get uploaded on netsim failure ([#2807](https://github.com/n0-computer/iroh/issues/2807)) - ([1436389](https://github.com/n0-computer/iroh/commit/14363891777e9857a7f6e0fd90a284f5a50d5fd9))
- *(deps)* Update postcard to get rid of yanked critical-section ([#2810](https://github.com/n0-computer/iroh/issues/2810)) - ([62e4bd4](https://github.com/n0-computer/iroh/commit/62e4bd4d8306b2810f8fe815c09ff24fb539576d))
- *(iroh-net)* Keep the relay connection alive on read errors ([#2782](https://github.com/n0-computer/iroh/issues/2782)) - ([383f1f9](https://github.com/n0-computer/iroh/commit/383f1f9cb37841da24c9722beaabcea5b440c159))
- *(iroh-net)* Emit the call-me-maybe.sent event in all cases ([#2792](https://github.com/n0-computer/iroh/issues/2792)) - ([43f5fed](https://github.com/n0-computer/iroh/commit/43f5fed7e12e7b8133964baa2d147ee77e06d571))
- *(iroh-net)* Use `try_send` rather than `send` so we dont block the local swarm discovery service ([#2794](https://github.com/n0-computer/iroh/issues/2794)) - ([2d04306](https://github.com/n0-computer/iroh/commit/2d04306a518f060bdaa7adfb42630ae01e04e093))
- *(iroh-net)* [**breaking**] DiscoveredDirectAddrs need to update the timestamp ([#2808](https://github.com/n0-computer/iroh/issues/2808)) - ([85bd8b7](https://github.com/n0-computer/iroh/commit/85bd8b7ef0e1029608bb4a87ac8c4f2fa442753c))

### 🚜 Refactor

- *(iroh-base)* [**breaking**] No Result for creating new NodeTicket ([#2771](https://github.com/n0-computer/iroh/issues/2771)) - ([f536789](https://github.com/n0-computer/iroh/commit/f53678938577985dbc13a346ac0543afaddc8745))
- *(iroh-net)* Log the pkarr relay when publishing ([#2770](https://github.com/n0-computer/iroh/issues/2770)) - ([d514859](https://github.com/n0-computer/iroh/commit/d514859ff2340b20acf4671aa3c90aba89f7b010))
- *(iroh-net)* Add tracing span context to spawned tasks ([#2769](https://github.com/n0-computer/iroh/issues/2769)) - ([66549bf](https://github.com/n0-computer/iroh/commit/66549bf5accb196e75a07784c3914c25a392cf10))
- *(iroh-net)* Keep connection name, remove connection count ([#2779](https://github.com/n0-computer/iroh/issues/2779)) - ([6b1186f](https://github.com/n0-computer/iroh/commit/6b1186fe1635f9243bf0ee45a43434b9ce927ba0))
- *(iroh-net)* Optimise present nodes in ActiveRelay ([#2781](https://github.com/n0-computer/iroh/issues/2781)) - ([c7ac982](https://github.com/n0-computer/iroh/commit/c7ac982bd6cab52fbb23d2d3115bc687cab5325a))
- *(iroh-net)* Failing to bind is not a Warning log ([#2815](https://github.com/n0-computer/iroh/issues/2815)) - ([f08011a](https://github.com/n0-computer/iroh/commit/f08011a55953577188333a28b2fead870a176f77))
- *(iroh-net)* Attach Relay URL to a connecting client span ([#2817](https://github.com/n0-computer/iroh/issues/2817)) - ([a0ce00e](https://github.com/n0-computer/iroh/commit/a0ce00e1668d40f52c211db6d53281bc68937429))
- *(iroh-net)* No portmapper is not a warning ([#2816](https://github.com/n0-computer/iroh/issues/2816)) - ([f32f3f9](https://github.com/n0-computer/iroh/commit/f32f3f9e47528ffe272c03552bff07d632dbcd15))
- *(iroh-net)* Debug logging should not be per packet set ([#2818](https://github.com/n0-computer/iroh/issues/2818)) - ([c82ada5](https://github.com/n0-computer/iroh/commit/c82ada5781e04241b888d141e80d16616cee40ed))
- Display the socket addr and relay for a `ConnectionType::Mixed` ([#2793](https://github.com/n0-computer/iroh/issues/2793)) - ([c349c43](https://github.com/n0-computer/iroh/commit/c349c435f82494cf640fdea0d2026588d26e7f15))

### 📚 Documentation

- *(*)* Document cargo features in docs ([#2761](https://github.com/n0-computer/iroh/issues/2761)) - ([4d41a69](https://github.com/n0-computer/iroh/commit/4d41a6951114e0c509fdb551080f05169ea5a92e))
- *(iroh)* Enable iroh_docsrs feature ([#2780](https://github.com/n0-computer/iroh/issues/2780)) - ([234a856](https://github.com/n0-computer/iroh/commit/234a856eb528ba5f73fb61e21d6d7f95db7dc20d))
- *(iroh-base)* Clarify AddrInfoOptions a little ([#2813](https://github.com/n0-computer/iroh/issues/2813)) - ([a36970a](https://github.com/n0-computer/iroh/commit/a36970a921d7a061c97b15c0dace0f28d2528ddf))
- *(iroh-net)* Add examples to discovery ([#2786](https://github.com/n0-computer/iroh/issues/2786)) - ([ab3afef](https://github.com/n0-computer/iroh/commit/ab3afef7031c976aa3251fd63ec57d68dd28522b))
- *(iroh-net)* Add examples to the module docs ([#2785](https://github.com/n0-computer/iroh/issues/2785)) - ([39d4bd9](https://github.com/n0-computer/iroh/commit/39d4bd9c757da0dc7005f97b5c3d588532f48c42))
- *(iroh-net)* Some more example tweaking ([#2811](https://github.com/n0-computer/iroh/issues/2811)) - ([af8c474](https://github.com/n0-computer/iroh/commit/af8c474819c3a2878a86ce145d351d7c9e42f4e7))
- *(iroh-net)* Document cfg(test) items as well ([#2819](https://github.com/n0-computer/iroh/issues/2819)) - ([a03a08e](https://github.com/n0-computer/iroh/commit/a03a08ef71628cb6b013d30872622a0f9c82ed0a))
- *(relay)* Fix typos in map.rs ([#2773](https://github.com/n0-computer/iroh/issues/2773)) - ([73ca58a](https://github.com/n0-computer/iroh/commit/73ca58ad6011aeb2758dda548bd20f3669f4ceac))

### 🧪 Testing

- *(iroh)* Mark test_blob_delete_mem as flaky ([#2784](https://github.com/n0-computer/iroh/issues/2784)) - ([730f717](https://github.com/n0-computer/iroh/commit/730f71736e863c9f310960f29c971dc5afdea1e2))

### ⚙️ Miscellaneous Tasks

- *(iroh-net)* Upgrade igd-next, remove hyper 0.14 ([#2804](https://github.com/n0-computer/iroh/issues/2804)) - ([5e40fe1](https://github.com/n0-computer/iroh/commit/5e40fe138f9581a195d47c251992e3de8b1ec8c1))
- Format imports using rustfmt ([#2812](https://github.com/n0-computer/iroh/issues/2812)) - ([8808a36](https://github.com/n0-computer/iroh/commit/8808a360c9f8299984a7e5a739fa9377eeffe73a))
- Increase version numbers and update ([#2821](https://github.com/n0-computer/iroh/issues/2821)) - ([71b5903](https://github.com/n0-computer/iroh/commit/71b5903e2840daafcfb972df3e481b152bbbe990))
- Release - ([3f5b778](https://github.com/n0-computer/iroh/commit/3f5b778b379529f9f11deeafaf1f612b533b5c94))

### Deps

- *(*)* Update futures-util ([#2790](https://github.com/n0-computer/iroh/issues/2790)) - ([75d8019](https://github.com/n0-computer/iroh/commit/75d801933cb657bf5c0817c53366c123bfdc1e83))

## [0.26.0](https://github.com/n0-computer/iroh/compare/v0.25.0..v0.26.0) - 2024-09-30

### ⛰️  Features

- *(iroh)* Disable docs by default ([#2748](https://github.com/n0-computer/iroh/issues/2748)) - ([eb4c4a6](https://github.com/n0-computer/iroh/commit/eb4c4a6beb750c1b4a10b7df90d302e44b4f9375))
- *(iroh)* [**breaking**] Make blobs::read_at more flexible ([#2756](https://github.com/n0-computer/iroh/issues/2756)) - ([33dc559](https://github.com/n0-computer/iroh/commit/33dc559a524f9cced551c01f3192579b07cf12d2))
- *(iroh)* Allow setting a custom `quinn::TransportConfig` ([#2760](https://github.com/n0-computer/iroh/issues/2760)) - ([253f4f1](https://github.com/n0-computer/iroh/commit/253f4f1099baac690ea9854f541451a2936eb00d))
- *(iroh-cli)* Improve ergonomics of `iroh gossip subscribe` CLI cmd ([#2751](https://github.com/n0-computer/iroh/issues/2751)) - ([90fd6f0](https://github.com/n0-computer/iroh/commit/90fd6f04ec62305a6507cb29bc388b1583f3c5f0))
- Set derive_more to 1.0.0 (no beta!) ([#2736](https://github.com/n0-computer/iroh/issues/2736)) - ([2d863a9](https://github.com/n0-computer/iroh/commit/2d863a94cc19faab860e85b164abf47a8669cfa9))

### 🐛 Bug Fixes

- *(ci)* Make netsim work on forks ([#2757](https://github.com/n0-computer/iroh/issues/2757)) - ([0953263](https://github.com/n0-computer/iroh/commit/09532632b3d3b8f16b8ef175e84fe8e8821bb21a))
- *(examples)* Make `collection-provide`, `hello-world-provide` and `rpc` work again ([#2749](https://github.com/n0-computer/iroh/issues/2749)) - ([25c8305](https://github.com/n0-computer/iroh/commit/25c830574d54652a772cffd7d29e3fb386d37c25))
- *(iroh-blobs)* Preserve tracing subscriber in the LocalPool ([#2735](https://github.com/n0-computer/iroh/issues/2735)) - ([5dd8bd3](https://github.com/n0-computer/iroh/commit/5dd8bd394422c80b7737fa00d92be3347924d311))
- *(iroh-blobs)* Remove debugging logs & more cleanup ([#2690](https://github.com/n0-computer/iroh/issues/2690)) - ([857e513](https://github.com/n0-computer/iroh/commit/857e51313499caceb0ad16663170cefe69f136a7))
- *(iroh-net)* Clear the recent pong time when pong is lost ([#2743](https://github.com/n0-computer/iroh/issues/2743)) - ([8fb92f3](https://github.com/n0-computer/iroh/commit/8fb92f3e88a0e69fb631bc5ac297eb62ffa73c62))

### 🚜 Refactor

- *(ci)* Redo netsim CI ([#2737](https://github.com/n0-computer/iroh/issues/2737)) - ([443139d](https://github.com/n0-computer/iroh/commit/443139d4b6db87c35200e6db495da9a3a84e5cbf))
- *(iroh-net)* Various logging improvements ([#2744](https://github.com/n0-computer/iroh/issues/2744)) - ([2262fd5](https://github.com/n0-computer/iroh/commit/2262fd57271e42efeb88badffdd208dadc387bb0))
- *(iroh-net)* Remove PathState::recent_pong() ([#2745](https://github.com/n0-computer/iroh/issues/2745)) - ([cafdc08](https://github.com/n0-computer/iroh/commit/cafdc08354c4fea31376a116a5e5ff4b51e8ab9a))

### 📚 Documentation

- *(iroh-net)* Document default relay servers a bit more ([#2740](https://github.com/n0-computer/iroh/issues/2740)) - ([10025bd](https://github.com/n0-computer/iroh/commit/10025bd3e3dd6b7d22c17e22c60994e03571d14e))
- *(iroh-net)* Improve last_pong field docs ([#2747](https://github.com/n0-computer/iroh/issues/2747)) - ([19c8fd3](https://github.com/n0-computer/iroh/commit/19c8fd327ff60ed4395cc3557f3dafa93a4a744c))
- *(iroh-net)* Improve pkarr discovery docs ([#2722](https://github.com/n0-computer/iroh/issues/2722)) - ([a0a8d56](https://github.com/n0-computer/iroh/commit/a0a8d56963f965d7b73a880946dfc5a6daafa7f9))
- *(iroh-net)* Document cargo features needed for APIs ([#2759](https://github.com/n0-computer/iroh/issues/2759)) - ([5d92f49](https://github.com/n0-computer/iroh/commit/5d92f49891c0c9ce52d5f64ed990655f85392b2b))

### ⚙️ Miscellaneous Tasks

- Release - ([01c2bac](https://github.com/n0-computer/iroh/commit/01c2bac57c0814400b79848df06c7be91cf26eea))

## [0.25.0](https://github.com/n0-computer/iroh/compare/v0.24.0..v0.25.0) - 2024-09-16

### ⛰️  Features

- *(iroh-base)* Implement `From` & `Into` between `NodeAddr` and `NodeTicket` ([#2717](https://github.com/n0-computer/iroh/issues/2717)) - ([8a4bb09](https://github.com/n0-computer/iroh/commit/8a4bb09d6367e6a8e8daa2e269df9fd23140d6b2))
- Allow to bind to a specific address ([#2694](https://github.com/n0-computer/iroh/issues/2694)) - ([2e5188a](https://github.com/n0-computer/iroh/commit/2e5188a1f350a4d277d43ed747b9856305ffb285))

### 🐛 Bug Fixes

- *(ci)* Fix docker builds on release & release rebuilds ([#2712](https://github.com/n0-computer/iroh/issues/2712)) - ([21d75c7](https://github.com/n0-computer/iroh/commit/21d75c75eb831f812bcb4e9ecf1e9b4bdddf059b))
- *(iroh)* Handle out of bounds requests for blobs read_at ([#2729](https://github.com/n0-computer/iroh/issues/2729)) - ([28cf153](https://github.com/n0-computer/iroh/commit/28cf153e729e7d4e9fc8ff27d61bbca6763b6e9f))
- *(iroh-blobs)* Unconditionally delete blobs ([#2692](https://github.com/n0-computer/iroh/issues/2692)) - ([567577d](https://github.com/n0-computer/iroh/commit/567577d339f05b0100790977c8b2e90e3e20f4e8))
- *(iroh-net)* Fix a hot-loop when the probes time out ([#2699](https://github.com/n0-computer/iroh/issues/2699)) - ([874030a](https://github.com/n0-computer/iroh/commit/874030a374632f1e4e482e94a04674021ea3db24))
- Put `--with-relay` feature in iroh-net bench behind `local-relay` feature flag ([#2700](https://github.com/n0-computer/iroh/issues/2700)) - ([b8c0513](https://github.com/n0-computer/iroh/commit/b8c051303be45d3c832b7893de8b72aa9f50c9ce))

### 🚜 Refactor

- *(iroh)* Remove custom impl of `SharedAbortingJoinHandle` ([#2715](https://github.com/n0-computer/iroh/issues/2715)) - ([098b11f](https://github.com/n0-computer/iroh/commit/098b11f81e28a7de4d43e9b1066c4f993b85c815))
- *(iroh-gossip)* Make use of Endpoint::direct_addresses in iroh_gossip::net ([#2731](https://github.com/n0-computer/iroh/issues/2731)) - ([9583729](https://github.com/n0-computer/iroh/commit/9583729420a74dfd80cbcc88a9e23f4ddf7662d3))
- *(iroh-net)* [**breaking**] Make netcheck::Client !Clone ([#2716](https://github.com/n0-computer/iroh/issues/2716)) - ([ce2cfee](https://github.com/n0-computer/iroh/commit/ce2cfee00677fb0b17d1cc213e834cc273f6a1b8))
- [**breaking**] Migrate to tokio's AbortOnDropHandle ([#2701](https://github.com/n0-computer/iroh/issues/2701)) - ([35e9873](https://github.com/n0-computer/iroh/commit/35e9873901297a49434d1e8043e12e3a78ae5c72))

### 📚 Documentation

- *(iroh-cli)* Add docs to entrypoint ([#2697](https://github.com/n0-computer/iroh/issues/2697)) - ([c6e2f05](https://github.com/n0-computer/iroh/commit/c6e2f05e3ab8b7afbb8b8d6de77f975503ef3c46))
- *(iroh-cli)* Udpate `doctor` command documentation ([#2710](https://github.com/n0-computer/iroh/issues/2710)) - ([93b400a](https://github.com/n0-computer/iroh/commit/93b400a067dd31b97a3e8367fe7f224d7c9306c8))
- *(iroh-cli)* Update `authors` command documentation ([#2702](https://github.com/n0-computer/iroh/issues/2702)) - ([2c199a0](https://github.com/n0-computer/iroh/commit/2c199a02e8a02769565d183130dc17134c98574b))
- *(iroh-cli)* Update `console` command documentation ([#2705](https://github.com/n0-computer/iroh/issues/2705)) - ([4964ee3](https://github.com/n0-computer/iroh/commit/4964ee3652ace5748cb5358b48041c362acd5be2))
- *(iroh-cli)* Update `net` command documentation ([#2707](https://github.com/n0-computer/iroh/issues/2707)) - ([8c321a2](https://github.com/n0-computer/iroh/commit/8c321a2a482989291fe98a69a4f312dac94df8b7))
- *(iroh-cli)* Update `start` command documentation ([#2708](https://github.com/n0-computer/iroh/issues/2708)) - ([2636be8](https://github.com/n0-computer/iroh/commit/2636be85869f8f760d69e991f61a4c9d88765112))
- *(iroh-cli)* Update `rpc` command documentation ([#2711](https://github.com/n0-computer/iroh/issues/2711)) - ([518d439](https://github.com/n0-computer/iroh/commit/518d439684e0f4f1f17471b1b0a7a93839678ec2))
- *(iroh-cli)* Update `gossip` command documentation ([#2706](https://github.com/n0-computer/iroh/issues/2706)) - ([bdaeba1](https://github.com/n0-computer/iroh/commit/bdaeba1b966922ea0d3ef5ce15d618b1af6e27e8))
- *(iroh-cli)* Update `tags` command documentation ([#2709](https://github.com/n0-computer/iroh/issues/2709)) - ([7510a59](https://github.com/n0-computer/iroh/commit/7510a59b879856098d7165b221c4076c6f885ea9))
- *(iroh-cli)* Update `blobs` command documentation ([#2704](https://github.com/n0-computer/iroh/issues/2704)) - ([76b1473](https://github.com/n0-computer/iroh/commit/76b1473d373c5333fd9263361dca31b306577127))
- *(iroh-cli)* Update `docs` command documentation ([#2703](https://github.com/n0-computer/iroh/issues/2703)) - ([7b6c974](https://github.com/n0-computer/iroh/commit/7b6c974022777bfa6ea49e799bca2e401124b159))
- *(iroh-cli)* Fix typo ([#2718](https://github.com/n0-computer/iroh/issues/2718)) - ([d2ecbdb](https://github.com/n0-computer/iroh/commit/d2ecbdbf7f26bfc224f797571c2bdefd6fdadbdf))

### ⚙️ Miscellaneous Tasks

- *(ci)* Move mac builds over to arm box ([#2675](https://github.com/n0-computer/iroh/issues/2675)) - ([1df0813](https://github.com/n0-computer/iroh/commit/1df08132744c61bb30d5bb5611263b871616f5fa))
- *(iroh-net)* Remove direct dependency on rand_core ([#2719](https://github.com/n0-computer/iroh/issues/2719)) - ([b6a64e0](https://github.com/n0-computer/iroh/commit/b6a64e0764b2973497ee989910d2930ced3160f5))
- Fix clippy@1.81.0 and cargo deny ([#2714](https://github.com/n0-computer/iroh/issues/2714)) - ([52422cd](https://github.com/n0-computer/iroh/commit/52422cdb228e060c136d87b350fa9cfd35961b76))
- Remove double spellchecks ([#2720](https://github.com/n0-computer/iroh/issues/2720)) - ([a733143](https://github.com/n0-computer/iroh/commit/a73314385084ae4e72e15bc15469991e139763ec))
- Release - ([285101e](https://github.com/n0-computer/iroh/commit/285101eec876fe48a1bda3fa43ff5c2c5c6ef568))

## [0.24.0](https://github.com/n0-computer/iroh/compare/v0.23.0..v0.24.0) - 2024-09-02

### ⛰️  Features

- *(bench)* Add `--with-relay` option to allow testing relay throughput ([#2664](https://github.com/n0-computer/iroh/issues/2664)) - ([5c09013](https://github.com/n0-computer/iroh/commit/5c090134227929bb978d7f16fe33c74125f25e56))
- *(bench)* Add `--metrics` option printing iroh-net library metrics ([#2668](https://github.com/n0-computer/iroh/issues/2668)) - ([4f83c43](https://github.com/n0-computer/iroh/commit/4f83c43824eea7be3619f235f8944d228eaa79cc))
- *(iroh-net)* [**breaking**] Upgrade to Quinn 0.11 and Rustls 0.23 ([#2595](https://github.com/n0-computer/iroh/issues/2595)) - ([34ec5e2](https://github.com/n0-computer/iroh/commit/34ec5e24b9cdae751a7fae8f9d14fb6fa77482f1))

### 🐛 Bug Fixes

- *(iroh-blobs)* Demote `warn!` to `trace!` logs ([#2689](https://github.com/n0-computer/iroh/issues/2689)) - ([6181455](https://github.com/n0-computer/iroh/commit/6181455e32d4e9f69430d89a7cb70bb622a5c29d))
- *(iroh-blobs)* Turn `println!` into `tracing::debug!` ([#2686](https://github.com/n0-computer/iroh/issues/2686)) - ([5bbcb60](https://github.com/n0-computer/iroh/commit/5bbcb60838217ce2deaaeba259a1e6a56edf88bb))
- *(iroh-blobs)* Timeout based on correct `max_write_duration` option ([#2688](https://github.com/n0-computer/iroh/issues/2688)) - ([2347565](https://github.com/n0-computer/iroh/commit/23475650e63178efd677e357737fa3972ef16ab9))
- *(iroh-net)* Document the keylog environment variable correctly ([#2655](https://github.com/n0-computer/iroh/issues/2655)) - ([c70caaf](https://github.com/n0-computer/iroh/commit/c70caaf48ac39fcfb3b971366a76bff37b493ee9))
- *(iroh-net)* Magic sock `recv_data_ipv4` and `recv_data_ipv6` metrics numbers ([#2667](https://github.com/n0-computer/iroh/issues/2667)) - ([cb1650a](https://github.com/n0-computer/iroh/commit/cb1650a5ebea2b27a3130b038159f7e04448c1ff))
- *(iroh-net)* Also check the last packet in `MagicSock::poll_recv` ([#2650](https://github.com/n0-computer/iroh/issues/2650)) - ([54ca9c9](https://github.com/n0-computer/iroh/commit/54ca9c942fa7ce6e43825d1374483a049f4d4c13))
- *(iroh-net)* Reduce noise in swarm discovery due to republish ([#2685](https://github.com/n0-computer/iroh/issues/2685)) - ([fd56763](https://github.com/n0-computer/iroh/commit/fd56763352bc2cc308234068ddd7bf0a2767c782))
- Docker CI performance & release builds ([#2659](https://github.com/n0-computer/iroh/issues/2659)) - ([d567231](https://github.com/n0-computer/iroh/commit/d5672319d776789191c6e5b7076fea464d4f1208))

### 🚜 Refactor

- *(iroh, iroh-blobs, iroh-net)* [**breaking**] Remove deprecated items ([#2652](https://github.com/n0-computer/iroh/issues/2652)) - ([060bf83](https://github.com/n0-computer/iroh/commit/060bf8326d3d26b719c8e518c22708af4c20040b))

### 🧪 Testing

- *(iroh-gossip)* Wait for the relay to make `gossip_net_smoke` faster. ([#2663](https://github.com/n0-computer/iroh/issues/2663)) - ([1d3f3fa](https://github.com/n0-computer/iroh/commit/1d3f3fa8125761df509b94621eb173b91ed42904))

### ⚙️ Miscellaneous Tasks

- *(iroh-net)* Do not add the NodeId in the magicsock span field ([#2679](https://github.com/n0-computer/iroh/issues/2679)) - ([05fff6a](https://github.com/n0-computer/iroh/commit/05fff6a11d9afd181a59e119a5aa98d5304d3f58))
- Release - ([a029d89](https://github.com/n0-computer/iroh/commit/a029d89a2b9cb1d04eba054960114801b755b582))

### Deps

- *(iroh-gossip)* Do not depend directly on Quinn ([#2678](https://github.com/n0-computer/iroh/issues/2678)) - ([6296964](https://github.com/n0-computer/iroh/commit/6296964a596719afac3e734296be9fbbd6162d51))

## [0.23.0](https://github.com/n0-computer/iroh/compare/v0.22.0..v0.23.0) - 2024-08-20

### ⛰️  Features

- *(ci)* Notify discord of successfull flaky runs ([#2623](https://github.com/n0-computer/iroh/issues/2623)) - ([94cee34](https://github.com/n0-computer/iroh/commit/94cee34cefa0dc44d77d302c4d8963df1294b5c4))
- *(iroh)* [**breaking**] Blob batch PR, attempt 3 ([#2545](https://github.com/n0-computer/iroh/issues/2545)) - ([9a55122](https://github.com/n0-computer/iroh/commit/9a55122c9772aadd16c7bda22d83177b4bc74b1d))
- *(iroh-blobs)* Add outboard creation progress to the mem store ([#2625](https://github.com/n0-computer/iroh/issues/2625)) - ([47c8528](https://github.com/n0-computer/iroh/commit/47c8528b9e14c5121ba7eb69289d03ef0b8a168a))
- *(iroh-net)* Upgrade to new `swarm-discovery` api ([#2605](https://github.com/n0-computer/iroh/issues/2605)) - ([a9c96a9](https://github.com/n0-computer/iroh/commit/a9c96a92fe7d2bb0f92f574b9c5b78e6f27316cf))
- *(iroh-net)* Add PkarrNodeDiscovery to iroh-net ([#2628](https://github.com/n0-computer/iroh/issues/2628)) - ([9facd5a](https://github.com/n0-computer/iroh/commit/9facd5a333b545c7b036e6f7ce13a150e6aca492))
- *(iroh-net)* Allow customizing republish delay for the pkarr publisher ([#2637](https://github.com/n0-computer/iroh/issues/2637)) - ([134dbee](https://github.com/n0-computer/iroh/commit/134dbeedc7242a8de57707c920bcedf7b12a6130))
- Allow custom blob providing event handling ([#2583](https://github.com/n0-computer/iroh/issues/2583)) - ([bcc87a2](https://github.com/n0-computer/iroh/commit/bcc87a24c722362358c68251749b52eeaca31b53))

### 🐛 Bug Fixes

- *(ci)* Report flaky outupt only on success and failure ([#2627](https://github.com/n0-computer/iroh/issues/2627)) - ([8b6245e](https://github.com/n0-computer/iroh/commit/8b6245e3356df2e525a37512a44228ab52c864a9))
- *(iroh-blobs)* Do not skip empty partial blobs in migration ([#2604](https://github.com/n0-computer/iroh/issues/2604)) - ([1c86dac](https://github.com/n0-computer/iroh/commit/1c86dace54e243f9d1a65634bf1bfc385d573236))
- *(iroh-cli)* `cli_provide_addresses` to use the correct `iroh status` command ([#2649](https://github.com/n0-computer/iroh/issues/2649)) - ([717b3cd](https://github.com/n0-computer/iroh/commit/717b3cdd52be5cb0e71217e2097e8c5ec8162daf))
- *(iroh-gossip)* Clarify docs and semantics of gossip joined event ([#2597](https://github.com/n0-computer/iroh/issues/2597)) - ([5d98a5c](https://github.com/n0-computer/iroh/commit/5d98a5cb8194be58aff995a6aa463c36571d5399))
- *(tests)* For DNS discovery only use a local DNS server ([#2598](https://github.com/n0-computer/iroh/issues/2598)) - ([5eee643](https://github.com/n0-computer/iroh/commit/5eee643e8b52b40c7a48e41de2f9867403b30d79))

### 🚜 Refactor

- *(iroh)* [**breaking**] Convert node to net module ([#2642](https://github.com/n0-computer/iroh/issues/2642)) - ([6354e04](https://github.com/n0-computer/iroh/commit/6354e04f348dc4e0cc57411c0193880225d56141))
- *(iroh,iroh-net)* [**breaking**] Prefer `remote` to `connection` in api ([#2610](https://github.com/n0-computer/iroh/issues/2610)) - ([9d06888](https://github.com/n0-computer/iroh/commit/9d068886f1c16d6a47ac3ce1c454369b00cd6de7))
- *(iroh-blobs)* Use oneshot channel from oneshot crate ([#2624](https://github.com/n0-computer/iroh/issues/2624)) - ([2e01d47](https://github.com/n0-computer/iroh/commit/2e01d47e7b2d34341a9a23614bada43d54ab155f))
- *(iroh-blobs)* [**breaking**] Expand docs ([#2638](https://github.com/n0-computer/iroh/issues/2638)) - ([217ac06](https://github.com/n0-computer/iroh/commit/217ac06b2128af9721ed6780a6bb2f0092a46ace))
- *(iroh-blobs, iroh)* [**breaking**] Deprecate flat stores ([#2629](https://github.com/n0-computer/iroh/issues/2629)) - ([168fa5b](https://github.com/n0-computer/iroh/commit/168fa5b1e745576dc98f3f8c77fbc685126098ae))
- *(iroh-bytes)* [**breaking**] Remove flume dependency ([#2622](https://github.com/n0-computer/iroh/issues/2622)) - ([e9c5088](https://github.com/n0-computer/iroh/commit/e9c5088c60862368113fe117d4a1d47d20b7c4ba))
- *(iroh-cli)* [**breaking**] Metrics-addr cli arg, metrics off by default ([#2631](https://github.com/n0-computer/iroh/issues/2631)) - ([4df1c91](https://github.com/n0-computer/iroh/commit/4df1c91f4ddd66f680145b5656e3fb61b3faa4a7))
- *(iroh-net)* [**breaking**] Remove async channel ([#2620](https://github.com/n0-computer/iroh/issues/2620)) - ([74a527b](https://github.com/n0-computer/iroh/commit/74a527b9699e5da06c0b85bcb32a873397906472))
- *(iroh-net)* [**breaking**] Rename the local-swarm-discovery feature to discovery-local-network ([#2634](https://github.com/n0-computer/iroh/issues/2634)) - ([d1578ee](https://github.com/n0-computer/iroh/commit/d1578ee832da8f39efac1e916914557b9d219cde))
- *(iroh-net)* Move all timeouts into one file ([#2641](https://github.com/n0-computer/iroh/issues/2641)) - ([bb808b4](https://github.com/n0-computer/iroh/commit/bb808b45b9c3041454c0f8497f3ed566154e1edf))
- *(iroh-net,iroh)* Rename to remote_info_iter, fixup some docs ([#2645](https://github.com/n0-computer/iroh/issues/2645)) - ([b17bf1d](https://github.com/n0-computer/iroh/commit/b17bf1d55185cc9469719f02e6df7e174235a901))
- Normalize feature names ([#2633](https://github.com/n0-computer/iroh/issues/2633)) - ([d02c21f](https://github.com/n0-computer/iroh/commit/d02c21f50f90e42a872ccf3f1b445723e22a5c1a))

### 📚 Documentation

- *(iroh-cli)* Fix help text for incomplete blobs ([#2615](https://github.com/n0-computer/iroh/issues/2615)) - ([ceb94da](https://github.com/n0-computer/iroh/commit/ceb94dab985400958da8f9902c6bde4ef5ccdc7c))
- Also list `iroh-gossip` as a re-export ([#2606](https://github.com/n0-computer/iroh/issues/2606)) - ([3b7881c](https://github.com/n0-computer/iroh/commit/3b7881cccbd0b8fe09317695bd4c4808608cb149))

### 🧪 Testing

- *(iroh)* Reduce entry amount in `sync_gossip_bulk` ([#2608](https://github.com/n0-computer/iroh/issues/2608)) - ([a2d2ec6](https://github.com/n0-computer/iroh/commit/a2d2ec69e327da09b32e0e90a148d371e37d4f3a))
- *(iroh)* Re-enable some flaky tests to see if they are still flaky ([#2458](https://github.com/n0-computer/iroh/issues/2458)) - ([b8f2b3f](https://github.com/n0-computer/iroh/commit/b8f2b3f4eb16d7f47020ef17f0fc7917ca1f7ee1))
- *(iroh-cli)* Replace `cli_provide_one_file_large` with a faster test ([#2607](https://github.com/n0-computer/iroh/issues/2607)) - ([7494566](https://github.com/n0-computer/iroh/commit/7494566ef2da183f49b8d8e8418a33bebfb03bb0))

### ⚙️ Miscellaneous Tasks

- *(ci)* Use nextests groups to isolate some tests ([#2617](https://github.com/n0-computer/iroh/issues/2617)) - ([a5072c3](https://github.com/n0-computer/iroh/commit/a5072c3a0a11d931b3fc4e95ac48c32f12959a5b))
- Fix deps issues ([#2643](https://github.com/n0-computer/iroh/issues/2643)) - ([83f6fcc](https://github.com/n0-computer/iroh/commit/83f6fccc2c0de6db47daded6af206ea59711ec99))
- Release - ([855e1bb](https://github.com/n0-computer/iroh/commit/855e1bbdd2cf1fbf7a7af421603c114ae7d9d9be))

### Ref

- *(iroh-net)* Move PathState to its own module ([#2587](https://github.com/n0-computer/iroh/issues/2587)) - ([2e937a8](https://github.com/n0-computer/iroh/commit/2e937a834d25c6ea003f6666099d73f72f3e09f3))

## [0.22.0](https://github.com/n0-computer/iroh/compare/v0.21.0..v0.22.0) - 2024-08-05

### ⛰️  Features

- *(iroh)* Improve documentation and canonicalize docs in `iroh::client` ([#2553](https://github.com/n0-computer/iroh/issues/2553)) - ([d937234](https://github.com/n0-computer/iroh/commit/d937234621791338a65338678badc35345784296))
- Override to staging relays ([#2551](https://github.com/n0-computer/iroh/issues/2551)) - ([ed4420b](https://github.com/n0-computer/iroh/commit/ed4420b5df75d4cfe3623c3e722f33a8a19449ce))

### 🐛 Bug Fixes

- *(iroh)* Do not set low max streams in builder ([#2593](https://github.com/n0-computer/iroh/issues/2593)) - ([215cd1d](https://github.com/n0-computer/iroh/commit/215cd1d8ffdc4b7fbaeceb792da981c40f59b41a))
- *(iroh-blobs)* Use async_channel instead of flume for local_pool ([#2533](https://github.com/n0-computer/iroh/issues/2533)) - ([9052905](https://github.com/n0-computer/iroh/commit/9052905d0d75d62c761139f02294d6abc1c53af6))
- *(iroh-blobs)* Do not hit the network when downloading blobs which are complete ([#2586](https://github.com/n0-computer/iroh/issues/2586)) - ([0784403](https://github.com/n0-computer/iroh/commit/07844031c3e568e34c64a825803c9cd3f91a2035))
- *(iroh-cli)* [**breaking**] Improve cli and configuration file ([#2532](https://github.com/n0-computer/iroh/issues/2532)) - ([0fc3794](https://github.com/n0-computer/iroh/commit/0fc37942be3d68399fbe45401ba7d67be43a83a6))
- *(iroh-gossip)* Connection loop misuses `tokio::select!` leading to read errors ([#2572](https://github.com/n0-computer/iroh/issues/2572)) - ([32bb0f3](https://github.com/n0-computer/iroh/commit/32bb0f3be432676ca49473e75c7eb00db32a3673))
- *(iroh-net)* Fix a compiler error with newer `derive_more` versions ([#2578](https://github.com/n0-computer/iroh/issues/2578)) - ([3f3fec5](https://github.com/n0-computer/iroh/commit/3f3fec5010a97f7d11f00b9c3eb2f05e167a1472))
- *(iroh-net)* Make a single direct address in NodeAddr instant ([#2580](https://github.com/n0-computer/iroh/issues/2580)) - ([f5b3918](https://github.com/n0-computer/iroh/commit/f5b3918b8d4a0077334980b91ca6339acaa1c55f))
- Docker image builds ([#2530](https://github.com/n0-computer/iroh/issues/2530)) - ([5c60a52](https://github.com/n0-computer/iroh/commit/5c60a52dd442525852f1b1a0b0f5fc62b463060e))
- Disable docs preview on forks ([#2558](https://github.com/n0-computer/iroh/issues/2558)) - ([741b42f](https://github.com/n0-computer/iroh/commit/741b42fa4260c94b4e80b633bffdf5add6ee24aa))
- Force CI to use staging relays ([#2560](https://github.com/n0-computer/iroh/issues/2560)) - ([ffeb1a9](https://github.com/n0-computer/iroh/commit/ffeb1a901387a56a1544ef058a86843f500eb84a))
- Pin derive_more to avoid sudden breakages ([#2584](https://github.com/n0-computer/iroh/issues/2584)) - ([1ba033c](https://github.com/n0-computer/iroh/commit/1ba033cf0cc601c7ffd4c09822190ddbb2fb8197))

### 🚜 Refactor

- *(iroh)* Remove flume from iroh gossip ([#2542](https://github.com/n0-computer/iroh/issues/2542)) - ([2964569](https://github.com/n0-computer/iroh/commit/29645698ca794d88314ff9c1117e962ec6260650))
- *(iroh)* Remove flume from iroh-cli and iroh ([#2543](https://github.com/n0-computer/iroh/issues/2543)) - ([347d45c](https://github.com/n0-computer/iroh/commit/347d45c3de3bcba878657566a67f4e1825b03bc4))
- *(iroh-docs)* Replace flume with async_channel in docs ([#2540](https://github.com/n0-computer/iroh/issues/2540)) - ([e7a7552](https://github.com/n0-computer/iroh/commit/e7a7552191b71b476cab0a75544f129e657d8dfe))
- *(iroh-net)* Replace flume in iroh-net with async_channel ([#2539](https://github.com/n0-computer/iroh/issues/2539)) - ([22314a1](https://github.com/n0-computer/iroh/commit/22314a18228799e26de8ba2c0e44b45aec3b2af4))
- *(iroh-net)* Move more server code behind `iroh-relay` feature flag ([#2566](https://github.com/n0-computer/iroh/issues/2566)) - ([1dda2f7](https://github.com/n0-computer/iroh/commit/1dda2f7ab706cf794d2c8f4e6b47b24caf2f1c78))
- *(iroh-net)* [**breaking**] Improve server modules structure & rename structs ([#2568](https://github.com/n0-computer/iroh/issues/2568)) - ([29d2e82](https://github.com/n0-computer/iroh/commit/29d2e82a577ebc8cb4029c0df0138fe662031d5c))
- *(iroh-net)* Switch to (now stable) `IpAddr::to_canonical` ([#2569](https://github.com/n0-computer/iroh/issues/2569)) - ([7fdd6cb](https://github.com/n0-computer/iroh/commit/7fdd6cb64f24c908862ccdf59fb5ca466e0b508f))

### 📚 Documentation

- *(iroh)* Add documentations and examples for the `iroh::node::Client` ([#2582](https://github.com/n0-computer/iroh/issues/2582)) - ([55836fa](https://github.com/n0-computer/iroh/commit/55836fa5ca56fe6964be52046bb0c7f77e62b647))
- *(iroh-cli)* Point to the configuration refernce from each iroh subcommand ([#2571](https://github.com/n0-computer/iroh/issues/2571)) - ([8e4e586](https://github.com/n0-computer/iroh/commit/8e4e586cece3968700a13562058f3a5c152c1805))
- Fix typos discovered by codespell ([#2534](https://github.com/n0-computer/iroh/issues/2534)) - ([8435a45](https://github.com/n0-computer/iroh/commit/8435a45e3ee273d5a8dcb083eadc333426024b8b))
- Update description in cargo.toml - ([7259ab5](https://github.com/n0-computer/iroh/commit/7259ab584d509bde8f45654700a4bd9e74e4405c))

### 🧪 Testing

- *(iroh-blobs)* Comment out ignored test (that is not a flaky test) ([#2559](https://github.com/n0-computer/iroh/issues/2559)) - ([15f36b3](https://github.com/n0-computer/iroh/commit/15f36b373ec3dc86d9a81caeef54f8a165c10001))
- *(iroh-cli)* Update to new api ([#2549](https://github.com/n0-computer/iroh/issues/2549)) - ([f97c1c0](https://github.com/n0-computer/iroh/commit/f97c1c0858161a8c0e0f64b862aaceea0035d371))
- *(iroh-cli)* Remove flaky mark from 5 tests and improve logs ([#2562](https://github.com/n0-computer/iroh/issues/2562)) - ([14fccee](https://github.com/n0-computer/iroh/commit/14fcceed53e9633402ba1b978f2002901b615ba8))
- *(iroh-cli)* Reduce flakyness of cli_provide_file_resume ([#2563](https://github.com/n0-computer/iroh/issues/2563)) - ([f085e63](https://github.com/n0-computer/iroh/commit/f085e633c82531b7d24a70703ae48a2562eccfdd))
- *(iroh-cli)* Make cli resumption tests not flaky ([#2564](https://github.com/n0-computer/iroh/issues/2564)) - ([9e6b1e0](https://github.com/n0-computer/iroh/commit/9e6b1e0897b15ea7096c95143e11e09e948c862e))
- *(iroh-net)* Increase timeout for local swarm discovery test ([#2574](https://github.com/n0-computer/iroh/issues/2574)) - ([605a85d](https://github.com/n0-computer/iroh/commit/605a85d9c121f8d2b48f91c2eb1e86cfa451bd22))

### ⚙️ Miscellaneous Tasks

- *(iroh-net)* Remove need for relay info in best_addr ([#2579](https://github.com/n0-computer/iroh/issues/2579)) - ([d662bfc](https://github.com/n0-computer/iroh/commit/d662bfc663ad956bbb38716bd5b8022a699bfce4))
- Fix clippy warnings ([#2550](https://github.com/n0-computer/iroh/issues/2550)) - ([73de21b](https://github.com/n0-computer/iroh/commit/73de21b35d6b83def03f51caca06c1931ea8ee77))
- Generate docs for each PR ([#2547](https://github.com/n0-computer/iroh/issues/2547)) - ([0812333](https://github.com/n0-computer/iroh/commit/081233357d4dbe0cabe890009d674839d9de18be))
- Release - ([d54a5de](https://github.com/n0-computer/iroh/commit/d54a5deb099754eaccd28fdb3cc8da93122f1376))

### Ref

- *(iroh-net)* Don't write the match as fully exhaustive ([#2585](https://github.com/n0-computer/iroh/issues/2585)) - ([43ef8b6](https://github.com/n0-computer/iroh/commit/43ef8b6e87048f7f28ddb4c2b97d7bf4fe853b90))

## [0.21.0](https://github.com/n0-computer/iroh/compare/v0.20.0..v0.21.0) - 2024-07-22

### ⛰️  Features

- *(ci)* Publish docker images ([#2520](https://github.com/n0-computer/iroh/issues/2520)) - ([c0fa1f4](https://github.com/n0-computer/iroh/commit/c0fa1f4e81030656ec1c89abc06aa4c4c758cf2b))
- *(iroh-cli)* [**breaking**] Realign cli commands with library ([#2522](https://github.com/n0-computer/iroh/issues/2522)) - ([4c11c58](https://github.com/n0-computer/iroh/commit/4c11c581c73fff94752ecbe2872e224594008db3))
- *(iroh-net)* Add holepunching events ([#2495](https://github.com/n0-computer/iroh/issues/2495)) - ([8685222](https://github.com/n0-computer/iroh/commit/8685222afff4817c2c76e55100228f0ee99ed18c))
- *(iroh-net)* [**breaking**] Remove fs based peers storage ([#2510](https://github.com/n0-computer/iroh/issues/2510)) - ([0a8cb8a](https://github.com/n0-computer/iroh/commit/0a8cb8ac8fd350a87a66fe119871c26232956323))
- *(iroh-net)* Update netdev to 0.30 ([#2528](https://github.com/n0-computer/iroh/issues/2528)) - ([214bb0c](https://github.com/n0-computer/iroh/commit/214bb0c484f040b747ba21d76d504b6077433da3))
- *(iroh-relay)* Add more context to iroh-relay errors ([#2506](https://github.com/n0-computer/iroh/issues/2506)) - ([04df203](https://github.com/n0-computer/iroh/commit/04df203e8b7da7d8807a86c90c8d830785370e1c))

### 🐛 Bug Fixes

- *(iroh-blobs)* Properly handle Drop in local pool during shutdown ([#2517](https://github.com/n0-computer/iroh/issues/2517)) - ([b4506b2](https://github.com/n0-computer/iroh/commit/b4506b2c4a288434ea55c36607f8fd839d58bf10))
- *(iroh-docs)* Do not dial invalid peers ([#2470](https://github.com/n0-computer/iroh/issues/2470)) - ([7579caa](https://github.com/n0-computer/iroh/commit/7579caa6bb21fd2f0fe6239bc6dc414a3015f200))
- *(iroh-metrics)* Add the bind addr in errors for bind failures ([#2511](https://github.com/n0-computer/iroh/issues/2511)) - ([50a8b5c](https://github.com/n0-computer/iroh/commit/50a8b5cd6b14a2c27c865d9a260c5a55ba5ad622))

### 🚜 Refactor

- *(iroh)* Make use of quic-rpc-derive macros to prettify the rpc declarations ([#2508](https://github.com/n0-computer/iroh/issues/2508)) - ([026baaa](https://github.com/n0-computer/iroh/commit/026baaafdf9bd89feef8db4bfedfe9d9853551f3))
- *(iroh-net)* [**breaking**] Move relay implemention in `iroh-net` behind `iroh-relay` cfg flag ([#2516](https://github.com/n0-computer/iroh/issues/2516)) - ([f37d9f9](https://github.com/n0-computer/iroh/commit/f37d9f9f339dd0de50b35a405ce203c36272a0b4))
- *(iroh-net)* Switch to new iroh-relay route `/relay` instead of `/derp` ([#2489](https://github.com/n0-computer/iroh/issues/2489)) - ([b7b493d](https://github.com/n0-computer/iroh/commit/b7b493df63b988efd8cc84a9b359be4f08bf06b3))
- *(iroh-net)* More renaming of endpoint to direct address ([#2515](https://github.com/n0-computer/iroh/issues/2515)) - ([0c03f6e](https://github.com/n0-computer/iroh/commit/0c03f6ebf79baf5f125ca47bcf5f5ce06d79f99f))
- *(iroh-net)* Remove random choice of direct addr ([#2509](https://github.com/n0-computer/iroh/issues/2509)) - ([c1c3539](https://github.com/n0-computer/iroh/commit/c1c3539c0a07d8659979ffacdb5bd1fc23d6939c))
- [**breaking**] Metrics ([#2464](https://github.com/n0-computer/iroh/issues/2464)) - ([09e9746](https://github.com/n0-computer/iroh/commit/09e974623183e8a9bafdfc25fa255ed9fd5c808f))

### 📚 Documentation

- *(iroh-net)* Fix broken HTTP/3 link ([#2485](https://github.com/n0-computer/iroh/issues/2485)) - ([a5a2324](https://github.com/n0-computer/iroh/commit/a5a232425b1f627c04b2f711ad38f9c6e4127c42))
- *(iroh-net)* Improve Endpoint::accept docs ([#2492](https://github.com/n0-computer/iroh/issues/2492)) - ([79a2768](https://github.com/n0-computer/iroh/commit/79a27682107e108817301822e9418465eb9d4a44))

### 🧪 Testing

- *(iroh-cli)* Improve `bao_store_migration` test logging ([#2483](https://github.com/n0-computer/iroh/issues/2483)) - ([d17ffa3](https://github.com/n0-computer/iroh/commit/d17ffa3e2e96a9cb10ecfc75e5c3d1a1387c0cb8))

### ⚙️ Miscellaneous Tasks

- *(bytes)* Bytes v1.6.0 was yanked so upgrade to bytes v1.6.1 ([#2503](https://github.com/n0-computer/iroh/issues/2503)) - ([ecfbed3](https://github.com/n0-computer/iroh/commit/ecfbed3d5e1bdaca36ab1ddd2ebcd01a6b286a94))
- Add a flaky tests failure report to our discord notification ([#2496](https://github.com/n0-computer/iroh/issues/2496)) - ([f84c06e](https://github.com/n0-computer/iroh/commit/f84c06eb87ed8b93b1bce71c8502732db7faeedb))
- Keep GitHub Actions up to date with GitHub's Dependabot ([#2498](https://github.com/n0-computer/iroh/issues/2498)) - ([538efbf](https://github.com/n0-computer/iroh/commit/538efbfc6575733114292ddcfdc040adb50a246c))
- Release - ([1145b34](https://github.com/n0-computer/iroh/commit/1145b34a2f8001a37bcf907626dc8ebd8dd77da4))

### Deprecation

- *(iroh)* [**breaking**] Remove deprecated type aliases ([#2467](https://github.com/n0-computer/iroh/issues/2467)) - ([0102b05](https://github.com/n0-computer/iroh/commit/0102b05e084679d909bc33e588aa4f00ebc403cf))

## [0.20.0](https://github.com/n0-computer/iroh/compare/v0.19.0..v0.20.0) - 2024-07-09

### ⛰️  Features

- *(iroh)* Add rpc request to add an AddrInfo ([#2433](https://github.com/n0-computer/iroh/issues/2433)) - ([59e2719](https://github.com/n0-computer/iroh/commit/59e2719f06d06cb813cea25cbeb731e3c770b931))
- *(iroh)* Gossip client ([#2258](https://github.com/n0-computer/iroh/issues/2258)) - ([b0d5413](https://github.com/n0-computer/iroh/commit/b0d54133cb7e0b5c256c3ca71df7377717f34f7f))
- *(iroh)* Add missing gossip reexports ([#2479](https://github.com/n0-computer/iroh/issues/2479)) - ([af36c2f](https://github.com/n0-computer/iroh/commit/af36c2fa3b74878a199a181e2cb480debc4c9883))
- *(iroh-net)* Implement `websocket` protocol upgrade in iroh-relay ([#2387](https://github.com/n0-computer/iroh/issues/2387)) - ([17c654e](https://github.com/n0-computer/iroh/commit/17c654e59cc2069522a66b87355f52342b837b8c))
- *(iroh-net)* [**breaking**] Make relay protocol configurable on `ClientBuilder` instead of defined by the relay url scheme ([#2446](https://github.com/n0-computer/iroh/issues/2446)) - ([ab2c7ea](https://github.com/n0-computer/iroh/commit/ab2c7eaa2a44c53e8b8dcabeb34a80e30d1a6d42))
- *(iroh-net)* [**breaking**] Add PkarrResolver and publish direct addresses in PkarrPublisher when relay is disabled ([#2417](https://github.com/n0-computer/iroh/issues/2417)) - ([5ba6855](https://github.com/n0-computer/iroh/commit/5ba6855e4eef8c04df3eb040455b35101d66561c))
- *(iroh-net)* Local swarm discovery ([#2376](https://github.com/n0-computer/iroh/issues/2376)) - ([3866b6f](https://github.com/n0-computer/iroh/commit/3866b6f7d65238d56fd15be3e94e3e5f019ac3c2))
- [**breaking**] Split relay configuration between production and staging ([#2425](https://github.com/n0-computer/iroh/issues/2425)) - ([d421ece](https://github.com/n0-computer/iroh/commit/d421eceb485b7052688c2e2f0df1e8d7add58cf7))
- Add Asia Pacific relay url to the default relay url list in production ([#2469](https://github.com/n0-computer/iroh/issues/2469)) - ([23790cb](https://github.com/n0-computer/iroh/commit/23790cbdf1f59c0eca27b1996b46cd88c6d4738d))
- Docker images for iroh ([#2404](https://github.com/n0-computer/iroh/issues/2404)) - ([debc4fb](https://github.com/n0-computer/iroh/commit/debc4fb8c225d3529db4f165facda8664eedfe8b))

### 🐛 Bug Fixes

- *(cli)* Always respect the `--metrics-port disabled` option ([#2459](https://github.com/n0-computer/iroh/issues/2459)) - ([2c40984](https://github.com/n0-computer/iroh/commit/2c409847e4d55162b6cae437bcc8028b12e88722))
- *(iroh-bytes)* Fix off-by-one error in Collection::load ([#2473](https://github.com/n0-computer/iroh/issues/2473)) - ([3002deb](https://github.com/n0-computer/iroh/commit/3002deb2273a3605736731780377a98219affcfb))
- *(iroh-docs)* Ensure docs db write txn gets closed regularly under all circumstances ([#2474](https://github.com/n0-computer/iroh/issues/2474)) - ([235c69c](https://github.com/n0-computer/iroh/commit/235c69cfbda067048735b91163004afae2798e26))
- *(iroh-docs)* [**breaking**] Add `flush_store` and use it to make sure the default author is persisted ([#2471](https://github.com/n0-computer/iroh/issues/2471)) - ([b88dfa5](https://github.com/n0-computer/iroh/commit/b88dfa5bd230af89cf0f92a3cd866c1de0c49ba9))
- *(iroh-gossip)* Gossip dispatcher: reliable events on join, allow dropping sinks or streams ([#2482](https://github.com/n0-computer/iroh/issues/2482)) - ([998d29f](https://github.com/n0-computer/iroh/commit/998d29ffbe96336866f75dd5115e056972d00e28))
- *(iroh-net)* Delays of non-stun probes for subsequent relays ([#2445](https://github.com/n0-computer/iroh/issues/2445)) - ([b34587f](https://github.com/n0-computer/iroh/commit/b34587fdd5f3649437be1f4f82edb0757a7898fb))
- *(iroh-net)* Use staging URL for pkarr publish in dev mode ([#2466](https://github.com/n0-computer/iroh/issues/2466)) - ([fe1d17f](https://github.com/n0-computer/iroh/commit/fe1d17fe8eb7537e9e44c5e0624cc68d5ced6e6e))
- *(iroh-net)* Unexpected `cfg` condition values / possible fix on netbsd ([#2476](https://github.com/n0-computer/iroh/issues/2476)) - ([aff8152](https://github.com/n0-computer/iroh/commit/aff81520f836e4c572025989061744ba53367aff))

### 🚜 Refactor

- *(iroh)* Log inner errors ([#2423](https://github.com/n0-computer/iroh/issues/2423)) - ([da3f84b](https://github.com/n0-computer/iroh/commit/da3f84b85091609af51bae1aa05109a1302c872e))
- *(iroh)* [**breaking**] Attempt make naming more consistent ([#2434](https://github.com/n0-computer/iroh/issues/2434)) - ([6b4435d](https://github.com/n0-computer/iroh/commit/6b4435dd24990108b67ee3c1bc969864ff9b57b4))
- *(iroh)* Modularize protocol ([#2454](https://github.com/n0-computer/iroh/issues/2454)) - ([5aa3fb6](https://github.com/n0-computer/iroh/commit/5aa3fb64ad270a46e3c156ca74cab09fb7273953))
- *(iroh)* [**breaking**] Remove server channel type parameter ([#2461](https://github.com/n0-computer/iroh/issues/2461)) - ([f4d1e71](https://github.com/n0-computer/iroh/commit/f4d1e7108b5ca589a28c4761180e79da44896f36))
- *(iroh-relay)* [**breaking**] Remove `relay_endpoint` config option & rename `/derp` route to `/relay` ([#2419](https://github.com/n0-computer/iroh/issues/2419)) - ([d4fe155](https://github.com/n0-computer/iroh/commit/d4fe1557486a4b959ab8396ace541f12f7a45a29))

### 📚 Documentation

- *(iroh)* Expand module level documentation in iroh ([#2463](https://github.com/n0-computer/iroh/issues/2463)) - ([74e8a6a](https://github.com/n0-computer/iroh/commit/74e8a6a2fc238aa3877fad11e7b71a8f0aee828a))
- *(iroh-net)* Update discovery and dialing docs, signatures ([#2472](https://github.com/n0-computer/iroh/issues/2472)) - ([e53714c](https://github.com/n0-computer/iroh/commit/e53714cbe8e7d80e0508eccf54709a73c1746a7b))
- Pass `Doc` instead of `Iroh` in example ([#2432](https://github.com/n0-computer/iroh/issues/2432)) - ([975124c](https://github.com/n0-computer/iroh/commit/975124c0bacdcd22ce5af7b73be128da18e3ba79))
- Example requires `example` feature to run ([#2451](https://github.com/n0-computer/iroh/issues/2451)) - ([623dcc6](https://github.com/n0-computer/iroh/commit/623dcc6303629eaf1cf634bec03a06cea8ba0b02))
- Reference rust doc style guide in contributing guidelines ([#2452](https://github.com/n0-computer/iroh/issues/2452)) - ([32b23e6](https://github.com/n0-computer/iroh/commit/32b23e64bf72ff239c40b057c7e4873401558e44))

### 🧪 Testing

- *(iroh-cli)* Also test for "minutes" in transfer time regex :grimacing:  ([#2475](https://github.com/n0-computer/iroh/issues/2475)) - ([9dddafc](https://github.com/n0-computer/iroh/commit/9dddafcfcf81e29a09b3b6cceaae64696d59b997))
- *(iroh-net)* Make some tests less flaky ([#2457](https://github.com/n0-computer/iroh/issues/2457)) - ([bc0b397](https://github.com/n0-computer/iroh/commit/bc0b3974a09ed4d72aeee68010be46915556fe64))
- Increase timeout test_run_rpc_lock_file ([#2439](https://github.com/n0-computer/iroh/issues/2439)) - ([efececb](https://github.com/n0-computer/iroh/commit/efececbe0dc0a99ad754655aba468320df4d6a11))
- Increase timeouts for tests that are flaky on slow CI ([#2450](https://github.com/n0-computer/iroh/issues/2450)) - ([cc30743](https://github.com/n0-computer/iroh/commit/cc30743382c282161bd7f52dfa9180f133608b47))

### ⚙️ Miscellaneous Tasks

- *(ci)* Deny aws-lc backend to sneak in ([#2436](https://github.com/n0-computer/iroh/issues/2436)) - ([6aef6aa](https://github.com/n0-computer/iroh/commit/6aef6aaf9035cb1ec562614c2aaa1d69896f35a9))
- *(ci)* Separate out android builds & disable netbsd ([#2435](https://github.com/n0-computer/iroh/issues/2435)) - ([002f5d5](https://github.com/n0-computer/iroh/commit/002f5d560c9a955418e43c7aacb5962382cf3067))
- *(ci)* Use pre-compiled binary on CI ([#2429](https://github.com/n0-computer/iroh/issues/2429)) - ([cdad25a](https://github.com/n0-computer/iroh/commit/cdad25a193eabdfbaa449f0eb70ea965d4d102b8))
- *(docs)* Update readme ([#2465](https://github.com/n0-computer/iroh/issues/2465)) - ([61f3f7e](https://github.com/n0-computer/iroh/commit/61f3f7e8a37a18f97759c74fc1065d33635d3e82))
- *(iroh)* Improve and document `custom-protocol` example ([#2468](https://github.com/n0-computer/iroh/issues/2468)) - ([203f9e7](https://github.com/n0-computer/iroh/commit/203f9e74e512b980696648fe12360016e2c68209))
- Introduce crate-ci/typos ([#2430](https://github.com/n0-computer/iroh/issues/2430)) - ([c58f744](https://github.com/n0-computer/iroh/commit/c58f744236a0a918a0edc66d48d45636de712700))
- Release - ([264848c](https://github.com/n0-computer/iroh/commit/264848c72de0132c568ab91cc86be77ecefc1472))

### Deps

- *(iroh-net)* Bump netdev ([#2447](https://github.com/n0-computer/iroh/issues/2447)) - ([b5dc795](https://github.com/n0-computer/iroh/commit/b5dc795ba7975b94a54a2f059f7e43b52f7e888f))

## [0.19.0](https://github.com/n0-computer/iroh/compare/v0.18.0..v0.19.0) - 2024-06-27

### ⛰️  Features

- *(iroh)* Allow to disable docs engine completely ([#2390](https://github.com/n0-computer/iroh/issues/2390)) - ([0e6d441](https://github.com/n0-computer/iroh/commit/0e6d4415d88afc148e838e3a95d176de092c8348))
- *(iroh)* Allow setting the logging directory via config file ([#2391](https://github.com/n0-computer/iroh/issues/2391)) - ([600ba8c](https://github.com/n0-computer/iroh/commit/600ba8c3f17a64f2c5de2835d10212deb2f460f4))
- *(iroh)* [**breaking**] Expand ability to connect to RPC ([#2398](https://github.com/n0-computer/iroh/issues/2398)) - ([d30ed19](https://github.com/n0-computer/iroh/commit/d30ed19e876d603021d17c2dac0b6acf46f0c514))

### 🐛 Bug Fixes

- *(iroh)* Do not double-close docs on drop ([#2383](https://github.com/n0-computer/iroh/issues/2383)) - ([55a0c0b](https://github.com/n0-computer/iroh/commit/55a0c0bfc490ed0f3897ae2d7a135fff43c8370f))
- *(iroh)* Use two stage accept from quic-rpc ([#2416](https://github.com/n0-computer/iroh/issues/2416)) - ([83b01ad](https://github.com/n0-computer/iroh/commit/83b01adcaec7165e64f92eba017b9cff8e29dbb4))
- *(iroh-net)* [**breaking**] ALPNs can be bytes, not just strings ([#2377](https://github.com/n0-computer/iroh/issues/2377)) - ([f57c34f](https://github.com/n0-computer/iroh/commit/f57c34f58b365b6b400c7ee2574f4cc89b4538bf))
- *(iroh-net)* Prevent adding addressing info that points back to us ([#2333](https://github.com/n0-computer/iroh/issues/2333)) - ([b2e8557](https://github.com/n0-computer/iroh/commit/b2e8557cfbc43ce73640d44f0a4976efbbbae176))
- *(iroh-net)* `poll_send` should drop transmits that we dont have a `dest` for ([#2393](https://github.com/n0-computer/iroh/issues/2393)) - ([aba70ea](https://github.com/n0-computer/iroh/commit/aba70ea9251d9eeb91b946ae5a25f4f0921fbe29))
- Properly wait for docs engine shutdown ([#2389](https://github.com/n0-computer/iroh/issues/2389)) - ([eb74cf6](https://github.com/n0-computer/iroh/commit/eb74cf6a25ca53de2ef237b6c20a2e5846a8090e))
- Do not panic on blobs db IO error ([#2400](https://github.com/n0-computer/iroh/issues/2400)) - ([38e8ce0](https://github.com/n0-computer/iroh/commit/38e8ce0695504fe4d1c6ee27fcdbd9ded02a4c3b))

### 🚜 Refactor

- *(iroh)* [**breaking**] Use ref-cast instead of fields to get the subsystem clients ([#2374](https://github.com/n0-computer/iroh/issues/2374)) - ([be3e16e](https://github.com/n0-computer/iroh/commit/be3e16e7550f5140adce319e40bc14647ed318ba))
- *(iroh)* Allow to register custom protocols ([#2358](https://github.com/n0-computer/iroh/issues/2358)) - ([13ded84](https://github.com/n0-computer/iroh/commit/13ded8478a8597fbee22b959d29efeb133c2fe40))
- *(iroh)* Move code from builder to node and make things nicer ([#2386](https://github.com/n0-computer/iroh/issues/2386)) - ([08f1fe0](https://github.com/n0-computer/iroh/commit/08f1fe0ffaf254249ad68181c4e2cecea5b29386))
- *(iroh)* Use boxed client to get rid of the C type parameter ([#2353](https://github.com/n0-computer/iroh/issues/2353)) - ([abc7f5e](https://github.com/n0-computer/iroh/commit/abc7f5e9f3f72158222d7cd2680c52cd797d787d))
- *(iroh)* [**breaking**] Eliminate the type parameter for the rpc service type ([#2405](https://github.com/n0-computer/iroh/issues/2405)) - ([52c96ba](https://github.com/n0-computer/iroh/commit/52c96ba914796a8f6095f6a3f8c6ca4ed0c06d62))
- *(iroh-net)* [**breaking**] Rename Endpoint::my_relay to home_relay ([#2361](https://github.com/n0-computer/iroh/issues/2361)) - ([100d27d](https://github.com/n0-computer/iroh/commit/100d27d57b28547a0ec5b4719bf25c31427f961e))
- *(iroh-net)* [**breaking**] Rename Endpoint::my_addr to Endpoint::node_addr ([#2362](https://github.com/n0-computer/iroh/issues/2362)) - ([61d5109](https://github.com/n0-computer/iroh/commit/61d5109ff7e6f9cdca42af3d27a7681c55400604))
- *(iroh-net)* [**breaking**] Do not use &NodeId in APIs as this is Copy ([#2363](https://github.com/n0-computer/iroh/issues/2363)) - ([e9075f3](https://github.com/n0-computer/iroh/commit/e9075f3b93038a74a4f11c545992ac4ba39590d0))
- *(iroh-net)* [**breaking**] Rename Endpoint::local_addr to bound_sockets ([#2366](https://github.com/n0-computer/iroh/issues/2366)) - ([a5e5939](https://github.com/n0-computer/iroh/commit/a5e59397f2f3d5e5df925b7a192570750cfa59ae))
- *(iroh-net)* [**breaking**] Rename Endpoint::local_endpoints to direct_addresses ([#2369](https://github.com/n0-computer/iroh/issues/2369)) - ([2ac3d01](https://github.com/n0-computer/iroh/commit/2ac3d01d466622e5955fb1e179caabe7b52beffa))
- *(iroh-net)* Improve magicsock module visibility ([#2371](https://github.com/n0-computer/iroh/issues/2371)) - ([3b0bb51](https://github.com/n0-computer/iroh/commit/3b0bb51b956b83d122237a3d0e091f9c80cd0a9d))
- *(iroh-net)* [**breaking**] Rework relay-server binary, more configurable, reverse-proxy support ([#2341](https://github.com/n0-computer/iroh/issues/2341)) - ([4ff1ec4](https://github.com/n0-computer/iroh/commit/4ff1ec46beb73eaaef31a12956594e39d72dfbbe))
- *(iroh_net)* [**breaking**] Remove Endpoint::my_addr_with_endpoints ([#2359](https://github.com/n0-computer/iroh/issues/2359)) - ([3a2faea](https://github.com/n0-computer/iroh/commit/3a2faeaf907faa510e9d1347cbb300dc5bedea17))

### 📚 Documentation

- *(iroh-net)* Update NodeAddr docs ([#2365](https://github.com/n0-computer/iroh/issues/2365)) - ([53dfed1](https://github.com/n0-computer/iroh/commit/53dfed146717febb98af124bf23adcfcdc51a3a7))
- *(iroh-net)* A few small fixes from PR review ([#2375](https://github.com/n0-computer/iroh/issues/2375)) - ([ea7e654](https://github.com/n0-computer/iroh/commit/ea7e654f1f7d4f37f8e12c4b79594a541dd823f8))
- Fix spelling in new protocol handler docs ([#2385](https://github.com/n0-computer/iroh/issues/2385)) - ([f73c506](https://github.com/n0-computer/iroh/commit/f73c506a809331e11b1deff84ef0cfe0fc25587c))

### 🧪 Testing

- *(iroh-net)* Remove a flaky test ([#2379](https://github.com/n0-computer/iroh/issues/2379)) - ([d37a4a4](https://github.com/n0-computer/iroh/commit/d37a4a4f3c7944200b902dcd822f4c33eb1787a0))

### ⚙️ Miscellaneous Tasks

- Deny openssl ([#2372](https://github.com/n0-computer/iroh/issues/2372)) - ([ac72938](https://github.com/n0-computer/iroh/commit/ac72938d6e558d5561ba0433c404e4db361ea010))
- Release - ([3659628](https://github.com/n0-computer/iroh/commit/3659628f3f86a7b677ca4aee2c495e29a6051da5))

### Deps

- Bump curve25519-dalek ([#2382](https://github.com/n0-computer/iroh/issues/2382)) - ([96081e5](https://github.com/n0-computer/iroh/commit/96081e5020cc837103a81360b14c97dfd3ffc9fe))

## [0.18.0](https://github.com/n0-computer/iroh/compare/v0.17.0..v0.18.0) - 2024-06-07

### ⛰️  Features

- *(iroh-gossip)* Configure the max message size ([#2340](https://github.com/n0-computer/iroh/issues/2340)) - ([7153a38](https://github.com/n0-computer/iroh/commit/7153a38bc52a8cec877c8b874f37a37658b99370))

### 🐛 Bug Fixes

- *(docs)* Prevent deadlocks with streams returned from docs actor ([#2346](https://github.com/n0-computer/iroh/issues/2346)) - ([98914ee](https://github.com/n0-computer/iroh/commit/98914ee4dcdb78f7477311f933d84f4f2478e168))
- *(iroh-net)* Fix extra delay ([#2330](https://github.com/n0-computer/iroh/issues/2330)) - ([77f92ef](https://github.com/n0-computer/iroh/commit/77f92efd16e523c41b0e01aa5a7e11e9aae3e795))
- *(iroh-net)* Return `Poll::Read(Ok(n))` when we have no relay URL or direct addresses in `poll_send` ([#2322](https://github.com/n0-computer/iroh/issues/2322)) - ([b2f0b0e](https://github.com/n0-computer/iroh/commit/b2f0b0eb84ef8f4a9962d540805a148a103d1e2b))

### 🚜 Refactor

- *(iroh)* [**breaking**] Replace public fields in iroh client with accessors and use ref-cast to eliminate them entirely ([#2350](https://github.com/n0-computer/iroh/issues/2350)) - ([35ce780](https://github.com/n0-computer/iroh/commit/35ce7805230ac7732a1bf3213be5424a1e019a44))
- *(iroh)* [**breaking**] Remove tags from downloader ([#2348](https://github.com/n0-computer/iroh/issues/2348)) - ([82aa93f](https://github.com/n0-computer/iroh/commit/82aa93fc5e2f55499ab7d29b18029ae47c519c3a))
- *(iroh-blobs)* [**breaking**] Make TempTag non-Clone ([#2338](https://github.com/n0-computer/iroh/issues/2338)) - ([d0662c2](https://github.com/n0-computer/iroh/commit/d0662c2d980b9fe28c669f2e6262c446d08bf7bf))
- *(iroh-blobs)* [**breaking**] Implement some collection related things on the client side ([#2349](https://github.com/n0-computer/iroh/issues/2349)) - ([b047b28](https://github.com/n0-computer/iroh/commit/b047b28ddead8f357cb22c67c6e7ada23db5deb8))
- Move docs engine into iroh-docs ([#2343](https://github.com/n0-computer/iroh/issues/2343)) - ([3772889](https://github.com/n0-computer/iroh/commit/3772889cd0a8e02731e5dc9c2a1e2f638ab2691a))

### 📚 Documentation

- *(iroh-net)* Update toplevel module documentation ([#2329](https://github.com/n0-computer/iroh/issues/2329)) - ([4dd69f4](https://github.com/n0-computer/iroh/commit/4dd69f44d62e3b671339ce586a2f7e97a47559ff))
- *(iroh-net)* Update endpoint docs ([#2334](https://github.com/n0-computer/iroh/issues/2334)) - ([8d91b10](https://github.com/n0-computer/iroh/commit/8d91b10e25e5a8363edde3c41a1bce4f9dc7455a))

### 🧪 Testing

- Disable a flaky tests ([#2332](https://github.com/n0-computer/iroh/issues/2332)) - ([23e8c7b](https://github.com/n0-computer/iroh/commit/23e8c7b3d5cdc83783822e3fa10b09e798d24f22))

### ⚙️ Miscellaneous Tasks

- *(ci)* Update clippy ([#2351](https://github.com/n0-computer/iroh/issues/2351)) - ([7198cd0](https://github.com/n0-computer/iroh/commit/7198cd0f69cd0a178db3b71b7ee58ea5f285b95e))
- Release - ([ea50b94](https://github.com/n0-computer/iroh/commit/ea50b94026a8f55abf02184e78671cf4cce96e0d))

## [0.17.0](https://github.com/n0-computer/iroh/compare/v0.16.0..v0.17.0) - 2024-05-24

### ⛰️  Features

- *(cli)* Add metrics server to iroh doctor ([#2292](https://github.com/n0-computer/iroh/issues/2292)) - ([d635d93](https://github.com/n0-computer/iroh/commit/d635d93ace4b1375c7dfeb194b5ee8e4651c810c))
- *(iroh)* [**breaking**] Remove node events ([#2274](https://github.com/n0-computer/iroh/issues/2274)) - ([b412927](https://github.com/n0-computer/iroh/commit/b412927e8578c1bfa78bcd07772520a0eb25b615))
- *(iroh)* Add node wide default author for documents ([#2299](https://github.com/n0-computer/iroh/issues/2299)) - ([c8690a2](https://github.com/n0-computer/iroh/commit/c8690a2c6eb5753c4ec6b7e44db72abf09df3c6e))
- *(iroh-base)* Wasm compatability ([#2305](https://github.com/n0-computer/iroh/issues/2305)) - ([ab18eae](https://github.com/n0-computer/iroh/commit/ab18eae5130acb6941eb16ce4d85c60f7c575298))
- *(iroh-net)* Watch relay changes ([#2291](https://github.com/n0-computer/iroh/issues/2291)) - ([9d71fd8](https://github.com/n0-computer/iroh/commit/9d71fd84d39866dc53e76f53b3a32303cb9895ad))
- *(iroh-net)* [**breaking**] Implement http proxy support ([#2298](https://github.com/n0-computer/iroh/issues/2298)) - ([6d1a6dd](https://github.com/n0-computer/iroh/commit/6d1a6dd6a9f825aa6fe434cd5098d2fb8684ae14))
- *(iroh-net)* [**breaking**] Improve dns behaviour by staggering requests ([#2313](https://github.com/n0-computer/iroh/issues/2313)) - ([d813089](https://github.com/n0-computer/iroh/commit/d81308933f39dc5a448609863402159ee72091ca))
- Emit PendingContentReady event ([#2302](https://github.com/n0-computer/iroh/issues/2302)) - ([fc73502](https://github.com/n0-computer/iroh/commit/fc735026c772c1aa4f00b9af0ffcc0654497d9a3))
- Import and subscribe to a document in a single call ([#2303](https://github.com/n0-computer/iroh/issues/2303)) - ([370075c](https://github.com/n0-computer/iroh/commit/370075c6d5689ad4349664eb9b51ec0a5e7e4e81))
- Iroh-perf ([#2186](https://github.com/n0-computer/iroh/issues/2186)) - ([98d45f3](https://github.com/n0-computer/iroh/commit/98d45f3b862f48e89be8e5b5d2ec1b15ae6fdf9f))
- [**breaking**] New quic-rpc, simlified generics, bump MSRV to 1.76 ([#2268](https://github.com/n0-computer/iroh/issues/2268)) - ([1e31dcf](https://github.com/n0-computer/iroh/commit/1e31dcfaae6c2e6b46052a04adba844ec629677d))
- Support {Free|Net|Open}BSD  ([#2311](https://github.com/n0-computer/iroh/issues/2311)) - ([cd65470](https://github.com/n0-computer/iroh/commit/cd654702a0d42348d754fec8a192051df3b55a13))

### 🐛 Bug Fixes

- *(iroh)* Make `client::docs::ImportProgress` public ([#2288](https://github.com/n0-computer/iroh/issues/2288)) - ([acd859b](https://github.com/n0-computer/iroh/commit/acd859b4e7f3dafd391c4f698b88c35f2c863644))
- *(iroh-gossip)* Do not drop existing connection on incoming one ([#2318](https://github.com/n0-computer/iroh/issues/2318)) - ([e41d1d9](https://github.com/n0-computer/iroh/commit/e41d1d9b6bee6129a58a0760d3410bc38d9abe19))
- Do not bind a mainline DHT socket ([#2296](https://github.com/n0-computer/iroh/issues/2296)) - ([491012c](https://github.com/n0-computer/iroh/commit/491012c87c98326275f97415016ebe1068f5c95d))

### 🚜 Refactor

- *(iroh-net)* [**breaking**] Rename MagicEndpoint -> Endpoint ([#2287](https://github.com/n0-computer/iroh/issues/2287)) - ([f4d6ca1](https://github.com/n0-computer/iroh/commit/f4d6ca1810615ec63bcb43dde818f9d19cd5cf72))
- *(iroh-net)* Small improvements to dns code ([#2301](https://github.com/n0-computer/iroh/issues/2301)) - ([b93dd34](https://github.com/n0-computer/iroh/commit/b93dd34951c1b982b116159f57cf0e086cda768f))
- Do not use gossip subscribe_all in iroh sync engine ([#2265](https://github.com/n0-computer/iroh/issues/2265)) - ([eebf6d1](https://github.com/n0-computer/iroh/commit/eebf6d127fa565c21ec696e9c10bca59a96b7b54))

### 📚 Documentation

- *(iroh-net)* Minor tweaks in the public iroh_net::dns module ([#2289](https://github.com/n0-computer/iroh/issues/2289)) - ([3f6b8e7](https://github.com/n0-computer/iroh/commit/3f6b8e7540a57e0c560f8c80d3c57b91bd18aaa3))

### 🧪 Testing

- *(iroh-gossip)* Fix `net` smoke test  ([#2314](https://github.com/n0-computer/iroh/issues/2314)) - ([8ad6ff1](https://github.com/n0-computer/iroh/commit/8ad6ff132aa377f3d925c48da20b16c333e37e3c))

### ⚙️ Miscellaneous Tasks

- Minimize use of raw base32 in examples ([#2304](https://github.com/n0-computer/iroh/issues/2304)) - ([1fafc9e](https://github.com/n0-computer/iroh/commit/1fafc9ea8c8eb085f1c51ce8314d5f62f8d1b260))
- Release - ([5ad15c8](https://github.com/n0-computer/iroh/commit/5ad15c8accc547fc33dd9e66839bd371834a3e35))

## [0.16.0](https://github.com/n0-computer/iroh/compare/v0.15.0..v0.16.0) - 2024-05-13

### ⛰️  Features

- *(doctor)* Report connection type changes in rolling fashion ([#2251](https://github.com/n0-computer/iroh/issues/2251)) - ([9a050a9](https://github.com/n0-computer/iroh/commit/9a050a954bcd3f3baedfa148b33e6df356a0c0f0))
- *(iroh)* [**breaking**] Unify node api ([#2275](https://github.com/n0-computer/iroh/issues/2275)) - ([6ed6b34](https://github.com/n0-computer/iroh/commit/6ed6b34d755aade02ce06e07b4f6c0faae616f09))
- *(iroh-base)* Allow the addr info of tickets to be empty ([#2254](https://github.com/n0-computer/iroh/issues/2254)) - ([5502c5a](https://github.com/n0-computer/iroh/commit/5502c5a8a88b11175c441b8730f3594fe2aad954))
- *(iroh-cli)* Make ticket-inspect print full node ids ([#2261](https://github.com/n0-computer/iroh/issues/2261)) - ([f099dab](https://github.com/n0-computer/iroh/commit/f099dab7742106eb49b36161d8e1b5ff4ed70c42))
- *(iroh-cli)* Add doctor plot ([#2206](https://github.com/n0-computer/iroh/issues/2206)) - ([4f1d8b0](https://github.com/n0-computer/iroh/commit/4f1d8b07f3851a0a15b55d4504fdd631fa5b8810))
- *(iroh-net)* Expose DNS resolver ([#2262](https://github.com/n0-computer/iroh/issues/2262)) - ([6504727](https://github.com/n0-computer/iroh/commit/650472793fb298aabf64195c0872e38bb7ca2fd0))
- *(iroh-net)* [**breaking**] Improve initial connection latency ([#2234](https://github.com/n0-computer/iroh/issues/2234)) - ([ec48b0d](https://github.com/n0-computer/iroh/commit/ec48b0d7eaef7f976f8d04e74629a4df07dcf39b))
- *(iroh-net)* Own the public QUIC API ([#2279](https://github.com/n0-computer/iroh/issues/2279)) - ([b62e904](https://github.com/n0-computer/iroh/commit/b62e90409f43aa06cbfb1f45a2ee2f9ae2af77de))
- Update from `default-net` to rebranded `netdev` ([#2264](https://github.com/n0-computer/iroh/issues/2264)) - ([302fea4](https://github.com/n0-computer/iroh/commit/302fea4ac46ad2e8119dc3df247fcd439c2a3892))

### 🐛 Bug Fixes

- *(iroh-net)* Reconfirm best addr when receiving data on it ([#2255](https://github.com/n0-computer/iroh/issues/2255)) - ([6fbf4a9](https://github.com/n0-computer/iroh/commit/6fbf4a92c98c394e888f3e33f40e20ede3ca7bcb))
- *(iroh-net)* Do not log as error if client disconnects from relay ([#2259](https://github.com/n0-computer/iroh/issues/2259)) - ([cdedc43](https://github.com/n0-computer/iroh/commit/cdedc434731428cb8dc80a5fcb9a46e6af4f85e3))

### 🚜 Refactor

- *(iroh)* [**breaking**] Cleanup public API ([#2263](https://github.com/n0-computer/iroh/issues/2263)) - ([d41f433](https://github.com/n0-computer/iroh/commit/d41f4331b94619360a2ceec5c48ae1c332518fa0))
- *(iroh-net)* [**breaking**] Make the interfaces module private ([#2266](https://github.com/n0-computer/iroh/issues/2266)) - ([38bdaef](https://github.com/n0-computer/iroh/commit/38bdaef1bc7053bfdafee5a48b99f3b56acb50b5))
- Renames iroh-sync & iroh-bytes ([#2271](https://github.com/n0-computer/iroh/issues/2271)) - ([26d718f](https://github.com/n0-computer/iroh/commit/26d718f324293ea1e428ce7b28a631e676d51279))

### 🧪 Testing

- *(iroh)* Test sync with restarting node ([#2146](https://github.com/n0-computer/iroh/issues/2146)) - ([ec1e1d2](https://github.com/n0-computer/iroh/commit/ec1e1d2d424ecdde6a7af57978052e3f47859494))
- *(iroh-net)* Fix relay's codec proptesting ([#2283](https://github.com/n0-computer/iroh/issues/2283)) - ([5343cea](https://github.com/n0-computer/iroh/commit/5343cea0e00741fb5a6c4c014a600c30a9f99fb6))
- Disable flaky tests on windowns again ([#2267](https://github.com/n0-computer/iroh/issues/2267)) - ([6cc12d8](https://github.com/n0-computer/iroh/commit/6cc12d856101aaed64dd11c5c12f346ab43223d8))

### ⚙️ Miscellaneous Tasks

- Release - ([531829d](https://github.com/n0-computer/iroh/commit/531829de3597c6977ecd4ddfb6ca52929603f46d))

## [0.15.0](https://github.com/n0-computer/iroh/compare/v0.14.0..v0.15.0) - 2024-04-29

### ⛰️  Features

- *(iroh-bytes)* Add more context to errors ([#2196](https://github.com/n0-computer/iroh/issues/2196)) - ([d3fec78](https://github.com/n0-computer/iroh/commit/d3fec78d23f98eb609bb5b7497c447301a8382b2))
- *(iroh-bytes)* [**breaking**] Refactor downloader queue and add progress reporting ([#2085](https://github.com/n0-computer/iroh/issues/2085)) - ([93290e3](https://github.com/n0-computer/iroh/commit/93290e3fb71ad66713dfa846bdf179d81e2c08d6))
- *(iroh-bytes)* Add copy fallback for Export::TryReference ([#2233](https://github.com/n0-computer/iroh/issues/2233)) - ([ec7de88](https://github.com/n0-computer/iroh/commit/ec7de88c87e13fde19713c0d792e397a7dc31fc3))
- *(iroh-dns-server)* [**breaking**] Add dht fallback option ([#2188](https://github.com/n0-computer/iroh/issues/2188)) - ([0b0508b](https://github.com/n0-computer/iroh/commit/0b0508b36c38ccbe2781b7ed4214227c8af8a64e))
- *(iroh-net)* Extend discovery NodeInfo to allow direct addrs ([#2201](https://github.com/n0-computer/iroh/issues/2201)) - ([2c49ee8](https://github.com/n0-computer/iroh/commit/2c49ee8d45b934054be8358e652efca8e2c10f49))
- Release automation ([#2214](https://github.com/n0-computer/iroh/issues/2214)) - ([b5f8277](https://github.com/n0-computer/iroh/commit/b5f827703f89740ee977965515b122005ae48826))
- [**breaking**] Implement improved address sharing options ([#2230](https://github.com/n0-computer/iroh/issues/2230)) - ([a26a350](https://github.com/n0-computer/iroh/commit/a26a35023e0565936925dcf819385df8f368230f))

### 🐛 Bug Fixes

- *(ci)* Typo in semver rev check ([#2213](https://github.com/n0-computer/iroh/issues/2213)) - ([2a6ae17](https://github.com/n0-computer/iroh/commit/2a6ae17cfb122f1434709e38bdf8648fd7e3f039))
- *(ci)* Minor corrections for manual release runs ([#2215](https://github.com/n0-computer/iroh/issues/2215)) - ([3a74d89](https://github.com/n0-computer/iroh/commit/3a74d893f6003c9a3b68c7795e6654aed047ba77))
- *(ci)* Fix for windows release runs ([#2216](https://github.com/n0-computer/iroh/issues/2216)) - ([2dfd0ae](https://github.com/n0-computer/iroh/commit/2dfd0aef7c61496456a21fe30dd3b0c97cc8760c))
- *(ci)* Release builds ([#2219](https://github.com/n0-computer/iroh/issues/2219)) - ([ba7317d](https://github.com/n0-computer/iroh/commit/ba7317d903ccbe8807c696c06a475cded3c60fa5))
- *(deps)* Update rustls ([#2218](https://github.com/n0-computer/iroh/issues/2218)) - ([f508830](https://github.com/n0-computer/iroh/commit/f5088303898a9b3197f8275cd3090635d69ffb97))
- *(iroh-bytes)* Do not log redundant file delete error ([#2199](https://github.com/n0-computer/iroh/issues/2199)) - ([1e84ae0](https://github.com/n0-computer/iroh/commit/1e84ae03cc315191c784e3d07c09ed8c30d5821f))
- *(iroh-bytes)* Reduce log level from info to debug for most uncritical operations ([#2202](https://github.com/n0-computer/iroh/issues/2202)) - ([6d36d00](https://github.com/n0-computer/iroh/commit/6d36d0001738ebd309c27af2136f750f97914646))
- *(iroh-cli)* Avoid using debug formatting for rpc errors ([#2203](https://github.com/n0-computer/iroh/issues/2203)) - ([508a812](https://github.com/n0-computer/iroh/commit/508a8123c1c9f9b14a16234bf8519ede97566047))
- *(iroh-dns-server)* Fix bug in pkarr name parsing ([#2200](https://github.com/n0-computer/iroh/issues/2200)) - ([2bb7bd5](https://github.com/n0-computer/iroh/commit/2bb7bd51a460c2de2aaacde35a79c37a33c029bf))
- *(iroh-gossip)* Do not enable "metrics" feature for iroh-net by default ([#2235](https://github.com/n0-computer/iroh/issues/2235)) - ([2693ec5](https://github.com/n0-computer/iroh/commit/2693ec5c0b5ab2fba4a346b388d7ea9bfa04c9b2))
- *(iroh-net)* Suppress HostUnreachable network error as well ([#2197](https://github.com/n0-computer/iroh/issues/2197)) - ([600393b](https://github.com/n0-computer/iroh/commit/600393b3d48509b5603bf31c2f424634ac64268b))
- *(iroh-net)* Better logging for pkarr publish ([#2208](https://github.com/n0-computer/iroh/issues/2208)) - ([0f624cc](https://github.com/n0-computer/iroh/commit/0f624cc2bb59b97737a80cf19737ae50108a0663))
- *(iroh-net)* [**breaking**] Improve magicsock's shutdown story ([#2227](https://github.com/n0-computer/iroh/issues/2227)) - ([265e284](https://github.com/n0-computer/iroh/commit/265e2843e25afca759b3c4917b139c03cad71139))
- *(iroh-net)* [**breaking**] Only call quinn_connect if a send addr is available ([#2225](https://github.com/n0-computer/iroh/issues/2225)) - ([e913051](https://github.com/n0-computer/iroh/commit/e91305138e866ce54327655e7b6df72e072e5c3a))
- *(iroh-net)* Do not persist invalid node addresses ([#2209](https://github.com/n0-computer/iroh/issues/2209)) - ([18b301a](https://github.com/n0-computer/iroh/commit/18b301a877f8d59f1718278e6b3085012cbdfaef))
- *(iroh_net)* Less agressive best_addr clearing on pong timeout ([#2238](https://github.com/n0-computer/iroh/issues/2238)) - ([5329927](https://github.com/n0-computer/iroh/commit/5329927d63c80b3e81d2f0120542e049a573a65d))
- *(iroh_net)* Track `recv_data_ipv4` & `recv_data_ipv6` ([#2243](https://github.com/n0-computer/iroh/issues/2243)) - ([f8ff3bc](https://github.com/n0-computer/iroh/commit/f8ff3bc26be9c36bdfe31fa0ccae1c1b277250aa))
- Better logging for iroh-dns-server ([#2195](https://github.com/n0-computer/iroh/issues/2195)) - ([075737d](https://github.com/n0-computer/iroh/commit/075737d93fe0b8b4ba499860c6a8ce55ce56082a))
- Semver check on main ([#2212](https://github.com/n0-computer/iroh/issues/2212)) - ([5873a55](https://github.com/n0-computer/iroh/commit/5873a55557f68251425746eb171a2caf47eb13e0))

### 🚜 Refactor

- *(iroh-net)* [**breaking**] Rename endpoint for nodes to node_state ([#2222](https://github.com/n0-computer/iroh/issues/2222)) - ([26e4564](https://github.com/n0-computer/iroh/commit/26e4564441358a083787542b013a4d4e4b797ba1))
- *(iroh-net)* Merge related fields regarding incoming pings ([#2236](https://github.com/n0-computer/iroh/issues/2236)) - ([0f370ad](https://github.com/n0-computer/iroh/commit/0f370ad4dce0cd0ac566b8a7569c915caf033559))
- *(iroh-net)* [**breaking**] Remove the magicsock module from the public api ([#2247](https://github.com/n0-computer/iroh/issues/2247)) - ([06e0b7b](https://github.com/n0-computer/iroh/commit/06e0b7b3ba1537f66b912b9520cf3fc013b8b3c6))
- *(iroh-sync)* Doc store batching ([#2172](https://github.com/n0-computer/iroh/issues/2172)) - ([9b3165b](https://github.com/n0-computer/iroh/commit/9b3165b7f26685d16042a5e10ee14e80f74da5e9))
- Happy clippy ([#2220](https://github.com/n0-computer/iroh/issues/2220)) - ([d6ff0cf](https://github.com/n0-computer/iroh/commit/d6ff0cf552a4cf2f992205b53efac3a006974843))
- Improve content downloading in docs ([#2127](https://github.com/n0-computer/iroh/issues/2127)) - ([1432d61](https://github.com/n0-computer/iroh/commit/1432d61e7c4367e115e63dfe2785b3ff7b540b8c))
- [**breaking**] Avoid using futures crate directly ([#2117](https://github.com/n0-computer/iroh/issues/2117)) - ([b91b684](https://github.com/n0-computer/iroh/commit/b91b68400ebfcf557feed431f5a6b15a56a796e8))

### 📚 Documentation

- Improve breaking change handling ([#2207](https://github.com/n0-computer/iroh/issues/2207)) - ([d55b782](https://github.com/n0-computer/iroh/commit/d55b782a702ae4a8ee3f850c522597fd588eec03))

### 🧪 Testing

- *(iroh_net)* Mark test_icmpk_probe_eu_relayer as flaky on windows ([#2240](https://github.com/n0-computer/iroh/issues/2240)) - ([ea8e047](https://github.com/n0-computer/iroh/commit/ea8e047ea5a6efb3e2e031729639fc8fc6d429e8))
- Remove flaky label from windows-DNS affected tests ([#2223](https://github.com/n0-computer/iroh/issues/2223)) - ([93bcaa5](https://github.com/n0-computer/iroh/commit/93bcaa5a6adf92856eeb9938b4c4921aa6e3dfae))
- Mark iroh::sync_big flaky ([#2245](https://github.com/n0-computer/iroh/issues/2245)) - ([297fd1a](https://github.com/n0-computer/iroh/commit/297fd1a4d7db97cc41ec222f6651e572f0c43f29))

### ⚙️ Miscellaneous Tasks

- Rename derper > iroh-relay ([#2211](https://github.com/n0-computer/iroh/issues/2211)) - ([ebe7196](https://github.com/n0-computer/iroh/commit/ebe7196a978dccf4873188a2355039b496efc402))
- Release - ([13a0bbc](https://github.com/n0-computer/iroh/commit/13a0bbcaf9104dcf2f19e0aae996a890aecfea48))

### Deps

- *(iroh-blake3)* Upgrade to version fixing more symbol collions ([#2246](https://github.com/n0-computer/iroh/issues/2246)) - ([0c336c4](https://github.com/n0-computer/iroh/commit/0c336c40a015ed13492256d6831965b5a4ddef6f))

## [0.14.0](https://github.com/n0-computer/iroh/compare/v0.13.0..v0.14.0) - 2024-04-15

### ⛰️  Features

- *(iroh)* Implement basic author api ([#2132](https://github.com/n0-computer/iroh/issues/2132)) - ([5e1a71f](https://github.com/n0-computer/iroh/commit/5e1a71f3a4d514c124a06a4de96374d72a2d3328))
- *(iroh-cli)* Add file logging by default for start commands ([#2175](https://github.com/n0-computer/iroh/issues/2175)) - ([b80b338](https://github.com/n0-computer/iroh/commit/b80b338fcd908bca7b32e506f4906ce6b5790eb9))
- *(iroh-cli)* Simplify config loading ([#2171](https://github.com/n0-computer/iroh/issues/2171)) - ([2cfa055](https://github.com/n0-computer/iroh/commit/2cfa05588076792c2af1009162044a01243bf38c))
- *(iroh-net)* Add `MagicEndpoint::conn_type_stream` returns a stream that reports connection type changes for a `node_id` ([#2161](https://github.com/n0-computer/iroh/issues/2161)) - ([7986394](https://github.com/n0-computer/iroh/commit/7986394ebb4e31cf617d2d63a9763455b7432e9b))
- Mark iroh-cli's iroh binary as workspace default ([#2160](https://github.com/n0-computer/iroh/issues/2160)) - ([aeb04d8](https://github.com/n0-computer/iroh/commit/aeb04d8b2cae12ef3da9edcd1fcfe8bb5b782e15))
- Update redb to v2 ([#2120](https://github.com/n0-computer/iroh/issues/2120)) - ([ceaf168](https://github.com/n0-computer/iroh/commit/ceaf168afd50a3c5198762878e7e16afc66cc520))
- Node discovery via DNS ([#2045](https://github.com/n0-computer/iroh/issues/2045)) - ([72384ce](https://github.com/n0-computer/iroh/commit/72384ce63a178b3bf7ea7df6fc3e68690d08c1f4))
- Add discovery option to doctor ([#2182](https://github.com/n0-computer/iroh/issues/2182)) - ([2c1eca9](https://github.com/n0-computer/iroh/commit/2c1eca9b8e309237e5e0b22a8ce93d8d0c72796e))

### 🐛 Bug Fixes

- *(iroh)* Shutdown sync engine on iroh node shutdown ([#2131](https://github.com/n0-computer/iroh/issues/2131)) - ([35a1cdd](https://github.com/n0-computer/iroh/commit/35a1cdd3119c002f26c331251a90dacdea5698f5))
- *(iroh)* Do not shut down node on internal rpc error ([#2158](https://github.com/n0-computer/iroh/issues/2158)) - ([fcdc299](https://github.com/n0-computer/iroh/commit/fcdc299e316b425a26887369a1e48a8f90bdeee4))
- *(iroh-cli)* Doctor relay-urls, correct connection logic ([#2163](https://github.com/n0-computer/iroh/issues/2163)) - ([314c883](https://github.com/n0-computer/iroh/commit/314c88337a008450344d18610af43b321682b9e7))
- *(iroh-cli)* Fix printing of doctor connect/accept output ([#2166](https://github.com/n0-computer/iroh/issues/2166)) - ([5d4ac52](https://github.com/n0-computer/iroh/commit/5d4ac52763aeecc1c090e549643c9c99259c9aa0))
- *(iroh-net)* Avoid double connections to relays ([#2148](https://github.com/n0-computer/iroh/issues/2148)) - ([aa1cf66](https://github.com/n0-computer/iroh/commit/aa1cf66decf69f1f4b6d9e464c45d4229a065c65))
- *(tests)* Disable the metrics port of all cli tests ([#2154](https://github.com/n0-computer/iroh/issues/2154)) - ([1d51caa](https://github.com/n0-computer/iroh/commit/1d51caa920e37ee89c8a9d4e248246b382a848b1))
- Remove redundant imports ([#2159](https://github.com/n0-computer/iroh/issues/2159)) - ([43038df](https://github.com/n0-computer/iroh/commit/43038dfadbe629eea97240c7ca476ef431eab9ea))

### 🚜 Refactor

- *(iroh-bytes)* Update bao-tree to 0.12 and adjust code ([#2153](https://github.com/n0-computer/iroh/issues/2153)) - ([bfb7560](https://github.com/n0-computer/iroh/commit/bfb75602064a24155cc3579bd7fe79b8682b9593))
- *(iroh-bytes)* Use even newer bao-tree ([#2168](https://github.com/n0-computer/iroh/issues/2168)) - ([fe6dcac](https://github.com/n0-computer/iroh/commit/fe6dcaccad54e7d72ae6aa122721ccd33736edc4))
- *(iroh-net)* Remove incremental state from reportgen actor ([#2180](https://github.com/n0-computer/iroh/issues/2180)) - ([d22c1cd](https://github.com/n0-computer/iroh/commit/d22c1cd56825757c73deca4d3e525956d3245e1d))
- *(metrics)* Metrics on by default ([#2129](https://github.com/n0-computer/iroh/issues/2129)) - ([ff88f65](https://github.com/n0-computer/iroh/commit/ff88f65175eb0fd74d748e988ac021bacaccebc9))
- Rustc beta is stricter again wrt imports and unused code ([#2185](https://github.com/n0-computer/iroh/issues/2185)) - ([d6f336c](https://github.com/n0-computer/iroh/commit/d6f336c7bbd17f447872a7ebd56e0d58361209d6))

### 📚 Documentation

- *(gossip)* Add comment about message uniqueness ([#2140](https://github.com/n0-computer/iroh/issues/2140)) - ([9fc1266](https://github.com/n0-computer/iroh/commit/9fc126655e4ccd1c6a72e600691adfb69606e97d))

### ⚡ Performance

- *(iroh-net)* Simplify relay handshake ([#2164](https://github.com/n0-computer/iroh/issues/2164)) - ([70db5fb](https://github.com/n0-computer/iroh/commit/70db5fba3156c8b0669e4124ce8ccf8a7ceeff76))
- *(iroh-sync)* Avoid allocating a full range of values during sync ([#2152](https://github.com/n0-computer/iroh/issues/2152)) - ([13e83f3](https://github.com/n0-computer/iroh/commit/13e83f3a8fe5e3546af072aa8598ec933b77efe3))

### 🧪 Testing

- *(iroh-net)* Expose `run_relay_server` and option to skip cert verification to tests ([#2145](https://github.com/n0-computer/iroh/issues/2145)) - ([fb4703a](https://github.com/n0-computer/iroh/commit/fb4703aef9c7484e054af8b76a5e386f7cd61715))

### ⚙️ Miscellaneous Tasks

- *(ci)* Upload iroh-dns-server binaries ([#2189](https://github.com/n0-computer/iroh/issues/2189)) - ([d1f946e](https://github.com/n0-computer/iroh/commit/d1f946ebe3b7d658d34801a5cdbfd23722783755))
- Move metrics init into CLI ([#2136](https://github.com/n0-computer/iroh/issues/2136)) - ([319e9cc](https://github.com/n0-computer/iroh/commit/319e9ccfda41af7f0b8a72337ef876875692eacd))
- Remove unused dependencies ([#2170](https://github.com/n0-computer/iroh/issues/2170)) - ([b07547b](https://github.com/n0-computer/iroh/commit/b07547b68eb771e789474ad4f1344e02b2223f95))
- Release - ([406280c](https://github.com/n0-computer/iroh/commit/406280c6f6d543c93c651378ad22c64f957127ba))

### Deps

- *(iroh-next)* Move from igd to igd-next ([#2134](https://github.com/n0-computer/iroh/issues/2134)) - ([6417816](https://github.com/n0-computer/iroh/commit/6417816c61b22df086aca7faaf97c281afa4ea35))
- Update h2 ([#2147](https://github.com/n0-computer/iroh/issues/2147)) - ([c85bf3d](https://github.com/n0-computer/iroh/commit/c85bf3dd94ce0bec766d8eed0fbc4bb130660309))

## [0.13.0](https://github.com/n0-computer/iroh/compare/v0.12.0..v0.13.0) - 2024-03-25

### ⛰️  Features

- *(deps)* Update from trust-dns-resolver to hickory-resolver ([#2033](https://github.com/n0-computer/iroh/issues/2033)) - ([af7783e](https://github.com/n0-computer/iroh/commit/af7783e15afeaa7b57c8412580f7aaf60b1313df))
- *(iroh)* Add blobs.create_collection api endpoint  - ([1f6153b](https://github.com/n0-computer/iroh/commit/1f6153ba2aeba7b916b9fa352263852498e0e68f))
- *(iroh)* Add more rpc methods ([#1962](https://github.com/n0-computer/iroh/issues/1962)) - ([4910df1](https://github.com/n0-computer/iroh/commit/4910df120d50944b47e30f9f052e4c2a6dce9492))
- *(iroh)* Add --log-fd flag on unix ([#2011](https://github.com/n0-computer/iroh/issues/2011)) - ([8e60d1b](https://github.com/n0-computer/iroh/commit/8e60d1befba2053a9f3800219c61510603312dfc))
- *(iroh)* Expose `ExportMode` in client API ([#2031](https://github.com/n0-computer/iroh/issues/2031)) - ([ac667bb](https://github.com/n0-computer/iroh/commit/ac667bb86ff54dc3590ceb9ad87e444b4d60738b))
- *(iroh)* Add Sync bound and Stream impl for BlobReader ([#2063](https://github.com/n0-computer/iroh/issues/2063)) - ([09e3e52](https://github.com/n0-computer/iroh/commit/09e3e52114ea05479bf83203bcb81ec60ec609ba))
- *(iroh)* Improved node builder ([#2087](https://github.com/n0-computer/iroh/issues/2087)) - ([2364329](https://github.com/n0-computer/iroh/commit/23643296d6ba9f6c6399bdfd01819b399b33440b))
- *(iroh)* Expose GetSyncPeers ([#2054](https://github.com/n0-computer/iroh/issues/2054)) - ([0b94992](https://github.com/n0-computer/iroh/commit/0b9499271db043b94c6d32d77026970570b4b4d8))
- *(iroh)* Improve various aspects of the api ([#2094](https://github.com/n0-computer/iroh/issues/2094)) - ([c776478](https://github.com/n0-computer/iroh/commit/c7764780e58b00c3a1252a500f55426db2ccdb98))
- *(iroh-bytes)* Bring back validation ([#2107](https://github.com/n0-computer/iroh/issues/2107)) - ([50b3e47](https://github.com/n0-computer/iroh/commit/50b3e47a421ac5fd240da481f051544fa509c2ce))
- *(iroh-net)* DNS queries: lookup ipv6 & ipv4 in parallel ([#2019](https://github.com/n0-computer/iroh/issues/2019)) - ([4615915](https://github.com/n0-computer/iroh/commit/4615915f9cb17ca95c39d51e720c74996ce63427))
- *(iroh-net)* ICMPv6 probe support in netcheck ([#2057](https://github.com/n0-computer/iroh/issues/2057)) - ([bbb55a8](https://github.com/n0-computer/iroh/commit/bbb55a815cf7360c740241ff086e4f067cf89eeb))
- *(iroh-net)* Combine discovery services and add heuristics when to start discovery ([#2056](https://github.com/n0-computer/iroh/issues/2056)) - ([f4d3fab](https://github.com/n0-computer/iroh/commit/f4d3fab10d7ba49a2e66510dc4cd06963e15899b))
- *(iroh-net)* Use the local endpoints info when closing derps ([#2082](https://github.com/n0-computer/iroh/issues/2082)) - ([8d86ffc](https://github.com/n0-computer/iroh/commit/8d86ffcf20abf104a68f122a05158844dc896052))
- Release artifacts & windows builds ([#1987](https://github.com/n0-computer/iroh/issues/1987)) - ([13a3fe6](https://github.com/n0-computer/iroh/commit/13a3fe6ebc9ccfad6eceb908802362a81a221212))
- Split CLI implementation into a new iroh-cli crate ([#2076](https://github.com/n0-computer/iroh/issues/2076)) - ([5c70cd2](https://github.com/n0-computer/iroh/commit/5c70cd2a51e9ba67477c8063fc0300409057e0a7))

### 🐛 Bug Fixes

- *(ci)* Cleanup and fix bugs ([#1926](https://github.com/n0-computer/iroh/issues/1926)) - ([cced7f1](https://github.com/n0-computer/iroh/commit/cced7f172374d6067615b5ecb691fa08e357a385))
- *(ci)* Stop reusing concurrency labels across jobs ([#1937](https://github.com/n0-computer/iroh/issues/1937)) - ([02ead0a](https://github.com/n0-computer/iroh/commit/02ead0a2b75d570f8b890cc6bf40f6c4a2800c3c))
- *(ci)* Also test iroh-cli for cargo features ([#2122](https://github.com/n0-computer/iroh/issues/2122)) - ([a136b1d](https://github.com/n0-computer/iroh/commit/a136b1dfc6409f84069eb8973b54481bd18d7704))
- *(console)* Prevent deadlock in `author new --switch` ([#2032](https://github.com/n0-computer/iroh/issues/2032)) - ([fea92ac](https://github.com/n0-computer/iroh/commit/fea92ac1b47083c99015925c0a8079088c7dac16))
- *(derp)* Restore `ClientInfo` `mesh_key` field ([#2090](https://github.com/n0-computer/iroh/issues/2090)) - ([75a8590](https://github.com/n0-computer/iroh/commit/75a8590fd29a26973d4561b545bcb7dcb4435a1a))
- *(examples)* Adjust and add examples ([#1968](https://github.com/n0-computer/iroh/issues/1968)) - ([9f10152](https://github.com/n0-computer/iroh/commit/9f10152d885aaf2884f8ada5eecdfc25f3938bbf))
- *(iroh)* Add timestamp method to Entry RPC struct ([#1949](https://github.com/n0-computer/iroh/issues/1949)) - ([0084b5f](https://github.com/n0-computer/iroh/commit/0084b5f0bb5bf5d2d60cb56f8091f5d70ecf7aa9))
- *(iroh)* Do not establish connection if content already exists locally ([#1969](https://github.com/n0-computer/iroh/issues/1969)) - ([f7264ff](https://github.com/n0-computer/iroh/commit/f7264ff7f5c87e74270aae5f158fd227856d5f20))
- *(iroh)* Improve and test blob share ([#1979](https://github.com/n0-computer/iroh/issues/1979)) - ([5db247f](https://github.com/n0-computer/iroh/commit/5db247f3ac9a966b08a9ff5b054faf72660b5534))
- *(iroh)* Do not remove the rpc lockfile if an iroh node is already running ([#2013](https://github.com/n0-computer/iroh/issues/2013)) - ([a5c0db3](https://github.com/n0-computer/iroh/commit/a5c0db3d592d354f6137f91e00f347e4815f21e3))
- *(iroh)* Properly shut down the store on control-c ([#2100](https://github.com/n0-computer/iroh/issues/2100)) - ([7cc9efa](https://github.com/n0-computer/iroh/commit/7cc9efa1fb3bd28d3519702ffc7411f28ba4343c))
- *(iroh-bytes)* Print hashes as hex in validation ([#2118](https://github.com/n0-computer/iroh/issues/2118)) - ([9d40459](https://github.com/n0-computer/iroh/commit/9d404596ec68cd3719d33df10cc9ba3a4646a43c))
- *(iroh-net)* Improve connectivity ([#1983](https://github.com/n0-computer/iroh/issues/1983)) - ([4b58de5](https://github.com/n0-computer/iroh/commit/4b58de593543726fa926e29a0ee3056482e5aeb9))
- *(iroh-net)* Improve direct connectivity establishment speed and reliablity ([#1984](https://github.com/n0-computer/iroh/issues/1984)) - ([b173520](https://github.com/n0-computer/iroh/commit/b173520ce7cc7c73fe10b61e261bba45d056ffaa))
- *(iroh-net)* Correctly report sent transmits in poll_send ([#2025](https://github.com/n0-computer/iroh/issues/2025)) - ([b0afd40](https://github.com/n0-computer/iroh/commit/b0afd40f63273436e5b91c352c4687c1bba35e1e))
- *(iroh-net)* Race ipv4 and ipv6 dns resolution ([#2026](https://github.com/n0-computer/iroh/issues/2026)) - ([19553ed](https://github.com/n0-computer/iroh/commit/19553ede32b46e2abc3c2f1bde28eb843d3b5bb7))
- *(iroh-net)* Ensure netcheck finishes once it has results ([#2027](https://github.com/n0-computer/iroh/issues/2027)) - ([c62950e](https://github.com/n0-computer/iroh/commit/c62950e78f4b244765b48dbc756332e3835f7354))
- *(iroh-net)* Fix in detecting globally routable IPv6 addresses ([#2030](https://github.com/n0-computer/iroh/issues/2030)) - ([c3aa17e](https://github.com/n0-computer/iroh/commit/c3aa17e6b38b37284f4b6ce932ca1095cbf7b941))
- *(iroh-net)* Handle unreachable IPv6 networks better ([#2029](https://github.com/n0-computer/iroh/issues/2029)) - ([436121f](https://github.com/n0-computer/iroh/commit/436121fb8a4a49f1c0c5a3e228718c53a7cbe5d1))
- *(iroh-net)* Fix some flaky magicsock tests ([#2034](https://github.com/n0-computer/iroh/issues/2034)) - ([df57623](https://github.com/n0-computer/iroh/commit/df57623e5b41b6053542ead7cdfd59a926580536))
- *(iroh-net)* Trigger netcheck on a magicsock rebind ([#2042](https://github.com/n0-computer/iroh/issues/2042)) - ([890d019](https://github.com/n0-computer/iroh/commit/890d0195c8fb69f61706286a22f38b224927b50e))
- *(iroh-net)* Work around broken windows DNS configuration ([#2075](https://github.com/n0-computer/iroh/issues/2075)) - ([3747a09](https://github.com/n0-computer/iroh/commit/3747a091b58a13c64cd69ccb69e2c6634ceb5bb6))
- *(iroh-net)* Improve backpressure handling ([#2105](https://github.com/n0-computer/iroh/issues/2105)) - ([b98ed9d](https://github.com/n0-computer/iroh/commit/b98ed9d77655e37673efcf01ae6a854f8685e3da))
- *(iroh-sync)* Dl policies exists only if doc exists ([#1921](https://github.com/n0-computer/iroh/issues/1921)) - ([de7f603](https://github.com/n0-computer/iroh/commit/de7f6031d375b7a21772d47a2405a3a2c1d8f79f))
- *(iroh-sync)* Sync peers exists only if doc exists ([#1920](https://github.com/n0-computer/iroh/issues/1920)) - ([2835f62](https://github.com/n0-computer/iroh/commit/2835f62d91dcffa3e22ef644321a7d0eb1fd3458))
- Allow some dead code for the nightly compiler ([#1934](https://github.com/n0-computer/iroh/issues/1934)) - ([ca20102](https://github.com/n0-computer/iroh/commit/ca20102c8322e00f2e39c1bc8409e00694b137d3))
- Build successfully from `cargo vendor` tarball ([#1932](https://github.com/n0-computer/iroh/issues/1932)) - ([2337cb2](https://github.com/n0-computer/iroh/commit/2337cb26a16a9b17271f750e4d3883e4d35b3d09))
- Ci windows releases - ([ed23c43](https://github.com/n0-computer/iroh/commit/ed23c4339432adb708e588717666ad7886d16373))
- Ci release builds ([#1988](https://github.com/n0-computer/iroh/issues/1988)) - ([4abb782](https://github.com/n0-computer/iroh/commit/4abb782ecb5090466dc63532494660c610a81349))
- Update deps to avoid cargo-deny warning ([#2059](https://github.com/n0-computer/iroh/issues/2059)) - ([bc1af2e](https://github.com/n0-computer/iroh/commit/bc1af2e065f5f987b58df617c518abf2d58b0a6f))
- Properly shutdown sync actor ([#2067](https://github.com/n0-computer/iroh/issues/2067)) - ([e96a0c1](https://github.com/n0-computer/iroh/commit/e96a0c16cd816292bedfa6f3711d0a615b9f02c7))
- Remove dead code detected by the rust beta compiler ([#2121](https://github.com/n0-computer/iroh/issues/2121)) - ([2c59d7d](https://github.com/n0-computer/iroh/commit/2c59d7de4bd57e8c6f440b204bbc908cb3227eca))
- Do not allow connecting to ourself ([#2123](https://github.com/n0-computer/iroh/issues/2123)) - ([a2af124](https://github.com/n0-computer/iroh/commit/a2af12440f07969429f30767ec0a8367ab9853ec))
- Comment about grease_quic_bit ([#2124](https://github.com/n0-computer/iroh/issues/2124)) - ([8407907](https://github.com/n0-computer/iroh/commit/8407907c38cba813f9e9cdcf6d3a6081886896e2))

### 🚜 Refactor

- *(iroh)* Move rpc handling into its own module ([#2078](https://github.com/n0-computer/iroh/issues/2078)) - ([e7690b9](https://github.com/n0-computer/iroh/commit/e7690b909c53114fb617e6f56d5ef55419dc1cc6))
- *(iroh-bytes)* Take advantage of impl T in trait, update bao-tree and iroh-io ([#2018](https://github.com/n0-computer/iroh/issues/2018)) - ([a942973](https://github.com/n0-computer/iroh/commit/a942973834cbaa75805f5ea6b0f365d87de88ec3))
- *(iroh-bytes)* Simplify store traits ([#2023](https://github.com/n0-computer/iroh/issues/2023)) - ([27a8ef1](https://github.com/n0-computer/iroh/commit/27a8ef14370fd0c22a9d0233a9201fcd37fd9d98))
- *(iroh-bytes)* Async bao store ([#2043](https://github.com/n0-computer/iroh/issues/2043)) - ([5398479](https://github.com/n0-computer/iroh/commit/5398479e586826a23f81a550a0fdc473116d69db))
- *(iroh-bytes)* Rewrite the blob store to use redb ([#2051](https://github.com/n0-computer/iroh/issues/2051)) - ([980b53d](https://github.com/n0-computer/iroh/commit/980b53d29f93b2b1dbdd020088133958d0970e61))
- *(iroh-bytes)* Further reduce surface area ([#2102](https://github.com/n0-computer/iroh/issues/2102)) - ([953a768](https://github.com/n0-computer/iroh/commit/953a768b3e45d577d8ca84aad8d79feced97e487))
- *(iroh-bytes)* Make module name and feature flags consistent with docs db ([#2110](https://github.com/n0-computer/iroh/issues/2110)) - ([918fca6](https://github.com/n0-computer/iroh/commit/918fca62c75d72dc143a4e3513c8ee26370af3de))
- *(iroh-bytes)* Get rid of meta dir ([#2111](https://github.com/n0-computer/iroh/issues/2111)) - ([cbc5906](https://github.com/n0-computer/iroh/commit/cbc59062f9d877e138467ac652f6e08b523e8542))
- *(iroh-net)* Log best addr on debug if not changed ([#1958](https://github.com/n0-computer/iroh/issues/1958)) - ([db41c5e](https://github.com/n0-computer/iroh/commit/db41c5e6f37e9ee50b27b5c4c7bb6053869ac8a3))
- *(iroh-net)* A bunch of logging improvements ([#1982](https://github.com/n0-computer/iroh/issues/1982)) - ([9dd77fa](https://github.com/n0-computer/iroh/commit/9dd77fa10f6675e63a397e14805dd277cd81a573))
- *(iroh-net)* Introduce a minimal DerpUrl ([#1993](https://github.com/n0-computer/iroh/issues/1993)) - ([7844577](https://github.com/n0-computer/iroh/commit/78445770add12fc387ecb89f4eac7b54b349e18a))
- *(iroh-net)* Remove manual struct logging ([#2009](https://github.com/n0-computer/iroh/issues/2009)) - ([315032a](https://github.com/n0-computer/iroh/commit/315032a5d490a9fe5d35afdce9ab65db361561eb))
- *(iroh-net)* Rename CallMeMaybe field ([#2012](https://github.com/n0-computer/iroh/issues/2012)) - ([c0637d0](https://github.com/n0-computer/iroh/commit/c0637d08dc181ab8849ecbfaf3b6c00dd3c4edaa))
- *(iroh-net)* Delete some unused testing infrastructure ([#2028](https://github.com/n0-computer/iroh/issues/2028)) - ([e7af74d](https://github.com/n0-computer/iroh/commit/e7af74da01d3608f2e1b23e53308702da50dd63f))
- *(iroh-net)* Improve API to retrieve local endpoints ([#2041](https://github.com/n0-computer/iroh/issues/2041)) - ([540fd88](https://github.com/n0-computer/iroh/commit/540fd8827fd52a98357f7901a97406a7300c5e38))
- *(iroh-net)* Avoid using .unwrap() calls ([#2046](https://github.com/n0-computer/iroh/issues/2046)) - ([827aa8d](https://github.com/n0-computer/iroh/commit/827aa8d44e101ac510c10cf35268c348a9ca4456))
- *(iroh-net)* Remove unneeded async interactions with the magicsock actor ([#2058](https://github.com/n0-computer/iroh/issues/2058)) - ([a42c1b2](https://github.com/n0-computer/iroh/commit/a42c1b2d7084a8c94af0ffd212db2453e8fd5da1))
- *(iroh-net)* Clean up peer_map, node_map and endpoint names ([#2060](https://github.com/n0-computer/iroh/issues/2060)) - ([6578d2c](https://github.com/n0-computer/iroh/commit/6578d2c0cc755dd8e41f21e8048c7e0e7358978e))
- *(iroh-net)* Bump netcheck DNS timeout to 3s ([#2077](https://github.com/n0-computer/iroh/issues/2077)) - ([24b38c8](https://github.com/n0-computer/iroh/commit/24b38c8bb2ca7cae2d6eb91ad79ae47b3f76976e))
- *(iroh-net)* Remove rebinding ([#2083](https://github.com/n0-computer/iroh/issues/2083)) - ([484e5e8](https://github.com/n0-computer/iroh/commit/484e5e8b0f52e2a176d1c5276dbbf6a2d7115257))
- *(iroh-net)* Generalize `derp` naming to `relay` to prepare for future refactors ([#2091](https://github.com/n0-computer/iroh/issues/2091)) - ([07c29f0](https://github.com/n0-computer/iroh/commit/07c29f0ca910ac1b18f3c69bdac5660ae21b2335))
- *(iroh-net)* Allow to set a custom DNS resolver on the magic endpoint ([#2116](https://github.com/n0-computer/iroh/issues/2116)) - ([8dcb196](https://github.com/n0-computer/iroh/commit/8dcb1969ddca148757bc5c64861e29f107d6d0d9))
- *(iroh-sync)* Rip out the mem implementation of the doc store ([#2112](https://github.com/n0-computer/iroh/issues/2112)) - ([cdfde7d](https://github.com/n0-computer/iroh/commit/cdfde7d78f83c86ffc7c17f211db9e774cd94351))
- *(redb-store)* Optimization for small file import in redb store ([#2062](https://github.com/n0-computer/iroh/issues/2062)) - ([8dd2c8c](https://github.com/n0-computer/iroh/commit/8dd2c8cc1527138fd997e7c83d06d3fd7168efc1))
- Use common helper function ([#1933](https://github.com/n0-computer/iroh/issues/1933)) - ([63eecd9](https://github.com/n0-computer/iroh/commit/63eecd985f00e7c02aee41684e3c0dee7392b14f))
- Move `Dialer` from iroh-gossip to iroh-net ([#1998](https://github.com/n0-computer/iroh/issues/1998)) - ([90a5160](https://github.com/n0-computer/iroh/commit/90a5160d57a3dc601388211303cbd5ce879d9a5d))
- Cleanup ProgressSliceWriter ([#2000](https://github.com/n0-computer/iroh/issues/2000)) - ([7edd7ab](https://github.com/n0-computer/iroh/commit/7edd7ab31129320b6434c3f49c10fda3754077f8))
- Move `downloader` from `iroh` to `iroh-bytes` ([#1999](https://github.com/n0-computer/iroh/issues/1999)) - ([aeee718](https://github.com/n0-computer/iroh/commit/aeee7186894ee6249aa58eac7001d87cb9edf4d7))
- Download and export structure and progress events ([#2003](https://github.com/n0-computer/iroh/issues/2003)) - ([1838c17](https://github.com/n0-computer/iroh/commit/1838c172de02bc1382ac3c886a32679bc5fb9100))
- Fallible store traits ([#2005](https://github.com/n0-computer/iroh/issues/2005)) - ([1ad6510](https://github.com/n0-computer/iroh/commit/1ad6510f997e989460b4a871dfe6fe8e415b915d))
- Move `iroh_net` base types to `iroh_base` ([#2053](https://github.com/n0-computer/iroh/issues/2053)) - ([8bdb0a0](https://github.com/n0-computer/iroh/commit/8bdb0a0035588a4cc0e3c332cd843a5726d8eefc))
- Remove derp meshing ([#2079](https://github.com/n0-computer/iroh/issues/2079)) - ([29065fd](https://github.com/n0-computer/iroh/commit/29065fdf3d080898857b7b7b7bb34fa52648d7a5))
- Make export a seperate operation from download ([#2113](https://github.com/n0-computer/iroh/issues/2113)) - ([488be5b](https://github.com/n0-computer/iroh/commit/488be5b38ae796235f9e936be8589f350ee839c8))

### 📚 Documentation

- *(derper)* Display the correct port number in the derper `--dev` help message ([#2048](https://github.com/n0-computer/iroh/issues/2048)) - ([e1c9fda](https://github.com/n0-computer/iroh/commit/e1c9fdabdb3f2caab57e4c2406176da2510da3d2))
- *(iroh-gossip)* Fix typo in proto.rs ([#1927](https://github.com/n0-computer/iroh/issues/1927)) - ([7965836](https://github.com/n0-computer/iroh/commit/7965836513fcece047f54358d3ef11e8797f9d02))

### 🧪 Testing

- *(iroh)* Sort output in test for download policies ([#1918](https://github.com/n0-computer/iroh/issues/1918)) - ([c65b7de](https://github.com/n0-computer/iroh/commit/c65b7de8962c99f46b0074a1185b93f1eccad814))
- *(iroh-net)* Make derp connect loop test more reliable ([#2064](https://github.com/n0-computer/iroh/issues/2064)) - ([9e7605d](https://github.com/n0-computer/iroh/commit/9e7605de62664f4892f15bb78faa1dabb27eea53))
- *(iroh-net)* Re-enable icmp probe test ([#2065](https://github.com/n0-computer/iroh/issues/2065)) - ([2eb06d0](https://github.com/n0-computer/iroh/commit/2eb06d0fb36705b5c79fc7ed8de39855599f14a1))
- *(iroh-net)* Disable test_icmp_probe_eu_derper as flaky on windows ([#2068](https://github.com/n0-computer/iroh/issues/2068)) - ([3a33c24](https://github.com/n0-computer/iroh/commit/3a33c246869cc31769c4e535499b3f58cd7c3a06))
- *(iroh-net)* Ignore save_load_peers test as flaky on windows ([#2070](https://github.com/n0-computer/iroh/issues/2070)) - ([a542f76](https://github.com/n0-computer/iroh/commit/a542f76390f580802a650fece342df0432e3cf11))
- *(iroh-net)* Mark some DNS tests as flaky as well ([#2073](https://github.com/n0-computer/iroh/issues/2073)) - ([aeb0067](https://github.com/n0-computer/iroh/commit/aeb00671bef9bab59d25c8b67a3c28577ab46dcb))
- *(iroh-net)* Bring back another disabled test ([#2081](https://github.com/n0-computer/iroh/issues/2081)) - ([d0b6dde](https://github.com/n0-computer/iroh/commit/d0b6dde5a6aa6a71e2dc47189546c759b766c3eb))
- Mark a bunch of flaky tests ([#1936](https://github.com/n0-computer/iroh/issues/1936)) - ([6aa77ae](https://github.com/n0-computer/iroh/commit/6aa77ae7a23e38a4fdde67c26a585b215f67e6a5))

### ⚙️ Miscellaneous Tasks

- *(ci)* Set up a separate workflow for flaky tests ([#1922](https://github.com/n0-computer/iroh/issues/1922)) - ([940b78d](https://github.com/n0-computer/iroh/commit/940b78d45d7836721f87f3b23f6c7553ba515845))
- *(ci)* Add name to tests step ([#1938](https://github.com/n0-computer/iroh/issues/1938)) - ([51cf6ed](https://github.com/n0-computer/iroh/commit/51cf6edaebb68602b469384bd6da4d66a12e1697))
- *(ci)* Run non-flaky tests again ([#1948](https://github.com/n0-computer/iroh/issues/1948)) - ([41f056b](https://github.com/n0-computer/iroh/commit/41f056bd55f4f01a84e400874a36bd79c7d752d2))
- *(ci)* Do not test nightly rust on every PR ([#1940](https://github.com/n0-computer/iroh/issues/1940)) - ([eab55bf](https://github.com/n0-computer/iroh/commit/eab55bf97acff7df3163240c7dc438520e4874f0))
- *(ci)* Run tests from the PR branch, not main ([#1971](https://github.com/n0-computer/iroh/issues/1971)) - ([f22cbf5](https://github.com/n0-computer/iroh/commit/f22cbf5ed1a6003d9a7efc276c0c0d15d6df0630))
- *(ci)* Update outdated actions ([#1997](https://github.com/n0-computer/iroh/issues/1997)) - ([c69ef60](https://github.com/n0-computer/iroh/commit/c69ef6031e7162db2e6020ca0e8c5ce4cce7893b))
- *(ci)* Notify our discord channel for flaky failures ([#2036](https://github.com/n0-computer/iroh/issues/2036)) - ([869ab7d](https://github.com/n0-computer/iroh/commit/869ab7de848f2276632c6f136a33dbbe4d64042e))
- *(ci)* Warn in our discord channel on failure ([#2044](https://github.com/n0-computer/iroh/issues/2044)) - ([6f1e13f](https://github.com/n0-computer/iroh/commit/6f1e13fb4025a36dfed6ae5172219feac430ce43))
- *(iroh)* Update quic-rpc ([#2072](https://github.com/n0-computer/iroh/issues/2072)) - ([bab35c5](https://github.com/n0-computer/iroh/commit/bab35c5680b331293aac7b4a8ce8edca5d6bfd61))
- *(iroh-bytes)* Increase redb version ([#2095](https://github.com/n0-computer/iroh/issues/2095)) - ([7bb4bfc](https://github.com/n0-computer/iroh/commit/7bb4bfc0ffc70a135f8bd2f814302e8ae4040bdc))
- *(iroh-bytes)* Update bao-tree dependency ([#2119](https://github.com/n0-computer/iroh/issues/2119)) - ([bed14d4](https://github.com/n0-computer/iroh/commit/bed14d4c4c90b46b428d99ae8d365bd4681af17f))
- *(iroh-bytes)* Increase iroh-bytes ALPN ([#2125](https://github.com/n0-computer/iroh/issues/2125)) - ([bd57656](https://github.com/n0-computer/iroh/commit/bd57656af65606aa1f6825e05ef144fa82416075))
- *(netsim)* Disable netsim prometheus reports ([#1923](https://github.com/n0-computer/iroh/issues/1923)) - ([b49314e](https://github.com/n0-computer/iroh/commit/b49314e270095df7450c0bfd08d8a23c6b96029d))
- Update dependencies in Cargo.lock ([#1960](https://github.com/n0-computer/iroh/issues/1960)) - ([d5502b1](https://github.com/n0-computer/iroh/commit/d5502b1ebb42902d19887fe2e9e8013738a8bf61))
- Fix typos ([#1964](https://github.com/n0-computer/iroh/issues/1964)) - ([c2359e8](https://github.com/n0-computer/iroh/commit/c2359e899398a341bd881fb40d34e491a2163d8b))
- Add conventional-commit-checker ([#2020](https://github.com/n0-computer/iroh/issues/2020)) - ([983edcc](https://github.com/n0-computer/iroh/commit/983edcc0910d55035205759107fc3b318243480e))
- Update Cargo.lock ([#2106](https://github.com/n0-computer/iroh/issues/2106)) - ([77df843](https://github.com/n0-computer/iroh/commit/77df8435267520d9b8edaea0c30f3af48071931c))
- Release - ([024a9b8](https://github.com/n0-computer/iroh/commit/024a9b844f078f6c3ce678311f6e8954480959b0))

### Deps

- *(iroh)* Update quic-rpc ([#2016](https://github.com/n0-computer/iroh/issues/2016)) - ([c04307e](https://github.com/n0-computer/iroh/commit/c04307e399beb80a6ee512788972ee58b53591d1))
- Upgrade away from yanked bumpalo version ([#2035](https://github.com/n0-computer/iroh/issues/2035)) - ([b90508a](https://github.com/n0-computer/iroh/commit/b90508a2e1511e2a0db67a78ab43d2e88c79593d))

### Example

- *(iroh-net)* Minimal use of unreliable datagram ([#1967](https://github.com/n0-computer/iroh/issues/1967)) - ([12e42b3](https://github.com/n0-computer/iroh/commit/12e42b3267b44e4972692513178a2ce8dc4f48b2))

## [0.12.0](https://github.com/n0-computer/iroh/compare/v0.11.0..v0.12.0) - 2023-12-20

### ⛰️  Features

- *(bytes)* Switch to a single directory for the flat store ([#1855](https://github.com/n0-computer/iroh/issues/1855)) - ([adc88f3](https://github.com/n0-computer/iroh/commit/adc88f39bf56a08973b28a316113081fe0ededfd))
- *(net)* Add `Magicsock::network_change` ([#1845](https://github.com/n0-computer/iroh/issues/1845)) - ([3952b04](https://github.com/n0-computer/iroh/commit/3952b04281bf8f5c9a8e9f740dd6dc576ae09337))
- Usage metrics reporting ([#1862](https://github.com/n0-computer/iroh/issues/1862)) - ([7ec4d92](https://github.com/n0-computer/iroh/commit/7ec4d92ef406e16d5f1f9a708abfa0bd88fe7019))
- Remove derp regions in favor of direct urls ([#1831](https://github.com/n0-computer/iroh/issues/1831)) - ([4002c46](https://github.com/n0-computer/iroh/commit/4002c465af5404b3cc73f4dfa7f0ec05730ba779))
- Additional public get utils - ([1389857](https://github.com/n0-computer/iroh/commit/1389857c1881eca36f9584fbfe74ab94c1c1b146))

### 🐛 Bug Fixes

- *(ci)* Enable forks to run netsim manually ([#1834](https://github.com/n0-computer/iroh/issues/1834)) - ([54acfcb](https://github.com/n0-computer/iroh/commit/54acfcb63de2602be7afd2c53e84b08fa5aca7c0))
- *(iroh)* Check output for blob get ([#1898](https://github.com/n0-computer/iroh/issues/1898)) - ([52f17a3](https://github.com/n0-computer/iroh/commit/52f17a3997e360e2607f2bd4179e464527a4a4b1))
- *(iroh)* Do not exit after commands ([#1899](https://github.com/n0-computer/iroh/issues/1899)) - ([53ab3b0](https://github.com/n0-computer/iroh/commit/53ab3b02cb891a823bdfe9576caabff36f321d05))
- *(iroh-net)* Fix display of mixed type connections ([#1882](https://github.com/n0-computer/iroh/issues/1882)) - ([9d047e0](https://github.com/n0-computer/iroh/commit/9d047e0ebd42a0f1d34a1567c77dbc86bd9178dc))
- *(iroh-net)* Do not prune addrs that are just added ([#1916](https://github.com/n0-computer/iroh/issues/1916)) - ([4b18e67](https://github.com/n0-computer/iroh/commit/4b18e67f1df1ec1d488473d38f42081b726f5f2b))
- *(sync)* Handle migration 004 in the empty case ([#1852](https://github.com/n0-computer/iroh/issues/1852)) - ([860563f](https://github.com/n0-computer/iroh/commit/860563f55cbf4c7c1167a98cfd1b3e479529be73))
- Use `path_to_key` helper function in `iroh doc import` ([#1811](https://github.com/n0-computer/iroh/issues/1811)) - ([64b668e](https://github.com/n0-computer/iroh/commit/64b668ede57086353a85bd33bbbaeceabec405f5))
- Do not block on network change ([#1885](https://github.com/n0-computer/iroh/issues/1885)) - ([54d5efc](https://github.com/n0-computer/iroh/commit/54d5efcf72ab548209eda2f1ce8ecfaec3f73b7d))
- Fix abort on ctrl-c in console ([#1909](https://github.com/n0-computer/iroh/issues/1909)) - ([712b45e](https://github.com/n0-computer/iroh/commit/712b45ecc6c6c673998fb724357f46c63ec9c669))

### 🚜 Refactor

- *(iroh)* Remove the addr arg from start ([#1830](https://github.com/n0-computer/iroh/issues/1830)) - ([e03de38](https://github.com/n0-computer/iroh/commit/e03de38302d81b976f3c0d199ee9ca68800507ae))
- *(iroh)* Remove request token ([#1828](https://github.com/n0-computer/iroh/issues/1828)) - ([1dfb7ac](https://github.com/n0-computer/iroh/commit/1dfb7acfd94ee829c066babe6a5409dd6c468c95))
- *(iroh)* Remove rpc port option ([#1842](https://github.com/n0-computer/iroh/issues/1842)) - ([d1fcfca](https://github.com/n0-computer/iroh/commit/d1fcfcaba85a30fb4d00e626f4442e1da1324f56))
- *(iroh-bytes)* Remove explicitly passing the runtime to the flat store ([#1829](https://github.com/n0-computer/iroh/issues/1829)) - ([3d2e118](https://github.com/n0-computer/iroh/commit/3d2e118989dbef1a7f93bd9b7aba93e87652ac25))
- *(iroh-net)* Make `ControlMsg` public ([#1895](https://github.com/n0-computer/iroh/issues/1895)) - ([c6bc3c2](https://github.com/n0-computer/iroh/commit/c6bc3c2ba9cfac8cdbdb97bdb1c7cfb951539893))
- *(logging)* Reduce loglevel of blob GC ([#1866](https://github.com/n0-computer/iroh/issues/1866)) - ([3b1652c](https://github.com/n0-computer/iroh/commit/3b1652c6655ac5955120e8eb7b784a5b2b69331b))
- *(tests)* Slow down a hot loop ([#1910](https://github.com/n0-computer/iroh/issues/1910)) - ([9ac88ef](https://github.com/n0-computer/iroh/commit/9ac88ef76f170c17a4d347f4edd35e8ca504a60b))
- Upgrade to hyper 1.0 ([#1858](https://github.com/n0-computer/iroh/issues/1858)) - ([b8aa5d6](https://github.com/n0-computer/iroh/commit/b8aa5d6c48a1b28e5801e095ba23bb655b33a6d7))
- Streamline local endpoint discovery ([#1847](https://github.com/n0-computer/iroh/issues/1847)) - ([cb20bb8](https://github.com/n0-computer/iroh/commit/cb20bb89099975d724cbde2633ff069c89f80f22))
- Client `Entry` with methods to read content ([#1854](https://github.com/n0-computer/iroh/issues/1854)) - ([690e2aa](https://github.com/n0-computer/iroh/commit/690e2aa85d5f83ede8f6ebb2ba49d614b43b2883))

### 🧪 Testing

- *(iroh-net)* Try fix flaky udp_blocked test - ([0418af6](https://github.com/n0-computer/iroh/commit/0418af6399dc6e0d107415c9ab23a6e006405580))
- *(net)* Use actual derp hostname and reduce iteration count ([#1886](https://github.com/n0-computer/iroh/issues/1886)) - ([62ac4d8](https://github.com/n0-computer/iroh/commit/62ac4d8bb57329bc65cf126fabace882066ddb8a))

### ⚙️ Miscellaneous Tasks

- *(ci)* Run cargo build for android platforms ([#1843](https://github.com/n0-computer/iroh/issues/1843)) - ([227f0e8](https://github.com/n0-computer/iroh/commit/227f0e831f2be02574e67531e0869b2f139ba208))
- *(ci)* Configure sccache to use local caches ([#1865](https://github.com/n0-computer/iroh/issues/1865)) - ([4b07c2d](https://github.com/n0-computer/iroh/commit/4b07c2d5d3b7796b27dc1893314db654507a6cb3))
- *(ci)* Split jobs so they do not stomp over target directory ([#1871](https://github.com/n0-computer/iroh/issues/1871)) - ([b9709ef](https://github.com/n0-computer/iroh/commit/b9709ef871099e1500a34571e0950234d85c23d9))
- *(ci)* Pin clippy to specific nightly version ([#1874](https://github.com/n0-computer/iroh/issues/1874)) - ([6433a66](https://github.com/n0-computer/iroh/commit/6433a6699f58d7431eadf7ba585c978b5ead0cb9))
- *(ci)* Windows sccache ([#1873](https://github.com/n0-computer/iroh/issues/1873)) - ([0d9ebea](https://github.com/n0-computer/iroh/commit/0d9ebea18af62bcf83ffb87fbb8b97cfcd7301a4))
- *(ci)* Split release builds from regular CI flows ([#1883](https://github.com/n0-computer/iroh/issues/1883)) - ([ce97cee](https://github.com/n0-computer/iroh/commit/ce97ceee55d455aa5d6ff46bf2026dd162c13c14))
- *(ci)* Test derper deploy flow ([#1884](https://github.com/n0-computer/iroh/issues/1884)) - ([a1c5b56](https://github.com/n0-computer/iroh/commit/a1c5b563f689c98e0a6fc4fbefc2c528a53da359))
- *(ci)* Use TRACE logging for tests run by nextest ([#1902](https://github.com/n0-computer/iroh/issues/1902)) - ([b789a1f](https://github.com/n0-computer/iroh/commit/b789a1fccdde69c496fdf344d6476a0be51a6455))
- *(clippy)* Fix some warnings ([#1861](https://github.com/n0-computer/iroh/issues/1861)) - ([57bb691](https://github.com/n0-computer/iroh/commit/57bb691dfe60417ec8bc3108afefdc84b7d20dfd))
- *(docs)* Update derp IP for EU region ([#1880](https://github.com/n0-computer/iroh/issues/1880)) - ([5c43b1d](https://github.com/n0-computer/iroh/commit/5c43b1dc3eb5e08221f0e5765e80844577ecab6f))
- *(iroh,iroh-bytes)* Fix manifest keywords ([#1881](https://github.com/n0-computer/iroh/issues/1881)) - ([b4da5f4](https://github.com/n0-computer/iroh/commit/b4da5f4212dd8f71240c1df40b5effd2df9eb8f3))
- Add BSD3 license note for code derived from tailscale ([#1889](https://github.com/n0-computer/iroh/issues/1889)) - ([876a0f5](https://github.com/n0-computer/iroh/commit/876a0f582ef311d4a2fa07ba88ae8cbf74b3ed5c))
- Release - ([deec1d6](https://github.com/n0-computer/iroh/commit/deec1d6a89a62a1e459ebad63407bfc56e96d880))

### Ref

- *(iroh-net)* Improve how STUN probes are run ([#1642](https://github.com/n0-computer/iroh/issues/1642)) - ([b95eb86](https://github.com/n0-computer/iroh/commit/b95eb86fa0a00d196db6bb72685483766d8da898))

## [0.11.0](https://github.com/n0-computer/iroh/compare/v0.10.0..v0.11.0) - 2023-11-17

### ⛰️  Features

- *(iroh)* Store rpc port in iroh data dir ([#1783](https://github.com/n0-computer/iroh/issues/1783)) - ([d471477](https://github.com/n0-computer/iroh/commit/d471477659cd9018bdaebdfa3c0146451d5d3b43))
- *(iroh)* Make `out` argument required for `iroh get` ([#1786](https://github.com/n0-computer/iroh/issues/1786)) - ([0e0f641](https://github.com/n0-computer/iroh/commit/0e0f6411d0fbe88559db132a06b0ccf64bf831f4))
- *(iroh)* Allow full and short hash printing in the cli ([#1795](https://github.com/n0-computer/iroh/issues/1795)) - ([018772c](https://github.com/n0-computer/iroh/commit/018772ce2f8a06f98447160f33a9720da4ea5939))
- Add `Doc::import_file` and `Doc::export_file` ([#1793](https://github.com/n0-computer/iroh/issues/1793)) - ([fe7fc50](https://github.com/n0-computer/iroh/commit/fe7fc506c7ac5bc7be518d407829580d880b0f62))

### 🐛 Bug Fixes

- *(iroh-sync)* Ensure the authors table exists ([#1807](https://github.com/n0-computer/iroh/issues/1807)) - ([39ed64e](https://github.com/n0-computer/iroh/commit/39ed64e4492393b133398f49a957614fd3535968))
- Drop temp tag after doc insert ([#1810](https://github.com/n0-computer/iroh/issues/1810)) - ([a608fe8](https://github.com/n0-computer/iroh/commit/a608fe8c7562286629a41d70fbbef05382443649))
- Netsim should fail on all failed tests ([#1816](https://github.com/n0-computer/iroh/issues/1816)) - ([199a677](https://github.com/n0-computer/iroh/commit/199a677121ac469634ba1c2d6c6d412f75c1e3c8))

### 🚜 Refactor

- *(iroh)* Restructure cli modules to match command structure ([#1799](https://github.com/n0-computer/iroh/issues/1799)) - ([c1aeeb1](https://github.com/n0-computer/iroh/commit/c1aeeb12898d86bce901ec6ec9d54ada026c7adf))
- *(iroh)* Add `--start` option to CLI commands ([#1802](https://github.com/n0-computer/iroh/issues/1802)) - ([10af401](https://github.com/n0-computer/iroh/commit/10af4018302ee62fdad8fbbbe8c3902a9082bb35))
- *(logging)* Log hairpin results at debug level ([#1809](https://github.com/n0-computer/iroh/issues/1809)) - ([ca8a983](https://github.com/n0-computer/iroh/commit/ca8a98383bc69d672073edb0df8086ae83a0b893))
- Common base library ([#1780](https://github.com/n0-computer/iroh/issues/1780)) - ([de58d71](https://github.com/n0-computer/iroh/commit/de58d71998e49ed14c99b9765fc51d37965a95d9))
- More renaming of the term peer id to node id ([#1789](https://github.com/n0-computer/iroh/issues/1789)) - ([53f1b61](https://github.com/n0-computer/iroh/commit/53f1b616c75bcc81c1b7493a4365c22340989a5d))

### ⚙️ Miscellaneous Tasks

- Update dependencies ([#1787](https://github.com/n0-computer/iroh/issues/1787)) - ([697b80c](https://github.com/n0-computer/iroh/commit/697b80cbe7cf17a8f39b2ab4ee4044d7074135e3))
- Release - ([0773e30](https://github.com/n0-computer/iroh/commit/0773e3088250986aabaa97d4e408bfc0c0cc6c06))

## [0.10.0](https://github.com/n0-computer/iroh/compare/v0.9.0..v0.10.0) - 2023-11-08

### ⛰️  Features

- *(iroh-sync)* Read only replicas ([#1770](https://github.com/n0-computer/iroh/issues/1770)) - ([c1ebea8](https://github.com/n0-computer/iroh/commit/c1ebea8eb9b21114b92c94f37212bb0feaf794c2))
- *(iroh-sync)* Queries and "views" ([#1766](https://github.com/n0-computer/iroh/issues/1766)) - ([899768a](https://github.com/n0-computer/iroh/commit/899768a16a4d8e3f8cc3f98d3df2e4494d8ca57f))
- Add ability to connect just by node id - ([5ee69a4](https://github.com/n0-computer/iroh/commit/5ee69a47e67b9f87a67270c15ee4e3f7cce52671))

### 🐛 Bug Fixes

- *(console)* Blob download args ([#1729](https://github.com/n0-computer/iroh/issues/1729)) - ([a916d4c](https://github.com/n0-computer/iroh/commit/a916d4cb2d5d4704715536dc73d408dac59c507a))
- *(iroh-bytes)* Ensure to flush file to disk ([#1778](https://github.com/n0-computer/iroh/issues/1778)) - ([0987022](https://github.com/n0-computer/iroh/commit/0987022e218333c6ce9249eb273ee0d39bc374b3))
- *(iroh-sync)* Fix panic in send ([#1773](https://github.com/n0-computer/iroh/issues/1773)) - ([c36cc6d](https://github.com/n0-computer/iroh/commit/c36cc6d736a99c89f108d1b9b6dc408c1474583c))
- *(iroh-sync)* Prevent panic in namespace migration ([#1775](https://github.com/n0-computer/iroh/issues/1775)) - ([84ae95a](https://github.com/n0-computer/iroh/commit/84ae95a6a51972cf92ebd116f7f84b6129766e37))

### 🚜 Refactor

- *(*)* Rename Peer to Node in peer_map related code ([#1771](https://github.com/n0-computer/iroh/issues/1771)) - ([fbeeab7](https://github.com/n0-computer/iroh/commit/fbeeab721a023cb195ac6cf1025867bb1e363244))
- *(iroh-net)* Remove cli ping ([#1764](https://github.com/n0-computer/iroh/issues/1764)) - ([2b70426](https://github.com/n0-computer/iroh/commit/2b704267b9666ad17d2dc07ad459ad983ecbafaf))
- *(iroh-net)* Rename PeerAddr to NodeAddr, introduce NodeId alias ([#1765](https://github.com/n0-computer/iroh/issues/1765)) - ([215953f](https://github.com/n0-computer/iroh/commit/215953f23089b918a74bd51276d5c9c8d7711cd0))

### ⚙️ Miscellaneous Tasks

- *(iroh-net)* Demote 'pong not received in timeout' message to debug ([#1769](https://github.com/n0-computer/iroh/issues/1769)) - ([56e92ca](https://github.com/n0-computer/iroh/commit/56e92caa1172ac416c2c2f5139a4aacd26cf27c7))
- Switch to git-cliff for changelog generation - ([bcdccb3](https://github.com/n0-computer/iroh/commit/bcdccb39fa374ec8eac84eb347f1e38c2f4dbb09))
- Release - ([c4514aa](https://github.com/n0-computer/iroh/commit/c4514aafa5e6452b881ae4917a63ab05cfe62e96))

## [0.9.0](https://github.com/n0-computer/iroh/compare/v0.8.0..v0.9.0) - 2023-10-31

### ⛰️  Features

- *(ci)* CI improvements ([#1737](https://github.com/n0-computer/iroh/issues/1737)) - ([10f5982](https://github.com/n0-computer/iroh/commit/10f5982ef62543780aa0ac89ad16aebbcdb2e98c))
- *(console)* Blob share ticket ([#1746](https://github.com/n0-computer/iroh/issues/1746)) - ([fa9fa83](https://github.com/n0-computer/iroh/commit/fa9fa836d6da29d503aa7a73909fa571d117de55))
- *(iroh)* Add ticket prefixes and a `doctor ticket-inspect` command ([#1711](https://github.com/n0-computer/iroh/issues/1711)) - ([2d292e3](https://github.com/n0-computer/iroh/commit/2d292e30b41e557c03ddbab9f2bd73942af82e78))
- *(iroh)* Pass a runtime to Doc client to spawn close task on drop ([#1758](https://github.com/n0-computer/iroh/issues/1758)) - ([0c145d5](https://github.com/n0-computer/iroh/commit/0c145d5dc77cf51de5c917e68f87b54085f87565))

### 🐛 Bug Fixes

- *(ci)* Avoid sccache on linux aarch64 builds ([#1762](https://github.com/n0-computer/iroh/issues/1762)) - ([054020b](https://github.com/n0-computer/iroh/commit/054020bacdd28d60cd004138302f4c9f6152ef22))
- *(console)* Remove ticket separator to improve usability ([#1754](https://github.com/n0-computer/iroh/issues/1754)) - ([f6c6932](https://github.com/n0-computer/iroh/commit/f6c69324975c1908d20dfba308f0931e600c7fc6))
- *(deps)* Iroh-sync - ([261debf](https://github.com/n0-computer/iroh/commit/261debfaae664e9e63a463d57aa83c824df7b5b4))
- *(iroh)* Handle rpc args in any position ([#1739](https://github.com/n0-computer/iroh/issues/1739)) - ([0ca61ad](https://github.com/n0-computer/iroh/commit/0ca61ad60eecaaf7f2987e88edb6c0d10b62f7f9))
- *(iroh-net)* Correctly set the time in which a probe is created ([#1722](https://github.com/n0-computer/iroh/issues/1722)) - ([d44a7dc](https://github.com/n0-computer/iroh/commit/d44a7dc70e950e75a7043ec90f045d67ff09f863))
- *(net)* Do not dial regions in parallel ([#1736](https://github.com/n0-computer/iroh/issues/1736)) - ([c851fe1](https://github.com/n0-computer/iroh/commit/c851fe1e2da221e2358ed7a1a3eea4e0db15513a))
- Update ahash ([#1708](https://github.com/n0-computer/iroh/issues/1708)) - ([118c1d7](https://github.com/n0-computer/iroh/commit/118c1d70da3394796b777e776ce3c87272f2e52c))
- Do not block on netcheck ([#1745](https://github.com/n0-computer/iroh/issues/1745)) - ([8e6f5a9](https://github.com/n0-computer/iroh/commit/8e6f5a96ba28262de9a896d475d0e999814cab99))
- Do not wait_idle on endpoint close ([#1753](https://github.com/n0-computer/iroh/issues/1753)) - ([f4735c6](https://github.com/n0-computer/iroh/commit/f4735c6052801876a26fdc880f9e1504757e0465))
- Do not block on dropping UDP sockets ([#1755](https://github.com/n0-computer/iroh/issues/1755)) - ([cadb89b](https://github.com/n0-computer/iroh/commit/cadb89b900131cbcadf559fd6c923021b3469c6b))
- Release builds ([#1763](https://github.com/n0-computer/iroh/issues/1763)) - ([c90b78d](https://github.com/n0-computer/iroh/commit/c90b78d7a14b6490e2298348c8b53a3032533f60))

### 🚜 Refactor

- *(iroh-net)* Split `endpoint` module and reduce `PeerMap` surface ([#1718](https://github.com/n0-computer/iroh/issues/1718)) - ([eb99d0f](https://github.com/n0-computer/iroh/commit/eb99d0f2db93ca0159c2ba872ece7e7297c64aca))
- *(iroh-net)* Improve `PeerMap` and `Endpoint` abstractions ([#1724](https://github.com/n0-computer/iroh/issues/1724)) - ([e1cfe50](https://github.com/n0-computer/iroh/commit/e1cfe502c340bad9800656068e330783217dc674))
- *(iroh-net)* Call-me-maybe improvements (no more tasks for queue, better logic on recv) ([#1752](https://github.com/n0-computer/iroh/issues/1752)) - ([376748c](https://github.com/n0-computer/iroh/commit/376748c295382d4738744a0581f8aabbfcb1b6e7))

### 🧪 Testing

- Disable sync_big ([#1760](https://github.com/n0-computer/iroh/issues/1760)) - ([f68d55d](https://github.com/n0-computer/iroh/commit/f68d55db00a80bae892de32278a4ad0ad8f2988c))

### ⚙️ Miscellaneous Tasks

- Makes `SyncReason` public (as expected) ([#1756](https://github.com/n0-computer/iroh/issues/1756)) - ([dff946c](https://github.com/n0-computer/iroh/commit/dff946c4841c05440fa18e9f5281a4ba52b32e9b))
- Split test and check steps into workspace and per crate ([#1761](https://github.com/n0-computer/iroh/issues/1761)) - ([eb2f73a](https://github.com/n0-computer/iroh/commit/eb2f73a00e8d781de36fbb1e26fa7023c6079f10))
- Match iroh-net-bench version number - ([f0a1b2c](https://github.com/n0-computer/iroh/commit/f0a1b2c9e71e0ce9f04b716e190085e8b74964d5))
- Changelog v0.9.0 - ([f851b8b](https://github.com/n0-computer/iroh/commit/f851b8bfbaa0f4996144429befc2d3a7ed8a8937))
- Release - ([eba3c33](https://github.com/n0-computer/iroh/commit/eba3c3304b20f7504a541818cf19ddfbbe717e15))

### Clippy

- Warn on unsused async fn ([#1743](https://github.com/n0-computer/iroh/issues/1743)) - ([7068f33](https://github.com/n0-computer/iroh/commit/7068f33ce2609a01b8707efbd370680f09a67102))

### Example

- *(magic)* Make arguments to connect named  - ([232a4ee](https://github.com/n0-computer/iroh/commit/232a4ee81ebe4effb833f8d6fec168be9ed58557))

## [0.8.0](https://github.com/n0-computer/iroh/compare/v0.7.0..v0.8.0) - 2023-10-23

### ⛰️  Features

- *(console)* Improve the output of `node connections` and `node connection` ([#1683](https://github.com/n0-computer/iroh/issues/1683)) - ([d0c7cac](https://github.com/n0-computer/iroh/commit/d0c7cac635633048c3dc09a70ed5d7d44a2c98bf))
- *(iroh-net)* Cache for crypto keys ([#1677](https://github.com/n0-computer/iroh/issues/1677)) - ([f8f08a0](https://github.com/n0-computer/iroh/commit/f8f08a0e78ed75f1eefa26d23243240d41fdf934))
- *(iroh-sync)* Sync propagation ([#1613](https://github.com/n0-computer/iroh/issues/1613)) - ([d07e225](https://github.com/n0-computer/iroh/commit/d07e22510d618adee982e5a0f8d04c3dc23b2063))
- Update dependencies ([#1661](https://github.com/n0-computer/iroh/issues/1661)) - ([133ca8a](https://github.com/n0-computer/iroh/commit/133ca8af1059f797bcbfd6a178bfab77c62ddcb7))

### 🐛 Bug Fixes

- *(iroh)* Do not exit on ctrl+c ([#1691](https://github.com/n0-computer/iroh/issues/1691)) - ([a658d4a](https://github.com/n0-computer/iroh/commit/a658d4a7d9f26033dd07175f3d4d6c0c008f7001))
- *(iroh)* Cleanly exit on Eof ([#1695](https://github.com/n0-computer/iroh/issues/1695)) - ([196ad7a](https://github.com/n0-computer/iroh/commit/196ad7a16874acf2b9d17b6217be9791ac8b3c0f))
- *(iroh-bytes)* Handle case of 0 sent bytes in send stats ([#1625](https://github.com/n0-computer/iroh/issues/1625)) - ([550303c](https://github.com/n0-computer/iroh/commit/550303cfaef0a16968e8992f1f04415325d71c22))
- *(iroh-net)* Enforce storing a single derp region per peer ([#1607](https://github.com/n0-computer/iroh/issues/1607)) - ([bfcce3d](https://github.com/n0-computer/iroh/commit/bfcce3d80c6fa20a4e36bd1f4ae4580716dc482e))
- *(iroh-net)* Ping via relay, enable relay ping in derp only mode ([#1632](https://github.com/n0-computer/iroh/issues/1632)) - ([eec5425](https://github.com/n0-computer/iroh/commit/eec5425b4ba3f7cf5a0832f138f20871ce1843f6))
- *(iroh-net)* Bring the doctor command up to date ([#1656](https://github.com/n0-computer/iroh/issues/1656)) - ([16773b0](https://github.com/n0-computer/iroh/commit/16773b08cba7454c6a4e984f37d1324700fb481b))
- *(iroh-net)* Direct address management ([#1653](https://github.com/n0-computer/iroh/issues/1653)) - ([90f73f7](https://github.com/n0-computer/iroh/commit/90f73f7d5387413cbc9227101deea66bc9d97194))
- *(iroh-net)* Temp fix for progress bar when downloading a hash seq ([#1658](https://github.com/n0-computer/iroh/issues/1658)) - ([1b5760d](https://github.com/n0-computer/iroh/commit/1b5760dfa94872fe754bb8e73f10a580903ac6e2))
- *(net)* Correct packet math for poll_recv ([#1698](https://github.com/n0-computer/iroh/issues/1698)) - ([c603a9e](https://github.com/n0-computer/iroh/commit/c603a9ec53f54e51124b420863e9e471caf0b6f5))
- *(net)* Correctly track dial errors ([#1706](https://github.com/n0-computer/iroh/issues/1706)) - ([92bb5b4](https://github.com/n0-computer/iroh/commit/92bb5b4cdd16725fd62d612e05ed9194c296c117))
- `doc export` exports the latest entry at a given key ([#1629](https://github.com/n0-computer/iroh/issues/1629)) - ([b815576](https://github.com/n0-computer/iroh/commit/b8155763dbbd0fa7be2c2ca4047e7f241e881a0c))
- Actually transfer newer entries for identical keys ([#1630](https://github.com/n0-computer/iroh/issues/1630)) - ([ef8c64b](https://github.com/n0-computer/iroh/commit/ef8c64b79c480ee6f133f1bb0386aea3c1686576))
- Avoid FuturesUnordered ([#1647](https://github.com/n0-computer/iroh/issues/1647)) - ([5813e09](https://github.com/n0-computer/iroh/commit/5813e09445cb7520aab49f6bf3c25a269c01e9b0))
- Dependency updates - ([2323114](https://github.com/n0-computer/iroh/commit/23231140c575f57dbec497bcf2317c7d172f41be))

### 🚜 Refactor

- *(iroh-net)* Don't send pings over the actor channel ([#1678](https://github.com/n0-computer/iroh/issues/1678)) - ([0cbab51](https://github.com/n0-computer/iroh/commit/0cbab51a7b7343e78626c0e05d038f9b7bd5e596))
- *(iroh-net)* Proper abstraction around `best_addr` ([#1675](https://github.com/n0-computer/iroh/issues/1675)) - ([7baff93](https://github.com/n0-computer/iroh/commit/7baff932d92a834a67a563fbe5edcbcf37627ab8))
- *(iroh-sync)* Add actor to iroh-sync, remove deadlocks ([#1612](https://github.com/n0-computer/iroh/issues/1612)) - ([a70c6f1](https://github.com/n0-computer/iroh/commit/a70c6f16aed16cb9a3395fa3811e1ebe63367590))
- *(iroh-sync)* Remove generic from SyncEngine ([#1648](https://github.com/n0-computer/iroh/issues/1648)) - ([53b0bb0](https://github.com/n0-computer/iroh/commit/53b0bb058a2aae635e07d1db7db76a1f9b6189ed))
- *(net)* Improve derp client handling ([#1674](https://github.com/n0-computer/iroh/issues/1674)) - ([56d4d3f](https://github.com/n0-computer/iroh/commit/56d4d3fb7d414c7644b840fd970f780e60e5b400))

### 📚 Documentation

- `test_run_mesh_client` documentation ([#1697](https://github.com/n0-computer/iroh/issues/1697)) - ([d5aef12](https://github.com/n0-computer/iroh/commit/d5aef1220f56d809b59fc99bda9f524d49cc6dab))

### ⚡ Performance

- Improve derp connection establishment ([#1631](https://github.com/n0-computer/iroh/issues/1631)) - ([615381c](https://github.com/n0-computer/iroh/commit/615381c6e126304924d1ec476a744cb2514dca61))
- No more channels for UDP send/recv ([#1579](https://github.com/n0-computer/iroh/issues/1579)) - ([d6657bd](https://github.com/n0-computer/iroh/commit/d6657bd59b9c2e8f002fd80d5e1f1091aed1c9dc))

### 🧪 Testing

- *(iroh-net)* Do not use fixed ports ([#1689](https://github.com/n0-computer/iroh/issues/1689)) - ([8dd0509](https://github.com/n0-computer/iroh/commit/8dd0509a74c53772c14f98a1decff92e4ff87563))

### ⚙️ Miscellaneous Tasks

- *(*)* Update tracing to fix audit failure ([#1684](https://github.com/n0-computer/iroh/issues/1684)) - ([0a5a8e8](https://github.com/n0-computer/iroh/commit/0a5a8e853a7a564652edce98b51d2f6dae9a6ccb))
- *(*)* Remove unused deps ([#1699](https://github.com/n0-computer/iroh/issues/1699)) - ([3006791](https://github.com/n0-computer/iroh/commit/30067913ba13879ecfdfe14a06098c548090b3fe))
- *(derp)* Update default derpers ([#1622](https://github.com/n0-computer/iroh/issues/1622)) - ([d187827](https://github.com/n0-computer/iroh/commit/d187827ef28bbe8ec67b0ac3a1f506e495fc2f50))
- Release - ([7fcb174](https://github.com/n0-computer/iroh/commit/7fcb1746f521cd94d4c4a7f6368819dd317bfc70))

### Iroh-bytes

- Get api improvements ([#1660](https://github.com/n0-computer/iroh/issues/1660)) - ([6a630d9](https://github.com/n0-computer/iroh/commit/6a630d925eebc00cd1739b8ac7aabc4def831702))
- Show connection status in doctor accept / connect GUI ([#1666](https://github.com/n0-computer/iroh/issues/1666)) - ([215c5fc](https://github.com/n0-computer/iroh/commit/215c5fc8e1e960f46033254cc0a3d131b286cd9d))

### Iroh-net

- Doctor improvements ([#1663](https://github.com/n0-computer/iroh/issues/1663)) - ([8169053](https://github.com/n0-computer/iroh/commit/8169053a0605f848ac3bade7b09833b4636333a6))
- Use BTreeSet for AddrInfo ([#1672](https://github.com/n0-computer/iroh/issues/1672)) - ([a93e89e](https://github.com/n0-computer/iroh/commit/a93e89e9c84e757823bfec089dc92110a46aa33d))

### Release

- Add changelog for v0.8.0 - ([e972d53](https://github.com/n0-computer/iroh/commit/e972d532ed6847f15430238e74c96dd9be485feb))

## [0.7.0](https://github.com/n0-computer/iroh/compare/v0.6.0..v0.7.0) - 2023-10-11

### ⛰️  Features

- *(*)* Log me ([#1561](https://github.com/n0-computer/iroh/issues/1561)) - ([7e79227](https://github.com/n0-computer/iroh/commit/7e79227e5ea4f71cca7a0ee70a6ac0714c09141c))
- *(iroh)* Export path and config related tooling ([#1570](https://github.com/n0-computer/iroh/issues/1570)) - ([c284793](https://github.com/n0-computer/iroh/commit/c284793ebc554ad87c3f388800da2b71452bb8e9))
- *(iroh)* Improve displaying content in the repl ([#1577](https://github.com/n0-computer/iroh/issues/1577)) - ([2fd31b7](https://github.com/n0-computer/iroh/commit/2fd31b776742bac080f421a05085a086d1f19ed9))
- *(iroh)* Use reflink if possible ([#1581](https://github.com/n0-computer/iroh/issues/1581)) - ([e2ee678](https://github.com/n0-computer/iroh/commit/e2ee6784a92d84fa6418b7becdd9f0f75e35e6cb))
- *(iroh)* Show content as hex when utf8 fails ([#1596](https://github.com/n0-computer/iroh/issues/1596)) - ([872f3b1](https://github.com/n0-computer/iroh/commit/872f3b1fff7ebdb8844dbc5aaa8ab8d0c4e64ac5))
- *(iroh-sync)* Store peers per doc ([#1564](https://github.com/n0-computer/iroh/issues/1564)) - ([31f08bb](https://github.com/n0-computer/iroh/commit/31f08bb082b3a568634c6afc79ead077e069b167))
- *(sync)* Implement prefix deletion ([#1535](https://github.com/n0-computer/iroh/issues/1535)) - ([e7fc8be](https://github.com/n0-computer/iroh/commit/e7fc8be00e167743e10d0902f1e502b4df23a68b))
- Use `BlobFormat` and properly support adding raw blobs ([#1518](https://github.com/n0-computer/iroh/issues/1518)) - ([f3ed0ba](https://github.com/n0-computer/iroh/commit/f3ed0ba9bd2bcd68cccb523b8364c3ad33e26d03))
- Add blobs from byte streams ([#1550](https://github.com/n0-computer/iroh/issues/1550)) - ([e138400](https://github.com/n0-computer/iroh/commit/e138400062624d268bbb315be6310d2ba2d9e639))
- Leave and drop docs ([#1589](https://github.com/n0-computer/iroh/issues/1589)) - ([d7a3dd3](https://github.com/n0-computer/iroh/commit/d7a3dd3f3c9cf99767cb9cacdc016d518c7f717d))
- `doc import` & `doc export` commands ([#1563](https://github.com/n0-computer/iroh/issues/1563)) - ([3c0195c](https://github.com/n0-computer/iroh/commit/3c0195c9e771cf0b7d24d413b606eaf997134a8a))

### 🐛 Bug Fixes

- *(`iroh::downloader`)* Remove hash from `providers` in two missed cases ([#1584](https://github.com/n0-computer/iroh/issues/1584)) - ([068f0bd](https://github.com/n0-computer/iroh/commit/068f0bde4d8f2ba07f806a13830fa5cbeb9a558c))
- *(cli,console)* Default to 'hash' mode for the keys command ([#1617](https://github.com/n0-computer/iroh/issues/1617)) - ([c3571e1](https://github.com/n0-computer/iroh/commit/c3571e13e12118a85c9aa31f15e8027e9f1e8cf5))
- *(derper)* Update config to auto generate keys ([#1599](https://github.com/n0-computer/iroh/issues/1599)) - ([8fb46d4](https://github.com/n0-computer/iroh/commit/8fb46d49e1d7c6e3da47c56b206e26210dcd7f4a))
- *(iroh-net)* Do not unwrap sending on response channel ([#1529](https://github.com/n0-computer/iroh/issues/1529)) - ([974b66e](https://github.com/n0-computer/iroh/commit/974b66e3ea01156b4fc6e7fa4d08f638c5b9b2b2))
- *(iroh-net)* Dialer bug ([#1533](https://github.com/n0-computer/iroh/issues/1533)) - ([16939c8](https://github.com/n0-computer/iroh/commit/16939c86177820904c6b4b20ff685cc49f3d93cc))
- *(iroh-net)* Reverse ip-port mapping stores only direct addresses in the peermap ([#1606](https://github.com/n0-computer/iroh/issues/1606)) - ([176d632](https://github.com/n0-computer/iroh/commit/176d6322d04c61e4023c33a9f014633ee6c39397))
- *(metrics)* Labels need to be lowercase underscore format ([#1574](https://github.com/n0-computer/iroh/issues/1574)) - ([81c6f04](https://github.com/n0-computer/iroh/commit/81c6f04b85af7832e8e06d07a4555efb75dd7849))
- *(net)* Avoid deadlock on stayin_alive calls ([#1537](https://github.com/n0-computer/iroh/issues/1537)) - ([34fa30a](https://github.com/n0-computer/iroh/commit/34fa30a4f2b1ac278685712583e9e3a64209edd8))
- *(net)* Stop deleting endpoints we want to keep ([#1567](https://github.com/n0-computer/iroh/issues/1567)) - ([96cd106](https://github.com/n0-computer/iroh/commit/96cd1060a0a2bd0679e3e23da5d04068ce58d203))
- Mark initially created endpoints inactive ([#1539](https://github.com/n0-computer/iroh/issues/1539)) - ([9b61ab7](https://github.com/n0-computer/iroh/commit/9b61ab7737777878036ce24e07c55fdf405dba9d))
- Actually allow to disable DERP ([#1560](https://github.com/n0-computer/iroh/issues/1560)) - ([cf9abc0](https://github.com/n0-computer/iroh/commit/cf9abc02c8becbfc1754dfa02ac04bd990d0867a))
- Avoid blockage in endpoint handling ([#1569](https://github.com/n0-computer/iroh/issues/1569)) - ([ccdf0c9](https://github.com/n0-computer/iroh/commit/ccdf0c962eea97bf0d63ccabe2620744c50f82f5))
- Feature flags for iroh-io dependency ([#1588](https://github.com/n0-computer/iroh/issues/1588)) - ([c1c7d15](https://github.com/n0-computer/iroh/commit/c1c7d15e4e52f15f1e34fccb6085aefbc9cc255d))

### 🚜 Refactor

- *(iroh-net)* Store a single pong ([#1601](https://github.com/n0-computer/iroh/issues/1601)) - ([0d17e81](https://github.com/n0-computer/iroh/commit/0d17e81185c5a598d38d68ab6bbe2c1532fb83e9))

### 📚 Documentation

- *(changelog)* V0.7.0 - ([f3fe93d](https://github.com/n0-computer/iroh/commit/f3fe93d58c3ca7e3516dd25bc8bcc622edbce32e))
- *(iroh)* Fix broken docs for tags subcommand... ([#1573](https://github.com/n0-computer/iroh/issues/1573)) - ([bb74e2c](https://github.com/n0-computer/iroh/commit/bb74e2cedff988fbc694cdacb3583d357c572aad))
- Tune up docs before release ([#1614](https://github.com/n0-computer/iroh/issues/1614)) - ([af06677](https://github.com/n0-computer/iroh/commit/af06677b4c33bc426afa8b6d6a8f76f62b524eb8))

### ⚡ Performance

- *(iroh-net)* Simplify stun::is check ([#1580](https://github.com/n0-computer/iroh/issues/1580)) - ([0b28d15](https://github.com/n0-computer/iroh/commit/0b28d15227c7b6967b48bab2eb115b7a70e7b519))

### 🧪 Testing

- *(iroh-net)* E2e saving and loading of peer data ([#1523](https://github.com/n0-computer/iroh/issues/1523)) - ([e7e70e4](https://github.com/n0-computer/iroh/commit/e7e70e4c601e611a07c2142a57df6c66ecf147dd))
- *(iroh-sync)* Fix `test_content_hashes_iterator_memory` ([#1565](https://github.com/n0-computer/iroh/issues/1565)) - ([07fa983](https://github.com/n0-computer/iroh/commit/07fa98327f4955eb9f1f95b8a4378db54c236aac))

### ⚙️ Miscellaneous Tasks

- *(*)* Make clippy happy ([#1582](https://github.com/n0-computer/iroh/issues/1582)) - ([2e5e464](https://github.com/n0-computer/iroh/commit/2e5e46450baebabc272c2ca13cc58891ed717b51))
- *(baomap)* Drop all baomap logging to debug or lower ([#1562](https://github.com/n0-computer/iroh/issues/1562)) - ([06b4ac7](https://github.com/n0-computer/iroh/commit/06b4ac7dd33a4159c86c7bc0bc2f668ea001bc37))
- Add release.toml for tags - ([45fa784](https://github.com/n0-computer/iroh/commit/45fa7845ccf360b7ed1dbbd8c5e9d8bb8cb94e16))
- Release - ([0090eee](https://github.com/n0-computer/iroh/commit/0090eeef20ebfc75eb25c27e14fb76278f68fe36))

## [0.6.0](https://github.com/n0-computer/iroh/compare/v0.6.0-alpha.1..v0.6.0) - 2023-09-25

### ⛰️  Features

- *(iroh)* Downloader ([#1420](https://github.com/n0-computer/iroh/issues/1420)) - ([c217283](https://github.com/n0-computer/iroh/commit/c21728346378d6aa780e60001c0858061d2f55df))
- *(iroh-net)* Implement network monitoring ([#1472](https://github.com/n0-computer/iroh/issues/1472)) - ([a89078f](https://github.com/n0-computer/iroh/commit/a89078f5ede5ee918df1d917337342cc9206dbf2))
- *(iroh-net)* Persist known peer info ([#1488](https://github.com/n0-computer/iroh/issues/1488)) - ([2e3516d](https://github.com/n0-computer/iroh/commit/2e3516d8ab14648cf574ba038fa024af7630eefd))
- *(sync)* Track incoming sync requests, allow subscriptions without sync, close inactive replicas ([#1491](https://github.com/n0-computer/iroh/issues/1491)) - ([6c07ad3](https://github.com/n0-computer/iroh/commit/6c07ad3f2a673ef3f49731386d527dc21d828c5a))
- Streaming blob reads over RPC ([#1477](https://github.com/n0-computer/iroh/issues/1477)) - ([6397d46](https://github.com/n0-computer/iroh/commit/6397d469000218183855e61ad22c14f4e44879f9))
- Content hashes iterator for sync store ([#1501](https://github.com/n0-computer/iroh/issues/1501)) - ([8fe3f71](https://github.com/n0-computer/iroh/commit/8fe3f710685c5f960e20a332924dcee3abdfbfa8))
- Improve content propagation in sync ([#1480](https://github.com/n0-computer/iroh/issues/1480)) - ([49bde4f](https://github.com/n0-computer/iroh/commit/49bde4fdbdca82a4cd2864ea41866f3334d728f4))

### 🐛 Bug Fixes

- *(iroh)* Do not log full messages for rpc ([#1453](https://github.com/n0-computer/iroh/issues/1453)) - ([d4983c5](https://github.com/n0-computer/iroh/commit/d4983c536e4ae6ed0750653509184fc56379617a))
- *(sync)* Fix `PeerData` encoding, neighbor events, better & predictable tests ([#1513](https://github.com/n0-computer/iroh/issues/1513)) - ([779e470](https://github.com/n0-computer/iroh/commit/779e47053b9f22ea0ff23755c75174f118f30087))
- Debug for BlobReader ([#1479](https://github.com/n0-computer/iroh/issues/1479)) - ([c6935bd](https://github.com/n0-computer/iroh/commit/c6935bddbef652982d58145c7936cb9efb1023a3))
- Print enum variant name for RPC debug logs ([#1503](https://github.com/n0-computer/iroh/issues/1503)) - ([39a3a33](https://github.com/n0-computer/iroh/commit/39a3a33ad680bacd7a690a0f1d8ed183facb64d8))
- Avoid double conns, better state tracking ([#1505](https://github.com/n0-computer/iroh/issues/1505)) - ([d8cc9df](https://github.com/n0-computer/iroh/commit/d8cc9df6262f805f9cfd205973e67cb960879472))
- No-default-features builds ([#1522](https://github.com/n0-computer/iroh/issues/1522)) - ([ff6fc4c](https://github.com/n0-computer/iroh/commit/ff6fc4c20bfce134ed4e28a49fe8fb5aeae98354))

### 🚜 Refactor

- *(*)* Rework `NodeAddr` ([#1506](https://github.com/n0-computer/iroh/issues/1506)) - ([f16e439](https://github.com/n0-computer/iroh/commit/f16e43966e105a2761e18015d5522724bc63ecb6))
- *(iroh)* Leverage `strum` for `IrohPaths` ([#1507](https://github.com/n0-computer/iroh/issues/1507)) - ([95dce40](https://github.com/n0-computer/iroh/commit/95dce40f7dabd3baeedb07a9e065cbdc7f7226a2))
- *(iroh,iroh-bytes)* Replace `currrent` with `current` ([#1467](https://github.com/n0-computer/iroh/issues/1467)) - ([4f4d8e5](https://github.com/n0-computer/iroh/commit/4f4d8e5b4366362b9ee5d383ad24355b8cf6a4c5))
- *(iroh-net)* Remove unused `expired` field from `Endpoint` ([#1484](https://github.com/n0-computer/iroh/issues/1484)) - ([f2f3ead](https://github.com/n0-computer/iroh/commit/f2f3ead655dee94bd01c9f4fdcc8730457f51ffd))
- *(iroh-net)* Remove `iroh-net::config::Node` since limited to its used fields it's redundant ([#1486](https://github.com/n0-computer/iroh/issues/1486)) - ([00d0150](https://github.com/n0-computer/iroh/commit/00d0150ed9c3fb4b9a39b688c77336b380e23d12))
- Extend Iroh client, improve API consistency ([#1478](https://github.com/n0-computer/iroh/issues/1478)) - ([5380cd5](https://github.com/n0-computer/iroh/commit/5380cd5e61876575cadadc17cd575ab85d4775d3))
- Use `iroh_net::PeerAddr` more ([#1493](https://github.com/n0-computer/iroh/issues/1493)) - ([2b4b27c](https://github.com/n0-computer/iroh/commit/2b4b27cab54236b12b02d066979e313198f7c5b8))

### 📚 Documentation

- Fix grammar in README ([#1465](https://github.com/n0-computer/iroh/issues/1465)) - ([1df9255](https://github.com/n0-computer/iroh/commit/1df9255744465fdc5893edf9bfa58fb3bba51384))
- Fix link to install URL in README ([#1476](https://github.com/n0-computer/iroh/issues/1476)) - ([156ce07](https://github.com/n0-computer/iroh/commit/156ce074bc38c03906ac26fab74b5cddff4d7bcc))
- Update instructions for running rust examples ([#1511](https://github.com/n0-computer/iroh/issues/1511)) - ([1bf55db](https://github.com/n0-computer/iroh/commit/1bf55db2d318e0d8b3276c27d35aa400418cd6cf))

### ⚙️ Miscellaneous Tasks

- *(iroh, iroh-sync)* Fill licence info ([#1471](https://github.com/n0-computer/iroh/issues/1471)) - ([75fcf12](https://github.com/n0-computer/iroh/commit/75fcf124df2a6a35360307fe02510951da10c779))
- Release v0.6.0 - ([76d3fdc](https://github.com/n0-computer/iroh/commit/76d3fdca5570b382ddc87e24b8632c4f00db954f))
- Release - ([0b126b1](https://github.com/n0-computer/iroh/commit/0b126b1306577535f6d02ce840c84590ae3d200e))

### Deps

- *(iroh-net)* Use minimum safe version of quinn-proto ([#1510](https://github.com/n0-computer/iroh/issues/1510)) - ([adbfe65](https://github.com/n0-computer/iroh/commit/adbfe6540303209e1efa3d2e1e77cef89667d05a))

## [0.6.0-alpha.1](https://github.com/n0-computer/iroh/compare/v0.6.0-alpha.0..v0.6.0-alpha.1) - 2023-09-05

### ⛰️  Features

- *(iroh-sync)* Validate timestamps and move validation up ([#1439](https://github.com/n0-computer/iroh/issues/1439)) - ([4e8ff56](https://github.com/n0-computer/iroh/commit/4e8ff5653d8a6dd4548bef7886060525c3025acd))
- Get list of `ConnectionInfo`s or an individual node's `ConnectionInfo` ([#1435](https://github.com/n0-computer/iroh/issues/1435)) - ([bdf966e](https://github.com/n0-computer/iroh/commit/bdf966ef04de18966c6cced7c32983675bea1471))

### 🐛 Bug Fixes

- *(iroh)* Update example to use correct subscription API ([#1452](https://github.com/n0-computer/iroh/issues/1452)) - ([2522fca](https://github.com/n0-computer/iroh/commit/2522fcabfcc1edcd492ae5f4696a69530e2dee7d))
- *(iroh-net)* Dns fallback to default config ([#1438](https://github.com/n0-computer/iroh/issues/1438)) - ([b89f4e1](https://github.com/n0-computer/iroh/commit/b89f4e1528339528f6b620f9dece524ffcdfa977))

### 🚜 Refactor

- *(iroh-net)* Remove `NetworkMap` ([#1447](https://github.com/n0-computer/iroh/issues/1447)) - ([bc26321](https://github.com/n0-computer/iroh/commit/bc2632133ccd55e326d77857320b908f5a5a722b))
- *(iroh-sync)* `RangeEntry` trait, byte newtypes for author/namestamp, timestamp into record ([#1445](https://github.com/n0-computer/iroh/issues/1445)) - ([1bcc765](https://github.com/n0-computer/iroh/commit/1bcc76544fb153b31b0d61b4a6fa1fa1c08f4408))

### 📚 Documentation

- *(changelog)* V0.6.0-alpha.1 - ([4671387](https://github.com/n0-computer/iroh/commit/46713873eced56a0a02aa3de579661fce98b1bba))

### 🧪 Testing

- *(iroh-net)* Removed unused stun_test_ip field from DerpNode ([#1450](https://github.com/n0-computer/iroh/issues/1450)) - ([4ef3611](https://github.com/n0-computer/iroh/commit/4ef3611d023790e237075856ebe0a72035ce97cc))
- *(iroh-sync)* Initial batch of property based tests for the ranger and store ([#1428](https://github.com/n0-computer/iroh/issues/1428)) - ([9db3694](https://github.com/n0-computer/iroh/commit/9db369457a498edda9093e72ff560f09c88c142a))

### ⚙️ Miscellaneous Tasks

- Release - ([729aa41](https://github.com/n0-computer/iroh/commit/729aa41653f0f7b12bb75373a49aec0861583ea7))

## [0.6.0-alpha.0](https://github.com/n0-computer/iroh/compare/v0.5.1..v0.6.0-alpha.0) - 2023-08-28

### ⛰️  Features

- *(iroh-bytes)* Remove unneeded u64 length prefix ([#1408](https://github.com/n0-computer/iroh/issues/1408)) - ([6d9eac7](https://github.com/n0-computer/iroh/commit/6d9eac7fef834ceb5fd980c9031aea722b08ac2f))
- *(iroh-net)* PCP mappings ([#1261](https://github.com/n0-computer/iroh/issues/1261)) - ([84e2f72](https://github.com/n0-computer/iroh/commit/84e2f721a0505ee44d04c01df0daa54dcbd400ab))
- *(iroh-net)* Nat-PMP probes and mappings ([#1283](https://github.com/n0-computer/iroh/issues/1283)) - ([5c38730](https://github.com/n0-computer/iroh/commit/5c387308a14e17738efed2e4bcefee02141e13cd))
- *(iroh-net)* Add `DEV_DERP_ONLY` env variable for testing the derp relay ([#1378](https://github.com/n0-computer/iroh/issues/1378)) - ([34c97bb](https://github.com/n0-computer/iroh/commit/34c97bb688cbf3ffd096246b22fa85d11402738b))
- *(tests)* Improve test_utils to warn about mutli-runtime tests ([#1280](https://github.com/n0-computer/iroh/issues/1280)) - ([62522dc](https://github.com/n0-computer/iroh/commit/62522dccaefaeca9ac13393329d3fbe7db48b203))
- Iroh-gossip ([#1149](https://github.com/n0-computer/iroh/issues/1149)) - ([7f8463f](https://github.com/n0-computer/iroh/commit/7f8463f48587e2173f7d8fb8851e4beea148d7de))
- Methods to check if a hash is complete or partial ([#1359](https://github.com/n0-computer/iroh/issues/1359)) - ([8006629](https://github.com/n0-computer/iroh/commit/800662957f67030014102653004e6490ebc4ea3b))
- Add iroh-sync and integrate into iroh node ([#1333](https://github.com/n0-computer/iroh/issues/1333)) - ([3f141be](https://github.com/n0-computer/iroh/commit/3f141be6fd2951f10c97ff8434fd78fc40a1afcc))
- Iroh console (REPL) and restructured CLI ([#1356](https://github.com/n0-computer/iroh/issues/1356)) - ([b73d950](https://github.com/n0-computer/iroh/commit/b73d9504d64ac09bbd7c675d1047d948edbfd0f6))

### 🐛 Bug Fixes

- *(ci)* Correctly detect forks ([#1327](https://github.com/n0-computer/iroh/issues/1327)) - ([80c54aa](https://github.com/n0-computer/iroh/commit/80c54aa2ba1d16914dc9b09ca283136fe16a46a1))
- *(iroh)* Atomically write keyfile - ([7752b5a](https://github.com/n0-computer/iroh/commit/7752b5a663876f9af293d5aea5fdfd3fe53ee1fa))
- *(iroh)* Pass derp map when setting up provider ([#1347](https://github.com/n0-computer/iroh/issues/1347)) - ([391db92](https://github.com/n0-computer/iroh/commit/391db92a64e877eff4c61fcdb7e4a099aba0c4c0))
- *(iroh)* Try to fix flaky test_token_passthrough test ([#1419](https://github.com/n0-computer/iroh/issues/1419)) - ([a1d4a4d](https://github.com/n0-computer/iroh/commit/a1d4a4d71b7f8c954c8b5627f31617ddef6bcdf6))
- *(iroh-bytes)* Hash should be serialized as array not bytes ([#1410](https://github.com/n0-computer/iroh/issues/1410)) - ([116eea9](https://github.com/n0-computer/iroh/commit/116eea9eaf40d81ebaadd62c5f0f6259781c57f8))
- *(iroh-bytes)* Range spec seq identification of single blobs ([#1421](https://github.com/n0-computer/iroh/issues/1421)) - ([c3e701f](https://github.com/n0-computer/iroh/commit/c3e701f18140c1f96ca99276d223ae0a5c737752))
- *(iroh-gossip)* Specify version for iroh-net dependency - ([c21a2d1](https://github.com/n0-computer/iroh/commit/c21a2d1b570d02b6cea890f8e104c7debcf0c2ab))
- *(iroh-net)* Do not panic on RIB issues ([#1313](https://github.com/n0-computer/iroh/issues/1313)) - ([8ede947](https://github.com/n0-computer/iroh/commit/8ede9473b15c46eef16a444767480360894ba70c))
- *(iroh-net)* Portmapper priority follows described priority strategy ([#1324](https://github.com/n0-computer/iroh/issues/1324)) - ([f60101a](https://github.com/n0-computer/iroh/commit/f60101a8ab75acd2ead1d5c62fbd5d179e948fac))
- *(iroh-net)* Remove `transparent` attribute from mapping debug + log bump ([#1339](https://github.com/n0-computer/iroh/issues/1339)) - ([2878e79](https://github.com/n0-computer/iroh/commit/2878e797163661cb921978d5a68139968b6f7e5c))
- *(iroh-net)* Split packets on send ([#1380](https://github.com/n0-computer/iroh/issues/1380)) - ([57a2dee](https://github.com/n0-computer/iroh/commit/57a2dee84af44d2877b8bddf7f0b790f4be879d8))
- *(iroh-net)* Use base32 encoding in the derper config for SecretKey ([#1385](https://github.com/n0-computer/iroh/issues/1385)) - ([b8a1de8](https://github.com/n0-computer/iroh/commit/b8a1de8a39e28b4c02a9904374a43037d70f834c))
- *(iroh-net)* Allow compiling without default-features - ([0f412ed](https://github.com/n0-computer/iroh/commit/0f412edf2e11a02c2253d674eead8b58c3bf9e4f))
- *(netcheck)* Build test ProbePlan from fake interface data ([#1266](https://github.com/n0-computer/iroh/issues/1266)) - ([f671aa5](https://github.com/n0-computer/iroh/commit/f671aa509a92f96b63404815acbbbe479c888aa4))
- *(tests)* Bring back MagicEndpoint connect-close test ([#1282](https://github.com/n0-computer/iroh/issues/1282)) - ([4b1f79c](https://github.com/n0-computer/iroh/commit/4b1f79c5aedd44fe8e703f67d916368ba35e917f))
- Enable derp metrics ([#1268](https://github.com/n0-computer/iroh/issues/1268)) - ([faad31a](https://github.com/n0-computer/iroh/commit/faad31ad84212da608851b228fe4d05e7d0e5811))
- Remove obsolete and unused module ([#1279](https://github.com/n0-computer/iroh/issues/1279)) - ([4c67385](https://github.com/n0-computer/iroh/commit/4c67385982d8e0c57399c9f275a2aaf3e19ac9b5))

### 🚜 Refactor

- *(iroh-net)* Remove unused hostinfo - ([0c277b7](https://github.com/n0-computer/iroh/commit/0c277b78787fdbea602628e760c64e5a7afb7424))
- *(iroh-net)* Always attach tracing spans to spawned tasks ([#1299](https://github.com/n0-computer/iroh/issues/1299)) - ([73cac23](https://github.com/n0-computer/iroh/commit/73cac2394d4c5f8d8e4423ed109d43cd645c8480))
- *(iroh-net)* Keep `DerpMap` fixed ([#1329](https://github.com/n0-computer/iroh/issues/1329)) - ([f764517](https://github.com/n0-computer/iroh/commit/f764517feb645548f1d3b2bf80baf7aa326c97d8))
- *(iroh-net)* Unify key handling ([#1373](https://github.com/n0-computer/iroh/issues/1373)) - ([8b73323](https://github.com/n0-computer/iroh/commit/8b73323bc594a2d9c27d114d12879b1a5eca57e0))
- *(iroh-net)* Remove pub(self) visibility specifier ([#1395](https://github.com/n0-computer/iroh/issues/1395)) - ([03339f1](https://github.com/n0-computer/iroh/commit/03339f1767029712e7aa83f4c1e8290a32fa40d8))
- *(iroh-net)* Use tokio-util::codec for derp protocol implementation ([#1386](https://github.com/n0-computer/iroh/issues/1386)) - ([fe98c8d](https://github.com/n0-computer/iroh/commit/fe98c8d7a1ae131223e1a4d24b5aa0f8ada39d9f))
- *(iroh-net)* Store DerpNodes as Arcs inside DerpMap ([#1379](https://github.com/n0-computer/iroh/issues/1379)) - ([bcce8a0](https://github.com/n0-computer/iroh/commit/bcce8a0b41fe9faf5cb3cc62f96bb451a060cb57))
- *(iroh-net)* Make derp_map not an option in MagicEndpoint ([#1363](https://github.com/n0-computer/iroh/issues/1363)) - ([93147ac](https://github.com/n0-computer/iroh/commit/93147ac49a960ef0f4646c41a5c951faf5df2278))
- *(iroh-net/magicsock)* Remove usused Arc ([#1301](https://github.com/n0-computer/iroh/issues/1301)) - ([0991b13](https://github.com/n0-computer/iroh/commit/0991b13b5430b55301b094778b5b5af96aaf9170))
- Move iroh bytes get handlers out of node into module ([#1343](https://github.com/n0-computer/iroh/issues/1343)) - ([ce4cb57](https://github.com/n0-computer/iroh/commit/ce4cb57dc32ccfc032a151434d7a5de51394f304))
- Improve path handling in iroh dir ([#1345](https://github.com/n0-computer/iroh/issues/1345)) - ([1c3a3f1](https://github.com/n0-computer/iroh/commit/1c3a3f131d2f394f18118a6a153ff8f0f29e9a83))
- Improve client sync api ([#1417](https://github.com/n0-computer/iroh/issues/1417)) - ([2c6ab29](https://github.com/n0-computer/iroh/commit/2c6ab29f5afae89fd534e93fb6b174f4bfcf622a))
- Reduce amount of info logging ([#1418](https://github.com/n0-computer/iroh/issues/1418)) - ([0277b31](https://github.com/n0-computer/iroh/commit/0277b31cea0c9f7b9b2b61e49718fd8eb6821ab0))

### 📚 Documentation

- *(iroh-bytes)* Improve range-spec docs ([#1372](https://github.com/n0-computer/iroh/issues/1372)) - ([2076bfb](https://github.com/n0-computer/iroh/commit/2076bfb5710bab4509a78deff9db2ff94cbe9a82))

### 🧪 Testing

- *(flaky)* Add timeouts to gossip smoke test ([#1364](https://github.com/n0-computer/iroh/issues/1364)) - ([28b1d14](https://github.com/n0-computer/iroh/commit/28b1d14bcb0fc8db6bab193822de2dff9bd927f7))
- *(iroh)* Only use flat db when enabled - ([5bc9c04](https://github.com/n0-computer/iroh/commit/5bc9c0472a6d55c3cae450ca7bc9a270a72c20aa))
- *(iroh-net)* Ignore MagicEndpoint test again ([#1300](https://github.com/n0-computer/iroh/issues/1300)) - ([c6314ff](https://github.com/n0-computer/iroh/commit/c6314ff5fe2d1e743bcba704146fb098b9ad360b))
- Introduce iroh-test with common logging infrastructure ([#1365](https://github.com/n0-computer/iroh/issues/1365)) - ([411e20b](https://github.com/n0-computer/iroh/commit/411e20b68f7d977d8a7c84c07bd2882cfd68a7fa))

### ⚙️ Miscellaneous Tasks

- *(*)* Contributors guide ([#1198](https://github.com/n0-computer/iroh/issues/1198)) - ([52ee997](https://github.com/n0-computer/iroh/commit/52ee9977db829165f1fd64ed8ae569ff8c64b3b4))
- *(ci)* Ensure external contributors don't fail CI on report dumps ([#1304](https://github.com/n0-computer/iroh/issues/1304)) - ([854c242](https://github.com/n0-computer/iroh/commit/854c24279838d19012e148d7b24f0bf5335db9e3))
- Update license field following SPDX 2.1 license expression standard - ([6c01938](https://github.com/n0-computer/iroh/commit/6c01938ad1b16e4159cc9c4d345316c84d33d662))
- Enable CI on merge_group trigger ([#1298](https://github.com/n0-computer/iroh/issues/1298)) - ([d11de73](https://github.com/n0-computer/iroh/commit/d11de731c7f87c6a3ab034c85e096bf0d0962511))
- Update README.md ([#1360](https://github.com/n0-computer/iroh/issues/1360)) - ([cf50c91](https://github.com/n0-computer/iroh/commit/cf50c91a78e0dbd15defda9aab1e0df98da65141))
- Improve code style of tracing calls ([#1390](https://github.com/n0-computer/iroh/issues/1390)) - ([e0daeb2](https://github.com/n0-computer/iroh/commit/e0daeb2e6b84be3499faaae9f885a4217e3d87d8))
- Specify resolver 2 for entire workspace ([#1406](https://github.com/n0-computer/iroh/issues/1406)) - ([38b06b0](https://github.com/n0-computer/iroh/commit/38b06b04246ddca5fc60b536f73b6566cbe18373))
- Release - ([29b011e](https://github.com/n0-computer/iroh/commit/29b011e0388e46a6a05cfc74c1b40bb1583e9dec))

### Deps

- Switch back to derive_more og - ([d97721e](https://github.com/n0-computer/iroh/commit/d97721ec91ec8071606be04ec25a430c683b9578))
- Allow old ed25519-dalek crate in cargo-deny for now ([#1361](https://github.com/n0-computer/iroh/issues/1361)) - ([3384f3e](https://github.com/n0-computer/iroh/commit/3384f3e2c076fc15bcbd27ad06a25908ee57b456))
- Update webpki to rustls-webpki and webpki-roots to latest ([#1389](https://github.com/n0-computer/iroh/issues/1389)) - ([a2fc0c1](https://github.com/n0-computer/iroh/commit/a2fc0c1af6accf3df5c498c459f0cf477954d5e9))

### Ref

- *(iroh-net)* More Conn -> MagicSock renaming ([#1294](https://github.com/n0-computer/iroh/issues/1294)) - ([66ec54d](https://github.com/n0-computer/iroh/commit/66ec54d32d49a78515d9263a3438d015f6f56ea2))
- *(iroh-net)* Use a short format for node PublicKey logging ([#1296](https://github.com/n0-computer/iroh/issues/1296)) - ([af52b51](https://github.com/n0-computer/iroh/commit/af52b514b3975f525576b31b54dba651646a2b40))

## [0.5.1](https://github.com/n0-computer/iroh/compare/iroh-net-v0.5.1..v0.5.1) - 2023-07-18

### ⚙️ Miscellaneous Tasks

- Release - ([b2b60da](https://github.com/n0-computer/iroh/commit/b2b60da1878c9d371829e5086515cd229eb33c7c))

## [iroh-net-v0.5.1](https://github.com/n0-computer/iroh/compare/v0.4.1..iroh-net-v0.5.1) - 2023-07-18

### ⛰️  Features

- *(ci)* Record dump uploads ([#1101](https://github.com/n0-computer/iroh/issues/1101)) - ([e289465](https://github.com/n0-computer/iroh/commit/e2894653506ed4cef2bcd7fd29a010b80c599448))
- *(ci)* Allow running netsim from another branch ([#1186](https://github.com/n0-computer/iroh/issues/1186)) - ([0f77e4e](https://github.com/n0-computer/iroh/commit/0f77e4e3e88025078433b7946035c68fb99395a3))
- *(conn)* Improve shutdown of IO loop - ([dbe0228](https://github.com/n0-computer/iroh/commit/dbe02287707f53454c815f829b5b1ace7626d779))
- *(docs)* Check rustdoc more strictly ([#1185](https://github.com/n0-computer/iroh/issues/1185)) - ([6a58800](https://github.com/n0-computer/iroh/commit/6a5880004931b492c024a1feade2878f3ce5db41))
- *(iroh)* Pass a callback to subscribe ([#1219](https://github.com/n0-computer/iroh/issues/1219)) - ([c325603](https://github.com/n0-computer/iroh/commit/c325603cb317600e4ee87844fa7a73174a8d7911))
- *(iroh-net)* Add more details to tracked endpoints - ([dfd946e](https://github.com/n0-computer/iroh/commit/dfd946ed427d5135bf2b7df2141ad7a607b05df1))
- *(iroh-net)* Implement `HomeRouter` detection - ([b14049e](https://github.com/n0-computer/iroh/commit/b14049ec0f9f36a540a9aa6fbd315272179d683a))
- *(iroh-net)* Upnp port mapping ([#1117](https://github.com/n0-computer/iroh/issues/1117)) - ([701e9b7](https://github.com/n0-computer/iroh/commit/701e9b7c6ff57037cd3bb88a9f7e037f5ddf6b87))
- *(iroh-net)* PCP probe  - ([659a54a](https://github.com/n0-computer/iroh/commit/659a54aa7571cff14592a81fffc011f683a8c954))
- *(loging)* Improve logging output of provider and get ([#932](https://github.com/n0-computer/iroh/issues/932)) - ([6ae709e](https://github.com/n0-computer/iroh/commit/6ae709e63a1c542c1e02640b0fa85cb0a92ebcd7))
- *(provider)* Add 'CollectionAdded' Provider event ([#1131](https://github.com/n0-computer/iroh/issues/1131)) - ([8b6a5bc](https://github.com/n0-computer/iroh/commit/8b6a5bc43d3bd602ff38bc8810ee72af5b5ac8de))
- Implement ICMP pings - ([6c19faa](https://github.com/n0-computer/iroh/commit/6c19faae7f88accf8a2225b825339e6cc63cbe75))
- Metrics collection ([#900](https://github.com/n0-computer/iroh/issues/900)) - ([d4a01f7](https://github.com/n0-computer/iroh/commit/d4a01f7aa0de1a208abf7809d79ff0a8403dc143))
- Remove AuthToken - ([96d9378](https://github.com/n0-computer/iroh/commit/96d93787d8905a527cee374cf1d3ccc78504e309))
- Print local endpoints on provide - ([b3c22bd](https://github.com/n0-computer/iroh/commit/b3c22bd12ec3d18b3c75af316f29075e72e8fa4e))
- Add configuration for derp regions - ([96903e7](https://github.com/n0-computer/iroh/commit/96903e776e03c7f72155db3c2e105f33389cb06f))
- Prefer configured port to be used for ipv4 - ([3a292e5](https://github.com/n0-computer/iroh/commit/3a292e555d0f035950f90c3df463abed93475ac3))
- Add iroh doctor utility ([#986](https://github.com/n0-computer/iroh/issues/986)) - ([4fc70f5](https://github.com/n0-computer/iroh/commit/4fc70f5915ac4d3e3d3a2dc0b8a869e8428637d4))
- Reduce dependency bloat for derper - ([07d7205](https://github.com/n0-computer/iroh/commit/07d72059404c169c17438a570cb5e3301f1c3351))
- Add api to list collections - ([7b0a7c7](https://github.com/n0-computer/iroh/commit/7b0a7c7b7ef9aab4b12970d91e615c74eeb792be))
- Integration metrics and viz dump ([#1089](https://github.com/n0-computer/iroh/issues/1089)) - ([2f65bc1](https://github.com/n0-computer/iroh/commit/2f65bc1e02798af7664d515a8aaf88e8c774ed4e))
- `hp::derp::http::server::Server`  & TLS in the derper! ([#1077](https://github.com/n0-computer/iroh/issues/1077)) - ([6f40e14](https://github.com/n0-computer/iroh/commit/6f40e14e26b2313998db9f75f0bc979cc6abe47e))
- Allow node to accept different ALPNs - ([34e02d0](https://github.com/n0-computer/iroh/commit/34e02d02baa9100bb13b58fadb76aa06856541be))
- Derp mesh network & derper cli & config cleanup ([#1130](https://github.com/n0-computer/iroh/issues/1130)) - ([3dca612](https://github.com/n0-computer/iroh/commit/3dca6125064044907bc7da9dc19fe5a26e12567a))
- Add MagicEndpoint to iroh-net - ([4597cb3](https://github.com/n0-computer/iroh/commit/4597cb36e0be5ffcb5ae21a42e4a37648d455aad))
- Make get-ticket just a way to use get ([#1168](https://github.com/n0-computer/iroh/issues/1168)) - ([2291ef4](https://github.com/n0-computer/iroh/commit/2291ef4f9b1885b440b6b993b9c81205a20549b5))
- Impl From<Url> for DerpMap - ([01641a7](https://github.com/n0-computer/iroh/commit/01641a7c3bf869c71c1949eeadfc7acd97c25e68))
- Specify a DERP region for the peer you are trying to connect to ([#1222](https://github.com/n0-computer/iroh/issues/1222)) - ([456f963](https://github.com/n0-computer/iroh/commit/456f96305954a23299d02ed65b8838ba168232e1))
- Disable bailing out when temp dir is missing ([#1251](https://github.com/n0-computer/iroh/issues/1251)) - ([eae79e8](https://github.com/n0-computer/iroh/commit/eae79e8e7a672571dbffc6caec0c1fd5359120fe))
- Add metrics to the derp server ([#1260](https://github.com/n0-computer/iroh/issues/1260)) - ([d1b4e18](https://github.com/n0-computer/iroh/commit/d1b4e183b7fd8af8a4566ede92021aa34bdbac67))
- Unify MSRV to 1.66 - ([090f6d8](https://github.com/n0-computer/iroh/commit/090f6d8c2a9939913881ddce6683bfc2d6a0a771))

### 🐛 Bug Fixes

- *(ci)* Also run doc tests ([#1095](https://github.com/n0-computer/iroh/issues/1095)) - ([97d24a6](https://github.com/n0-computer/iroh/commit/97d24a6a873420455ad0ca71da2bdaea6c35725f))
- *(ci)* Move chuck out of the workspace - ([0b8d22d](https://github.com/n0-computer/iroh/commit/0b8d22d75fba45ba827e6464ec36b9677dbff466))
- *(clippy)* Clean up clippy again ([#1061](https://github.com/n0-computer/iroh/issues/1061)) - ([4e1ba3e](https://github.com/n0-computer/iroh/commit/4e1ba3e77f79524a112b9ac2c55be61175fbe2a3))
- *(database)* Handle finding beetle data directory ([#960](https://github.com/n0-computer/iroh/issues/960)) - ([909ea9a](https://github.com/n0-computer/iroh/commit/909ea9abda3217973d1313016656febc4bfd7b6b))
- *(derp)* Remove client cleanup bug - ([f6287c1](https://github.com/n0-computer/iroh/commit/f6287c17bf484bef0d6d63a20364424f1af5f64a))
- *(derp)* Filter DNS results by address family ([#1227](https://github.com/n0-computer/iroh/issues/1227)) - ([b6f9df3](https://github.com/n0-computer/iroh/commit/b6f9df3bdd12f7f6d1840ab0427583c6658d2364))
- *(derper)* Small derper fixes ([#1083](https://github.com/n0-computer/iroh/issues/1083)) - ([4fb925a](https://github.com/n0-computer/iroh/commit/4fb925ae865ed7ee291b454aad9cf9f732765ba4))
- *(iroh)* Error when path does not exist ([#1146](https://github.com/n0-computer/iroh/issues/1146)) - ([c1b674f](https://github.com/n0-computer/iroh/commit/c1b674f9edc80e720291802b15f869378abf81cf))
- *(iroh)* Pass derp-map on get-options - ([b7fd889](https://github.com/n0-computer/iroh/commit/b7fd889e7806feeb941c0f611bbb3aa33a718b40))
- *(iroh-net)* Allow derp only connections to upgrade - ([25b35a3](https://github.com/n0-computer/iroh/commit/25b35a3c8e828ed1c11b1b5286508d8c90e00ba5))
- *(iroh-net)* Better logic for initial derp connection - ([6e6b97e](https://github.com/n0-computer/iroh/commit/6e6b97eb90d2e68098145468774cfc1a7d4f45e0))
- *(iroh-net)* No * deps - ([b1ff368](https://github.com/n0-computer/iroh/commit/b1ff36885be7dbcffbed86b84982867cdf54f654))
- *(iroh-net)* Handle non git environments in build - ([a645cbe](https://github.com/n0-computer/iroh/commit/a645cbed0458e4f1dc438a307d4b1b2263c5103b))
- *(netcheck)* Do not read from main Conn sockets ([#1017](https://github.com/n0-computer/iroh/issues/1017)) - ([5e997a4](https://github.com/n0-computer/iroh/commit/5e997a4a64cb4686dd3674315d6e2a1ca19619be))
- *(netcheck)* If no STUN sockets supplied allow bind to fail ([#1041](https://github.com/n0-computer/iroh/issues/1041)) - ([726cace](https://github.com/n0-computer/iroh/commit/726cace060f0a3a8b042a8605801eacaa9599d48))
- *(netcheck)* Make ICMP ping optional ([#1137](https://github.com/n0-computer/iroh/issues/1137)) - ([ac6bb1a](https://github.com/n0-computer/iroh/commit/ac6bb1a43571fd335f37631f7320d200495b23b1))
- *(netcheck)* Integrate https and icmp probes in probeplan ([#1220](https://github.com/n0-computer/iroh/issues/1220)) - ([a0ae228](https://github.com/n0-computer/iroh/commit/a0ae22851453ea9e277adba8d52fe55f90edcef3))
- *(netcheck)* Stable derp-region sorting ([#1250](https://github.com/n0-computer/iroh/issues/1250)) - ([899efd2](https://github.com/n0-computer/iroh/commit/899efd29362e539722869b2013b2058704098547))
- Fetch PR details on issue comment ([#931](https://github.com/n0-computer/iroh/issues/931)) - ([9272adb](https://github.com/n0-computer/iroh/commit/9272adb37af1154112506956c4df97a165f052da))
- Avoid polling future after completion - ([1f812fd](https://github.com/n0-computer/iroh/commit/1f812fd1b853c9bf699d1c678bb27122ce2f58df))
- Remove derp route on peergone - ([cefc8ba](https://github.com/n0-computer/iroh/commit/cefc8ba47cffe6565b963ed8e7efa5e150a7b188))
- Do not use magicsock for rpc - ([7717243](https://github.com/n0-computer/iroh/commit/7717243e6b6ae2bab55cb9e685e528dfd1732fe1))
- Show all listening addrs - ([b84ed59](https://github.com/n0-computer/iroh/commit/b84ed59ad39c807b30a138803dfd1891705694ee))
- Use correct endpoint for derp connections - ([07d919f](https://github.com/n0-computer/iroh/commit/07d919faf8a58e911af2ae2223a5e7d615fb5e3c))
- Checkout correct branch on netsim comment ([#934](https://github.com/n0-computer/iroh/issues/934)) - ([fa2ae68](https://github.com/n0-computer/iroh/commit/fa2ae68a9a2b9968216de445c206492d518e1d42))
- Correct ref on checkout ([#936](https://github.com/n0-computer/iroh/issues/936)) - ([f58df87](https://github.com/n0-computer/iroh/commit/f58df87f34a8bd1110a835adfaccf2979e3867bb))
- Avoid using tokio::block_in_place - ([db5ad3e](https://github.com/n0-computer/iroh/commit/db5ad3e0976cd2f66fcc2dc773b74f6cd7ea1ba8))
- Correct ipv4 and ipv6 port mappings on rebind and endpoints - ([6a1e405](https://github.com/n0-computer/iroh/commit/6a1e405ecaa4ecca4883a053d1e3f409b641bf0a))
- Store udpstate - ([f0bde56](https://github.com/n0-computer/iroh/commit/f0bde56c8d72b9d6e7dbe280632ab903ebe83133))
- Handle multiple transmit destinations - ([050e49f](https://github.com/n0-computer/iroh/commit/050e49f24c54faaf12bfff26a589dd2657113f27))
- Allow dialing by peer id only - ([6fb17d1](https://github.com/n0-computer/iroh/commit/6fb17d1efb23b56c01ac2f43d62e42507a1c2010))
- Endpoint update scheduler - ([93ca0e4](https://github.com/n0-computer/iroh/commit/93ca0e436054c9f2e7ff98268976a017dc1da21a))
- Cleanup ping sending logic - ([7896d37](https://github.com/n0-computer/iroh/commit/7896d37accd80a89f9bd67318e313cb04fdfcfb5))
- Send early ping if needed - ([d0755c7](https://github.com/n0-computer/iroh/commit/d0755c7fc0595216833d0d7a13924b0e3fe034d8))
- Improve local addr output and start fixing cli tests - ([f76d650](https://github.com/n0-computer/iroh/commit/f76d6504c8df76154aa5489ffa8bee8ebf662609))
- Process incoming IP packets in a seperate task ([#1020](https://github.com/n0-computer/iroh/issues/1020)) - ([96b882a](https://github.com/n0-computer/iroh/commit/96b882a80a129810682c2885f513dbcec81b3189))
- Format socket addr so that it does not need to be escaped ([#1019](https://github.com/n0-computer/iroh/issues/1019)) - ([7c87b94](https://github.com/n0-computer/iroh/commit/7c87b944da095c096880c56c6bb36be605710899))
- Ensure provider building waits for an endpoint update - ([c858f36](https://github.com/n0-computer/iroh/commit/c858f361195e486f721f7fea7002b196b7654874))
- Ensure endpoints are always discovered or timeout - ([58538e0](https://github.com/n0-computer/iroh/commit/58538e005322c838736f25b8ec74a25dea70cff5))
- Better handling of ipv4 only setups - ([547662b](https://github.com/n0-computer/iroh/commit/547662b1526df58378157d61a1855eb38ba95e3d))
- Avoid dualstack bindings - ([34322a6](https://github.com/n0-computer/iroh/commit/34322a6be04028a1d6fdfe5e8c3b03d0f09b260d))
- Use listen_addresses instead of local_address ([#1044](https://github.com/n0-computer/iroh/issues/1044)) - ([c4a1890](https://github.com/n0-computer/iroh/commit/c4a1890b5c2f905c0780d9dccf1bee70847f599d))
- Add entry in peer_map for unknown ping sender - ([648210c](https://github.com/n0-computer/iroh/commit/648210c6c23b4e637df574441ef06f0294960d62))
- Handle hairpining timeout properly ([#1049](https://github.com/n0-computer/iroh/issues/1049)) - ([3867b72](https://github.com/n0-computer/iroh/commit/3867b720f94da91c5c6cf6aa7f1689c6e60b7dc7))
- Make sure to use the config by default in iroh doctor report ([#1057](https://github.com/n0-computer/iroh/issues/1057)) - ([fcc74b8](https://github.com/n0-computer/iroh/commit/fcc74b80f6daf7185292e87e086b5e899f5d0d1a))
- Use simulated time in timer tests  - ([b80ef52](https://github.com/n0-computer/iroh/commit/b80ef5229cdb177bb8a7bc2e5f5cfcf82f34e1af))
- Online stun test ([#1065](https://github.com/n0-computer/iroh/issues/1065)) - ([bec1bbe](https://github.com/n0-computer/iroh/commit/bec1bbeadab93195094a3ee5cd22c7e261db2459))
- Update integration tests ([#1082](https://github.com/n0-computer/iroh/issues/1082)) - ([36cd904](https://github.com/n0-computer/iroh/commit/36cd904c1eafaac5bf75d48eca57220a0f9bf441))
- Release netsim should ignore some tests ([#1096](https://github.com/n0-computer/iroh/issues/1096)) - ([9b981c4](https://github.com/n0-computer/iroh/commit/9b981c4c4b75d76cd7fd4b9ac83d2d9d1e9edd1a))
- Update bao-tree dependency to get rid of ouroboros in dependency tree ([#1104](https://github.com/n0-computer/iroh/issues/1104)) - ([7840e1c](https://github.com/n0-computer/iroh/commit/7840e1ceceb8f787455fd4804d54248145fb9a7a))
- Don't crash the derper ([#1110](https://github.com/n0-computer/iroh/issues/1110)) - ([e1752bc](https://github.com/n0-computer/iroh/commit/e1752bc07184ec9e0801cde0e0d86065c25e3cbb))
- Don't spam re-connect attempts if something goes wrong connecting to a derp server ([#1113](https://github.com/n0-computer/iroh/issues/1113)) - ([92e8fc3](https://github.com/n0-computer/iroh/commit/92e8fc3bc2628cf33306a21661ce7e7188c2cdf7))
- Improve connectivity   - ([8e2d947](https://github.com/n0-computer/iroh/commit/8e2d94782549e47de4215394772186eed64e2f44))
- Remove build-data dependency  - ([26e9937](https://github.com/n0-computer/iroh/commit/26e99375a7b058adb4a682b7014a3c2407b590ae))
- Cross builds ([#1174](https://github.com/n0-computer/iroh/issues/1174)) - ([739ee07](https://github.com/n0-computer/iroh/commit/739ee072d28b848e999d6c84ed301cb7bbf0a5eb))
- Netsim branch CI default ([#1205](https://github.com/n0-computer/iroh/issues/1205)) - ([a8435eb](https://github.com/n0-computer/iroh/commit/a8435ebb594b93282e90959e702f11baabfd44c5))
- Default netsim branch ([#1208](https://github.com/n0-computer/iroh/issues/1208)) - ([01da61d](https://github.com/n0-computer/iroh/commit/01da61d4389905ac57a144548dd00ae8c0c7c801))
- Switch to derive_more_preview  - ([a0392c6](https://github.com/n0-computer/iroh/commit/a0392c6b9e518a707b341f67e69065eaf26404cc))
- Make sure to clean up any lingering processes ([#1214](https://github.com/n0-computer/iroh/issues/1214)) - ([f782fef](https://github.com/n0-computer/iroh/commit/f782fef3217dc01c58381f9beb184481b829f7a1))

### 🚜 Refactor

- *(iroh-bytes)* Remove handshake and rely on ALPN only for protocol negotiation - ([e321d9f](https://github.com/n0-computer/iroh/commit/e321d9f76c7ea44dd4065d5a09cf08160b18d4b3))
- *(iroh-net)* Make region ids always be u16 - ([685b9aa](https://github.com/n0-computer/iroh/commit/685b9aa28370dfa2006b2ea11de2a7f425f920c2))
- *(iroh-net)* Expand use of default values ([#1160](https://github.com/n0-computer/iroh/issues/1160)) - ([0905155](https://github.com/n0-computer/iroh/commit/0905155b64832b771d26b2acd1395b3c2cf79ea5))
- *(iroh-net)* Move `Conn` toplevel - ([72a4bc9](https://github.com/n0-computer/iroh/commit/72a4bc938ea1df5bb68d5d787377d3bcb12eec2a))
- *(iroh-net)* Rename `Conn` to `MagicSock` - ([810f9f3](https://github.com/n0-computer/iroh/commit/810f9f3d0ea5cbbda6e9dd5f749fc1e9618d7c0c))
- Move keys out of the mutex - ([caf7ebb](https://github.com/n0-computer/iroh/commit/caf7ebb25d1a4aa44b99c3c9f5fb6d0a6932c221))
- Update connection logic to for magicsock - ([e13f663](https://github.com/n0-computer/iroh/commit/e13f663e9710991b868c873543280b7f2eee90cf))
- Move derp receiving into the derp actor - ([ff28875](https://github.com/n0-computer/iroh/commit/ff2887546a94849e690a6b383342f0e308ceaf3c))
- Remove BlobOrCollection ([#1078](https://github.com/n0-computer/iroh/issues/1078)) - ([63a2529](https://github.com/n0-computer/iroh/commit/63a2529bfc0ed99656de5bf6f42fe9c00f4b676e))
- Remove ouroboros and replace it with self_cell ([#1102](https://github.com/n0-computer/iroh/issues/1102)) - ([a4077f4](https://github.com/n0-computer/iroh/commit/a4077f4d085336e1739bcf537353d1fedf118137))
- Strip down the iroh runtime and use tokio_util::task::LocalPoolHandle instead ([#1114](https://github.com/n0-computer/iroh/issues/1114)) - ([80e8eca](https://github.com/n0-computer/iroh/commit/80e8eca4d8b0ca840a64ca640c9db6046673a90a))
- Move code into workspace package - ([0fb0a17](https://github.com/n0-computer/iroh/commit/0fb0a17d19a4cb66415960818741b00263dd745e))
- Split main networking code into iroh-net - ([ba95ba3](https://github.com/n0-computer/iroh/commit/ba95ba3d31150e36ef0a743309001a1d2a7bfc31))
- Move byte specific pieces into iroh-bytes - ([8bb3524](https://github.com/n0-computer/iroh/commit/8bb3524cb72dd832d9b3c7629f2994afe28d3078))
- Move rpc and provider setup into iroh - ([620a904](https://github.com/n0-computer/iroh/commit/620a904309339b0ecc4726cf66bbcbd73222f022))
- Split metrics of into its own crate - ([f2afe47](https://github.com/n0-computer/iroh/commit/f2afe47343d93583a9c5e01d994e4cfab2ab28d3))
- Move connection issue into iroh-net - ([1b28c72](https://github.com/n0-computer/iroh/commit/1b28c7232dca390544c9b4794d453cd852452d76))
- Replace warp with axum for the test server ([#1124](https://github.com/n0-computer/iroh/issues/1124)) - ([0345f2e](https://github.com/n0-computer/iroh/commit/0345f2efa86b3326d32b4daab732518bf3cdc523))
- Move cli functionality into library format  - ([92fd3c6](https://github.com/n0-computer/iroh/commit/92fd3c63b3d5a9044d8d02aebf4bef954bbfbe00))
- Change default bind port to iroh leet port: 11204 ([#1147](https://github.com/n0-computer/iroh/issues/1147)) - ([2901b97](https://github.com/n0-computer/iroh/commit/2901b97eb5bc0b4bf1d5b5f13259e8205aae1d5e))
- Use newtype to avoid derp magic ips - ([8a2aab1](https://github.com/n0-computer/iroh/commit/8a2aab17fa048748bca99b56c275d42a6cf4055b))
- Pluggable metrics ([#1173](https://github.com/n0-computer/iroh/issues/1173)) - ([b0ccea5](https://github.com/n0-computer/iroh/commit/b0ccea547b794fcef3f88099306064e9ad6668c0))
- Get rid of Blake3Cid ([#1204](https://github.com/n0-computer/iroh/issues/1204)) - ([cf0573a](https://github.com/n0-computer/iroh/commit/cf0573ab95c4216aa4df919d975077e603108bea))
- Move dialing utils into iroh from iroh-bytes ([#1226](https://github.com/n0-computer/iroh/issues/1226)) - ([54630b9](https://github.com/n0-computer/iroh/commit/54630b9f08704658b085998e8b9fa6d675cbc6b3))
- Flatten `iroh_net::hp` module - ([6f9e7c0](https://github.com/n0-computer/iroh/commit/6f9e7c07f65ff6a4f87717aee3570425d2ace03a))

### 📚 Documentation

- *(bytes)* Add more about text to README.md ([#1255](https://github.com/n0-computer/iroh/issues/1255)) - ([f9a49c5](https://github.com/n0-computer/iroh/commit/f9a49c55f2fd7948819c32c0b71ac181012260cf))
- *(iroh-net)* Deny missing docs and broken links in the crate, except the `derp` mod - ([b9715ea](https://github.com/n0-computer/iroh/commit/b9715eabe8dae64a687d0b2a9f6015e0a1556c90))
- Fixup cargo doc - ([d3f4a26](https://github.com/n0-computer/iroh/commit/d3f4a26ceacc2caa6c7d8f15c7aaa78f9cd811b0))
- Iroh-net toplevel ([#1175](https://github.com/n0-computer/iroh/issues/1175)) - ([136483f](https://github.com/n0-computer/iroh/commit/136483ffe7dfc59971dceeba04cd5aac6074ea79))
- Fill out derp documentation ([#1171](https://github.com/n0-computer/iroh/issues/1171)) - ([b98851c](https://github.com/n0-computer/iroh/commit/b98851c17b224ae83a78c3f1409e9d258ebdb213))
- Deny missing docs ([#1156](https://github.com/n0-computer/iroh/issues/1156)) - ([d299092](https://github.com/n0-computer/iroh/commit/d299092d1ab8853eef3617baeb106e229afc6436))
- Add docs to RPC protocol ([#1234](https://github.com/n0-computer/iroh/issues/1234)) - ([316c185](https://github.com/n0-computer/iroh/commit/316c1859f91b872f008f8a2fdc1580ea053a9078))
- Iroh examples ([#1237](https://github.com/n0-computer/iroh/issues/1237)) - ([1cfa183](https://github.com/n0-computer/iroh/commit/1cfa183bc356e144cc6e00f50f7c5b1e296cb09b))
- Fill in the iroh-net README a little  - ([c5e4c1b](https://github.com/n0-computer/iroh/commit/c5e4c1b23689602422a87886667bba06147763c7))
- Update root, iroh, iroh-metrics readmes ([#1258](https://github.com/n0-computer/iroh/issues/1258)) - ([33464a7](https://github.com/n0-computer/iroh/commit/33464a7a43f6810859f8f744a44b35ca9adeb1e8))
- Nits in the derp docs  - ([4a4dd46](https://github.com/n0-computer/iroh/commit/4a4dd46bee33c4c1df5c84d18a5779b2f66925be))

### 🧪 Testing

- *(derp)* Fix test - ([10782be](https://github.com/n0-computer/iroh/commit/10782befb3512a874215a8f43d1f221737f231b8))
- *(ipv6)* Do not run IPv6 tests if the host doesn't support IPv6 ([#1059](https://github.com/n0-computer/iroh/issues/1059)) - ([e27cc77](https://github.com/n0-computer/iroh/commit/e27cc774b081d0fcf6a7f79cf0ddae127854a14d))
- *(iroh-net)* Disable flaky MagicEndpoint tests ([#1184](https://github.com/n0-computer/iroh/issues/1184)) - ([6fa891a](https://github.com/n0-computer/iroh/commit/6fa891ad72258d3fab2f558d40e8ad12529483e6))
- *(netcheck)* Assume udp packets get lost ([#1094](https://github.com/n0-computer/iroh/issues/1094)) - ([daa7c0c](https://github.com/n0-computer/iroh/commit/daa7c0cc83debbc570672baa21d005bf5a69e920))
- Check that no packets have been lost - ([fd7e0fe](https://github.com/n0-computer/iroh/commit/fd7e0fe047988ac025cbdb39850cf412ae6d02e2))
- All 10 rounds - ([4e8625a](https://github.com/n0-computer/iroh/commit/4e8625a8eb8998e6dcfd51875a5a84ba20dc5208))
- Fix cli addr test - ([a2a711c](https://github.com/n0-computer/iroh/commit/a2a711cfad1bb6c9b3de53f251eb51d83cd0e643))
- Cli fixes - ([05474df](https://github.com/n0-computer/iroh/commit/05474dffac78e9de5e677e0b83fdce288c18d9bb))
- Add logging to flaky google stun test ([#1053](https://github.com/n0-computer/iroh/issues/1053)) - ([b29fbf7](https://github.com/n0-computer/iroh/commit/b29fbf7eb228badb0f5c1b542c7d601e4ba563ab))
- Add test utilities to configure logging ([#1060](https://github.com/n0-computer/iroh/issues/1060)) - ([8448cb6](https://github.com/n0-computer/iroh/commit/8448cb64006d5343b1437ba5d493e35a261dde0b))
- Bring back tests ([#1126](https://github.com/n0-computer/iroh/issues/1126)) - ([de43b59](https://github.com/n0-computer/iroh/commit/de43b59d15177e3ad675c2ae3fd2d4cced5fd5c7))
- Add tests for the main derper endpoints - ([895a41e](https://github.com/n0-computer/iroh/commit/895a41e1acbd1f70935d51a14b13cd350efb28af))
- Change some tests to no longer access the disk ([#1232](https://github.com/n0-computer/iroh/issues/1232)) - ([58d42ba](https://github.com/n0-computer/iroh/commit/58d42ba7da1f3eca199f4952643d1de6ac812664))

### ⚙️ Miscellaneous Tasks

- *(Conn/PeerMap)* Introduce QuicMappedAddress ([#1001](https://github.com/n0-computer/iroh/issues/1001)) - ([2f8aeb9](https://github.com/n0-computer/iroh/commit/2f8aeb975b020fb5365487a842db17cb30ec7e6a))
- *(build)* Sort dependencies in Cargo.toml ([#1081](https://github.com/n0-computer/iroh/issues/1081)) - ([d9e3b7b](https://github.com/n0-computer/iroh/commit/d9e3b7b47ea17c0c1cb3ddae6d2a5942251bd68c))
- *(ci)* Do not use fail-fast strategy ([#1076](https://github.com/n0-computer/iroh/issues/1076)) - ([e0b2a9b](https://github.com/n0-computer/iroh/commit/e0b2a9bb38d5ed0d47383258ca648ca0429a6d7f))
- *(ci)* Do not output clippy in json format ([#1080](https://github.com/n0-computer/iroh/issues/1080)) - ([a89fccf](https://github.com/n0-computer/iroh/commit/a89fccfd9a545543b22b59aaa4976ba5eab84149))
- *(ci)* Deny warnings again ([#1075](https://github.com/n0-computer/iroh/issues/1075)) - ([6df66f4](https://github.com/n0-computer/iroh/commit/6df66f479aac274f8231aaabbe3d11f07521b6a4))
- *(ci)* Do not run cargo check separately and test all features ([#1079](https://github.com/n0-computer/iroh/issues/1079)) - ([dd6eccb](https://github.com/n0-computer/iroh/commit/dd6eccb43d645ac64fd0cf3dd4151767b47aadb0))
- *(ci)* Bring back release builds ([#1243](https://github.com/n0-computer/iroh/issues/1243)) - ([1dadcf5](https://github.com/n0-computer/iroh/commit/1dadcf5465fc4314edd860b026df9cc1fe9d5f67))
- *(iroh-net)* Fix warnings and errors due to incompatible deps after underlying dep update ([#1225](https://github.com/n0-computer/iroh/issues/1225)) - ([cf13398](https://github.com/n0-computer/iroh/commit/cf133989f8e460bedb0dbf2dc21d186c581d330e))
- *(logging)* Use nested tracing spans ([#1228](https://github.com/n0-computer/iroh/issues/1228)) - ([84c6f77](https://github.com/n0-computer/iroh/commit/84c6f77859fb51548e52059c2bb828d4b2b52c3f))
- *(reportgen)* Improve logging to e less confusing ([#1244](https://github.com/n0-computer/iroh/issues/1244)) - ([7557a91](https://github.com/n0-computer/iroh/commit/7557a91c57515c2eaedd15bb42977737347af40f))
- Update deps - ([532873f](https://github.com/n0-computer/iroh/commit/532873f0204c65ac05bf1d7ea69e910c317bae1e))
- Do not fail fast for cross - ([5e15c03](https://github.com/n0-computer/iroh/commit/5e15c03acae4ceb3283ee45deaf3c79b6c2ee330))
- Move CI to self hosted runners ([#1040](https://github.com/n0-computer/iroh/issues/1040)) - ([fba572d](https://github.com/n0-computer/iroh/commit/fba572d010f9fbf6dbe137f29c8172e049cf2fe1))
- Try latest cross ([#1069](https://github.com/n0-computer/iroh/issues/1069)) - ([71dcab1](https://github.com/n0-computer/iroh/commit/71dcab1d04723cef67bc2275bf2bf2feb08b3c54))
- Update dependencies ([#1107](https://github.com/n0-computer/iroh/issues/1107)) - ([23baf7d](https://github.com/n0-computer/iroh/commit/23baf7d98ad2aef0c3c50d287f054550a2ba2924))
- Delete unused file - ([0fb684f](https://github.com/n0-computer/iroh/commit/0fb684ff840b57dd595200c1eca596e3c563996b))
- Add explict parity acknowledgement on cert & verifier files, clarify codebase copyright is assigned to n0, inc. ([#1167](https://github.com/n0-computer/iroh/issues/1167)) - ([04c7247](https://github.com/n0-computer/iroh/commit/04c7247cd4dc75caae2299f1e713b7280cb64e0e))
- Change module structure and visibility and require docs ([#1176](https://github.com/n0-computer/iroh/issues/1176)) - ([81a0b1e](https://github.com/n0-computer/iroh/commit/81a0b1ecc92a0f844fbaa5455db1551040e170ee))
- Add PR template ([#1194](https://github.com/n0-computer/iroh/issues/1194)) - ([a3826c4](https://github.com/n0-computer/iroh/commit/a3826c42a092bae60aa8f944ed2e0e6e393dd026))
- Pause release builds ([#1206](https://github.com/n0-computer/iroh/issues/1206)) - ([69649ba](https://github.com/n0-computer/iroh/commit/69649ba603e17c893a698ed3da8923101a941db4))
- Cancel workflows when a new commit is pushed ([#1233](https://github.com/n0-computer/iroh/issues/1233)) - ([ca133a2](https://github.com/n0-computer/iroh/commit/ca133a228c7362da3650140116ee3f7cbc0798dc))
- Add metric readme and description - ([e2f55b1](https://github.com/n0-computer/iroh/commit/e2f55b1b6e3e7efd3ca6bede0c095f8cc186e804))
- Use version numbers for iroh deps - ([acf2d16](https://github.com/n0-computer/iroh/commit/acf2d167af667ec2288244302361721e1103cac4))
- Update deny.toml - ([d4c1a0f](https://github.com/n0-computer/iroh/commit/d4c1a0f7dd3bb9bb30642c8a64de8ab7da63a982))
- Release - ([cc01495](https://github.com/n0-computer/iroh/commit/cc0149596383d8fbaff29632a5b5f07bdfe5bd69))
- Release - ([947e0e3](https://github.com/n0-computer/iroh/commit/947e0e35819b895fa9e084d099bb311e79554376))

### Feat

- Request Tokens ([#1109](https://github.com/n0-computer/iroh/issues/1109)) - ([dbd7bfb](https://github.com/n0-computer/iroh/commit/dbd7bfb5a9d8960df1fb8415b8d555c028443147))

### Change

- Use DERP port from host_name URL ([#1143](https://github.com/n0-computer/iroh/issues/1143)) - ([fbeec14](https://github.com/n0-computer/iroh/commit/fbeec147f121d254be67a9cb838d42fe9a41af3f))

### Deper

- Ensure upgrades are allowed on derp - ([4f9cc86](https://github.com/n0-computer/iroh/commit/4f9cc86a35988f02097e01edd10d0abca7bfb1c1))

### Deps

- Update to released quic-rpc - ([0861b9f](https://github.com/n0-computer/iroh/commit/0861b9f093eacae79e89e9c8bbe0d46b0817d1bf))
- Update ed25519 and friends to released versions - ([a9ecbe2](https://github.com/n0-computer/iroh/commit/a9ecbe224dbd850c023e82d369d26d513e1c66b5))
- Update ([#1161](https://github.com/n0-computer/iroh/issues/1161)) - ([a0df682](https://github.com/n0-computer/iroh/commit/a0df6825fb4368876fd23ba7242300e209daeaa9))

### Derp

- Wait for connection - ([6c2f592](https://github.com/n0-computer/iroh/commit/6c2f5926d9f886bc4c53885151f8379f02c3e80b))

### Derper

- Refactor serving content & derp - ([05480a0](https://github.com/n0-computer/iroh/commit/05480a0e1af30af570469d6ab3971041ea3f8a6f))
- Cleanup - ([e60dc7f](https://github.com/n0-computer/iroh/commit/e60dc7fcefbdb7a73790236ed5f6d9caa28f2174))
- Add stun logs - ([f9175ca](https://github.com/n0-computer/iroh/commit/f9175cae4739b74d0a181ad8f49061efcd68744d))
- Stun improvements ([#1091](https://github.com/n0-computer/iroh/issues/1091)) - ([e191500](https://github.com/n0-computer/iroh/commit/e19150090a7669773e38819aa0ca52bbb3b40647))

### Endpoint

- Fix ping pong timings - ([e2f2bce](https://github.com/n0-computer/iroh/commit/e2f2bce0896cfe1b34836a4f6a770521169bd6fc))

### Key

- Remove dead code - ([8ef66f8](https://github.com/n0-computer/iroh/commit/8ef66f82cb2ab76601b3a88e679e2103434a4340))

### Magicsock

- :conn docs - ([a98ce77](https://github.com/n0-computer/iroh/commit/a98ce77ec0a57ee64feb561f3fed2bcc5fc9aa21))

### Metrics

- *(netcheck)* Add the basic netcheck metrics ([#1048](https://github.com/n0-computer/iroh/issues/1048)) - ([a548371](https://github.com/n0-computer/iroh/commit/a548371acef68cfc64c819a6534b291fe3e59aef))

### Netcheck

- Split up probe code - ([f832736](https://github.com/n0-computer/iroh/commit/f832736cf6decf2fbead5ed6abfb8c5d96176d74))

### Ref

- *(cli)* Declare args consistently, use defaults ([#970](https://github.com/n0-computer/iroh/issues/970)) - ([e7eebb0](https://github.com/n0-computer/iroh/commit/e7eebb0713a63c39e1b673b313ca334bfc6b94f1))
- *(clippy)* Let's keep it clippy clean ([#1009](https://github.com/n0-computer/iroh/issues/1009)) - ([034492c](https://github.com/n0-computer/iroh/commit/034492cd3a50c18636c6c86a3e762500db3f1e88))
- *(derp)* Default DNS name rooted at the DNS root ([#1231](https://github.com/n0-computer/iroh/issues/1231)) - ([8116345](https://github.com/n0-computer/iroh/commit/811634557c68a411797d62f5c9cb3aeee337bd23))
- *(metrics)* Document metrics and remove macro_use ([#1045](https://github.com/n0-computer/iroh/issues/1045)) - ([55d0211](https://github.com/n0-computer/iroh/commit/55d0211c5f4889a0e4b367622a319485b0cd3331))
- *(netcheck)* Statically declare udp bind addresses ([#1007](https://github.com/n0-computer/iroh/issues/1007)) - ([541fb87](https://github.com/n0-computer/iroh/commit/541fb878498fd31a5beabc1b3cb5f3671b6dea58))
- *(netcheck)* Log and shut down stun listeners ([#1022](https://github.com/n0-computer/iroh/issues/1022)) - ([252a04b](https://github.com/n0-computer/iroh/commit/252a04bec91ab437cf7dad9ddeac70e15762004c))
- *(netcheck)* Bring back the ActorMessage ([#1023](https://github.com/n0-computer/iroh/issues/1023)) - ([4437d7e](https://github.com/n0-computer/iroh/commit/4437d7e0708d13b32b37acce424f50f4e23df812))
- *(netcheck)* Make netcheck a long-running actor ([#1028](https://github.com/n0-computer/iroh/issues/1028)) - ([5f03510](https://github.com/n0-computer/iroh/commit/5f035109a9f4a197d53e7fe10d1b04d8a3a01739))
- *(netcheck)* Simplify and fix hairpinning ([#1051](https://github.com/n0-computer/iroh/issues/1051)) - ([b1fb4a6](https://github.com/n0-computer/iroh/commit/b1fb4a6774374b0befae9f99d10851052e83f3eb))
- *(netcheck)* Turn ReportState into more of an actor ([#1103](https://github.com/n0-computer/iroh/issues/1103)) - ([fbea8df](https://github.com/n0-computer/iroh/commit/fbea8df623808c8be1bb6efdae76115b3053f60e))
- *(tests)* Clean up various bits in tests ([#1145](https://github.com/n0-computer/iroh/issues/1145)) - ([da85f49](https://github.com/n0-computer/iroh/commit/da85f49a9e361ae1d69ee9bbbd38b658150a6656))
- *(tests)* Consisten test module naming ([#1181](https://github.com/n0-computer/iroh/issues/1181)) - ([05a39a4](https://github.com/n0-computer/iroh/commit/05a39a4c1c866314eee199caab920a576df2beb3))
- Change how a collection is created ([#939](https://github.com/n0-computer/iroh/issues/939)) - ([ce21952](https://github.com/n0-computer/iroh/commit/ce219523819c12d5d74c0cfafdccf043cfceab39))
- Rename Request.name to Request.hash ([#951](https://github.com/n0-computer/iroh/issues/951)) - ([ca1a091](https://github.com/n0-computer/iroh/commit/ca1a0919108f7401a093965bb9cebe9a666185c8))
- Naming heartbeats ([#982](https://github.com/n0-computer/iroh/issues/982)) - ([4a745ec](https://github.com/n0-computer/iroh/commit/4a745ec37af1ad3359b4b29f0c42548b1c035d65))
- Disable to unused code ([#992](https://github.com/n0-computer/iroh/issues/992)) - ([49dbaea](https://github.com/n0-computer/iroh/commit/49dbaea2e241800575eb812a94602a8cb474d845))
- Shut up clippy ([#1002](https://github.com/n0-computer/iroh/issues/1002)) - ([8df032b](https://github.com/n0-computer/iroh/commit/8df032b9aa74433c6999afd992de8a9f1aba44b1))
- Move packet building into conn ([#1016](https://github.com/n0-computer/iroh/issues/1016)) - ([3142912](https://github.com/n0-computer/iroh/commit/31429123a04ed215a69daa41dc7696b050c8d508))

## [0.4.1](https://github.com/n0-computer/iroh/compare/v0.4.0..v0.4.1) - 2023-04-03

### 🚜 Refactor

- Cleanup and move network related impls to the net module - ([3a442fa](https://github.com/n0-computer/iroh/commit/3a442fa013cc9aa9cdd82447fd0b8d1b64a148dd))

### 📚 Documentation

- *(changelog)* Prepare 0.4.1 - ([357d763](https://github.com/n0-computer/iroh/commit/357d763df4ba601054d8615a2d9ae2be210e8fb6))

### ⚙️ Miscellaneous Tasks

- Release iroh version 0.4.1 - ([4ebafa2](https://github.com/n0-computer/iroh/commit/4ebafa2d3d5a65a35c0cf131c01e68478dbbd40d))

## [0.4.0](https://github.com/n0-computer/iroh/compare/v0.3.0..v0.4.0) - 2023-03-29

### ⛰️  Features

- *(ci)* Push data to metro ([#794](https://github.com/n0-computer/iroh/issues/794)) - ([1a68106](https://github.com/n0-computer/iroh/commit/1a68106d07c0faf8d6354d6c313247529e8872f6))
- *(get-ticket)* Contact provider on all listening addrs ([#893](https://github.com/n0-computer/iroh/issues/893)) - ([adbb2bf](https://github.com/n0-computer/iroh/commit/adbb2bf1918087191dca8ef0cd403083e9600ea7))
- *(net)* Implement local address detection ([#822](https://github.com/n0-computer/iroh/issues/822)) - ([9323e10](https://github.com/n0-computer/iroh/commit/9323e10c9744ef83bef476d3fc9ec0503776b145))
- *(provider)* Emit events about outgoing transfers - ([f05ec8c](https://github.com/n0-computer/iroh/commit/f05ec8cbde836dda04b90867370ef3793a34e0f4))
- *(ticket)* Ensure a ticket always has at least one address ([#892](https://github.com/n0-computer/iroh/issues/892)) - ([0c17958](https://github.com/n0-computer/iroh/commit/0c17958dbc88e2b2ea81cca49119d541045630ef))
- Show more numbers in human readable form ([#790](https://github.com/n0-computer/iroh/issues/790)) - ([a0b7c26](https://github.com/n0-computer/iroh/commit/a0b7c26e5a4b83ae4413d25065405f54920eecfe))
- Use chunk groups feature ([#798](https://github.com/n0-computer/iroh/issues/798)) - ([d68f05d](https://github.com/n0-computer/iroh/commit/d68f05dc76b8e4b2d60329665e58c3a18edef51d))
- Begin impl Server side of derp, starting with the server side of the client connection ([#826](https://github.com/n0-computer/iroh/issues/826)) - ([94590ae](https://github.com/n0-computer/iroh/commit/94590ae0d1b548e055c8c7b9f40db04a52753947))
- Custom configs for netsim ([#862](https://github.com/n0-computer/iroh/issues/862)) - ([1078762](https://github.com/n0-computer/iroh/commit/10787624b00a7df46c42dae60b1a30f1b0ec5d0e))
- Release builds ([#863](https://github.com/n0-computer/iroh/issues/863)) - ([7b91c9a](https://github.com/n0-computer/iroh/commit/7b91c9ae4dbd9bda331027b38b6b5c64142eed8a))
- Set multiple addrs in the ticket ([#820](https://github.com/n0-computer/iroh/issues/820)) - ([9ac4cf6](https://github.com/n0-computer/iroh/commit/9ac4cf6e770879c8b2ec0dc6666fe531469e68e3))
- Ci netsim integration tests ([#877](https://github.com/n0-computer/iroh/issues/877)) - ([8fe1d81](https://github.com/n0-computer/iroh/commit/8fe1d8157aa68fb5ec981011ed797ac0619050c5))
- Cmd to list provide addrs ([#859](https://github.com/n0-computer/iroh/issues/859)) - ([2c0663a](https://github.com/n0-computer/iroh/commit/2c0663a9fcf2f79989e468a0daa79c40974d92ec))
- Add run_ticket to dial all addresses stored in a Ticket ([#888](https://github.com/n0-computer/iroh/issues/888)) - ([91c7e2a](https://github.com/n0-computer/iroh/commit/91c7e2aee1f7f4059f3d391725fb49af4410a3eb))

### 🐛 Bug Fixes

- *(ci)* Move from sendme to iroh ([#788](https://github.com/n0-computer/iroh/issues/788)) - ([6a5c13e](https://github.com/n0-computer/iroh/commit/6a5c13e31c1a29b39c6b308b1cd7cf4c20f19a52))
- *(ci)* Format output as table ([#791](https://github.com/n0-computer/iroh/issues/791)) - ([7fb888d](https://github.com/n0-computer/iroh/commit/7fb888d699b3f25b80687cbf5278ea8428009bda))
- *(netcheck)* Reduce locking and improved task tracking - ([5a733ff](https://github.com/n0-computer/iroh/commit/5a733ff63400a40bd155c4ac710d5057e0422069))
- *(provider)* Ensure postcard buffers are appropriately sized - ([c28e0a8](https://github.com/n0-computer/iroh/commit/c28e0a844797e5a21a42cab4a015fd802c30ba46))
- Avoid other output between contents when printing ([#786](https://github.com/n0-computer/iroh/issues/786)) - ([9076443](https://github.com/n0-computer/iroh/commit/907644345f1e8b6990d7d4cb278ab7c2e1be9e84))
- Improve listening addr output ([#789](https://github.com/n0-computer/iroh/issues/789)) - ([33c0482](https://github.com/n0-computer/iroh/commit/33c0482874d2c65e2ac45e11e22d5ec192608454))
- Output writing ([#804](https://github.com/n0-computer/iroh/issues/804)) - ([eb18a89](https://github.com/n0-computer/iroh/commit/eb18a89fa6f2bd4fdbb49ebe0b218869bc793bbc))
- Do not send duplicate NotFound responses ([#802](https://github.com/n0-computer/iroh/issues/802)) - ([c0d4984](https://github.com/n0-computer/iroh/commit/c0d4984086f443a216d51073a84ebb734c96a762))
- Compile on linux - ([02d8803](https://github.com/n0-computer/iroh/commit/02d880366ce42ced01552ca4c55ff814f9ae7a56))
- Update Cargo.lock after rebase - ([56fd099](https://github.com/n0-computer/iroh/commit/56fd099573f31075afd41c6613aa4342217f38ed))
- Update to new default-net - ([e2584c0](https://github.com/n0-computer/iroh/commit/e2584c007b53325e929f7d12b078ed94b9e6bfd0))
- Improve binding and rebinding of sockets - ([156560a](https://github.com/n0-computer/iroh/commit/156560aec24f20d06deafca425e5f18d338ec9ff))
- Use absolute paths everywhere ([#836](https://github.com/n0-computer/iroh/issues/836)) - ([b2730ee](https://github.com/n0-computer/iroh/commit/b2730ee004890a0930d09af7d8fb7dfd483befd0))
- Fix netsim bin paths ([#881](https://github.com/n0-computer/iroh/issues/881)) - ([3291291](https://github.com/n0-computer/iroh/commit/3291291991deb3e268e8247f50379a43421b4095))

### 🚜 Refactor

- Move timer to own file - ([1c0a763](https://github.com/n0-computer/iroh/commit/1c0a763d7f9105bc9f546a0d24ba3f2935be1eb6))

### 📚 Documentation

- *(changelog)* Prepare for 0.4.0 - ([005d0b1](https://github.com/n0-computer/iroh/commit/005d0b119ada926e103c7de636f9a350c2b90721))
- Fix typo ([#792](https://github.com/n0-computer/iroh/issues/792)) - ([a12de97](https://github.com/n0-computer/iroh/commit/a12de974312a9debe94ed85818f9fadf7d5c57d3))
- Add some missing comments about android default route ([#828](https://github.com/n0-computer/iroh/issues/828)) - ([1fedf46](https://github.com/n0-computer/iroh/commit/1fedf460f8dbd77a1d67e02537b755f49c49b832))

### 🧪 Testing

- Cli integration test for provide-get loop ([#781](https://github.com/n0-computer/iroh/issues/781)) - ([61ba002](https://github.com/n0-computer/iroh/commit/61ba002855ab8ae47c65d1489c5d2f5bd812b78d))
- Add failing test for large collections - ([bdab174](https://github.com/n0-computer/iroh/commit/bdab1741da7c890e2a6f272ed6684449cad3c465))

### ⚙️ Miscellaneous Tasks

- *(android)* Use the real android targets ([#880](https://github.com/n0-computer/iroh/issues/880)) - ([f198944](https://github.com/n0-computer/iroh/commit/f19894486bf480bfd9194a7028f79e19cee25add))
- Add cargo-deny ([#810](https://github.com/n0-computer/iroh/issues/810)) - ([96bb61b](https://github.com/n0-computer/iroh/commit/96bb61b2a8567a9be1c7d190684e7f29860d023e))
- Ci - replace actions-rs with dtolnay/rust-toolchain ([#884](https://github.com/n0-computer/iroh/issues/884)) - ([bf22ee2](https://github.com/n0-computer/iroh/commit/bf22ee2c311cf2a845bd7ef9425dc773d05502a2))
- Update netsim sims ([#887](https://github.com/n0-computer/iroh/issues/887)) - ([59babe1](https://github.com/n0-computer/iroh/commit/59babe14aa481e90dd09d16bd91fa9b4e12c9c54))
- Release iroh version 0.4.0 - ([5401321](https://github.com/n0-computer/iroh/commit/5401321761e305b8ad9cd8742be0c3d241ff0c7a))

### 🛡️ Security

- New version of tempfile to avoid security issue ([#819](https://github.com/n0-computer/iroh/issues/819)) - ([55a4c3a](https://github.com/n0-computer/iroh/commit/55a4c3aa4ab837384c03d15382e03182b785e84e))

### Deps

- *(default-net)* Bump version ([#879](https://github.com/n0-computer/iroh/issues/879)) - ([887c128](https://github.com/n0-computer/iroh/commit/887c128ccf2a8d1fc60887bae90f089f8a234bce))
- Updated from yanked version ([#890](https://github.com/n0-computer/iroh/issues/890)) - ([80ee3db](https://github.com/n0-computer/iroh/commit/80ee3db85ac4fdd234d1f6ee1f08f18e6ccaded1))

### Derp

- Fix missing server - ([75b6cee](https://github.com/n0-computer/iroh/commit/75b6cee9b59b54a531ec28266ba8a17500acd2c7))
- Implement first pass at client dialing - ([a37b3dc](https://github.com/n0-computer/iroh/commit/a37b3dcd75975b9d1857330c6371facb55cd85a8))

### Derper

- Implement manual certificate loading - ([283eab9](https://github.com/n0-computer/iroh/commit/283eab948dd29502c89534909547d199b392cd45))
- Fix hostname test - ([3a87872](https://github.com/n0-computer/iroh/commit/3a87872edf45150fb0aa7fe1d261b51d87e71406))

### Impl

- `Client` and `Clients`, how the server manages the different connected clients ([#846](https://github.com/n0-computer/iroh/issues/846)) - ([c502e57](https://github.com/n0-computer/iroh/commit/c502e57cd36bba9218730e5b8722ec15e3ad87f2))

### Magicsock

- Some cleanup - ([c0118d0](https://github.com/n0-computer/iroh/commit/c0118d0bd35fff77b799c7e4d538cc8cc0ed63a8))

### Magiscock

- New - ([080672b](https://github.com/n0-computer/iroh/commit/080672b7f78cb427c86d59960c9e646e732ded1f))

### Magisock

- Split into multiple files - ([0cff7b1](https://github.com/n0-computer/iroh/commit/0cff7b1fd790249b4a709f175128f8522bf96edf))
- More splitting - ([cbdda92](https://github.com/n0-computer/iroh/commit/cbdda92cd738619c1d6294f7c2f7b6bf9cabfae4))

### Netcheck

- Get main check logic to compile - ([e0748de](https://github.com/n0-computer/iroh/commit/e0748dea940b7680101147de63b902631e72a119))
- Fix first basic test - ([687f829](https://github.com/n0-computer/iroh/commit/687f829b9723eb692f68b999f301fea4ce112f48))

### Ref

- Rename --token to --auth-token for get ([#785](https://github.com/n0-computer/iroh/issues/785)) - ([d9aed3c](https://github.com/n0-computer/iroh/commit/d9aed3ca78716adece7d7fe2508066f32630ec3b))
- Remove duplicate read_lp implementation ([#801](https://github.com/n0-computer/iroh/issues/801)) - ([e80051e](https://github.com/n0-computer/iroh/commit/e80051e43d85c2d734e829415836e415b8ef976c))
- Micro-optimise by reserving buffer size ([#803](https://github.com/n0-computer/iroh/issues/803)) - ([fe97e4d](https://github.com/n0-computer/iroh/commit/fe97e4d154b0c15007f067241c6d2961ea346f4e))
- Bring back testdir for integration tests ([#811](https://github.com/n0-computer/iroh/issues/811)) - ([b0ade88](https://github.com/n0-computer/iroh/commit/b0ade88df2bc534ac0c4e5f037b42d1c01361008))
- Improve error for connection timeout ([#818](https://github.com/n0-computer/iroh/issues/818)) - ([9f2b486](https://github.com/n0-computer/iroh/commit/9f2b486a6fef0eff21df4549337c3585f4dea75e))
- Clean up public API regarding bound/local/listening addresses ([#891](https://github.com/n0-computer/iroh/issues/891)) - ([bbf4869](https://github.com/n0-computer/iroh/commit/bbf4869992182e22f1502b89c07618a91b7641e6))

## [0.3.0](https://github.com/n0-computer/iroh/compare/xtask-v0.2.0..v0.3.0) - 2023-02-22

### ⛰️  Features

- *(ci)* Add MSRV check - ([2a62263](https://github.com/n0-computer/iroh/commit/2a6226376dbff09049d4b5d1fa81777f22e8a5cd))
- *(ci)* Add MSRV check - ([2894143](https://github.com/n0-computer/iroh/commit/2894143f307065033430dde6d0844184b813195f))
- *(cli)* Improve the output of collections ([#69](https://github.com/n0-computer/iroh/issues/69)) - ([733e533](https://github.com/n0-computer/iroh/commit/733e53369e9e87da5aa99a5778875effc67b03c2))
- *(provider)* Add `ProviderBuilder` - ([bf01702](https://github.com/n0-computer/iroh/commit/bf01702ab7abed63490c508a3f503682bffc5f25))
- *(provider)* Add persistent identity - ([6073054](https://github.com/n0-computer/iroh/commit/60730540157a144e1fff1a598a0be9aff5d03a6d))
- *(provider)* Add events ([#87](https://github.com/n0-computer/iroh/issues/87)) - ([e7ce384](https://github.com/n0-computer/iroh/commit/e7ce384d1cb816c09d00c238cb355573e2a1c273))
- Add clap and server and client options - ([e46d460](https://github.com/n0-computer/iroh/commit/e46d460222a014939c64e9a5a49a2eebf5175602))
- Limit length prefixed message size - ([d99007e](https://github.com/n0-computer/iroh/commit/d99007e4ce5b2880c8f463d2b7e6a6ce4e87f502))
- Add handshake and reduce allocations - ([6403bd1](https://github.com/n0-computer/iroh/commit/6403bd1bb87b9f83c502d243e2b006a1ec8108a2))
- Limit number of active connections and streams - ([1dd46e9](https://github.com/n0-computer/iroh/commit/1dd46e9a6d49d65f989aa7a00da598b92754c6c9))
- Connect based on PeerIds - ([c57fa4f](https://github.com/n0-computer/iroh/commit/c57fa4f7d5e9c83a75560a4a80e5dd8a62778334))
- Rework client api to emit content - ([03e1f93](https://github.com/n0-computer/iroh/commit/03e1f9377d61dded6f67d924ec52578252de5514))
- Write to temporary file during transfer - ([1f39a57](https://github.com/n0-computer/iroh/commit/1f39a57e6e40ba98aa994d1a7b6e55daa51c3311))
- Add STDIN and STDOUT support ([#39](https://github.com/n0-computer/iroh/issues/39)) - ([c121094](https://github.com/n0-computer/iroh/commit/c121094de2dbe1487f178c2dc531a026b4f63fbf))
- Add authentication token to protocol handshake - ([58a2c2a](https://github.com/n0-computer/iroh/commit/58a2c2a48ba4ba8fd8be3dcbc549fd3ddc472270))
- Add authentication token to protocol handshake - ([bf08478](https://github.com/n0-computer/iroh/commit/bf084783ac03e18cfb62155eaf683cc771a4eda1))
- Transfer multiple files - ([bc040ea](https://github.com/n0-computer/iroh/commit/bc040eab08520236d070bbd3c91ba440c0a294f4))
- Improve CLI  - ([57dd758](https://github.com/n0-computer/iroh/commit/57dd758791bd2c9a1b4c72f0414286673d285514))
- Create a Builder for the Provider - ([41e05ed](https://github.com/n0-computer/iroh/commit/41e05ed8ff390491e2296615640d575916958388))
- Create a Builder for the Provider - ([bf087b6](https://github.com/n0-computer/iroh/commit/bf087b63a520fba3eecef04cc9e77d938430571f))
- Incrementally compute outboard - ([bf86837](https://github.com/n0-computer/iroh/commit/bf86837b7967c75f8f6d5d20d082d845197b66f8))
- Provide a single ticket to fetch a hash - ([5b979ab](https://github.com/n0-computer/iroh/commit/5b979abe018296a8cc01fc11e26f58aacb37f737))
- Provide a single ticket to fetch a hash - ([aa269ab](https://github.com/n0-computer/iroh/commit/aa269ab315d60d569e6df86720cc5fe404f50418))
- Remove varints ([#71](https://github.com/n0-computer/iroh/issues/71)) - ([35cb4bd](https://github.com/n0-computer/iroh/commit/35cb4bd28a8e9f82e2575d5cd164658dd868d20f))
- Looser dependencies as it is a library - ([a846ea2](https://github.com/n0-computer/iroh/commit/a846ea2652526fcb8f414cf188950895f9f62951))
- Looser dependencies as it is a library - ([eb07ca9](https://github.com/n0-computer/iroh/commit/eb07ca917dc519c85314350033c38dacc364c675))
- Add bao slice decoder - ([08ad6db](https://github.com/n0-computer/iroh/commit/08ad6db112a494799c07e703584859d093960d88))
- Step 1 - change from outboard+data to encoded - ([c5be9f5](https://github.com/n0-computer/iroh/commit/c5be9f5d557c412d421d6b970cccd3d377879659))
- Step 2 - use SyncIoBridge when writing - ([4d3b384](https://github.com/n0-computer/iroh/commit/4d3b384d8c6148c001fdc85196d8ce5d57695d54))
- Step 3 actually add AsyncSliceDecoder and friends - ([ff39ef2](https://github.com/n0-computer/iroh/commit/ff39ef2caf17074c4daab21d957fbe50bd544fa7))
- Step 4 make use of the AsyncSliceDecoder - ([80b9cff](https://github.com/n0-computer/iroh/commit/80b9cff77b133d5887fbe74f1964385ab23fce92))
- Pass in custom names for blobs using `DataSource::NamedFile` ([#97](https://github.com/n0-computer/iroh/issues/97)) - ([9b2ad04](https://github.com/n0-computer/iroh/commit/9b2ad046e9025f2a76a090d5b0122c5c559777d0))
- Add method read_size - ([bcc66f9](https://github.com/n0-computer/iroh/commit/bcc66f93097cc26a3cd29695e2fc0a45c0871f5c))
- Use read_size() to enforce that we don't download oversized files - ([cb6651e](https://github.com/n0-computer/iroh/commit/cb6651eaf94abeac5439a3416a6b38970f69eef1))
- Ensure we are not being lied to about total_blobs_size - ([6d66fc5](https://github.com/n0-computer/iroh/commit/6d66fc5865763ccd7c109c19bbc78fc860a06f23))
- Switch printing from hex to base64 - ([891004d](https://github.com/n0-computer/iroh/commit/891004d8059191e4005170b3d4982d13f152293f))
- Introduce custom Hash type ([#115](https://github.com/n0-computer/iroh/issues/115)) - ([c1eaf28](https://github.com/n0-computer/iroh/commit/c1eaf28fcc42f147ae0483dd3afda9ce47e26105))
- Switch from s2n-quic to quinn ([#112](https://github.com/n0-computer/iroh/issues/112)) - ([3eff210](https://github.com/n0-computer/iroh/commit/3eff2107559784459262df255a6d3d3fd55070c8))
- Add newtype wrapper for Hash that is compatible with Cid - ([9db0937](https://github.com/n0-computer/iroh/commit/9db0937cb67f6eddcf0b516496806033f03a25e2))
- Allow shutdown of Provider ([#121](https://github.com/n0-computer/iroh/issues/121)) - ([13f703f](https://github.com/n0-computer/iroh/commit/13f703f0ef04109c493edae0d4d57c39dce88234))
- Do not error when the provider closes the connection ([#124](https://github.com/n0-computer/iroh/issues/124)) - ([5bd545d](https://github.com/n0-computer/iroh/commit/5bd545d8eb800a48b36c8d7d2333b9f21afec49a))
- Add generic progress emitter utility ([#141](https://github.com/n0-computer/iroh/issues/141)) - ([d09a786](https://github.com/n0-computer/iroh/commit/d09a78636b6b280a4ca67c9948ba6325c4c75088))
- Add option to use SSLKEYLOGFILE env var ([#153](https://github.com/n0-computer/iroh/issues/153)) - ([d64d12d](https://github.com/n0-computer/iroh/commit/d64d12db44709570f37b213937b697bc31f2eaaa))
- Use our own ALPN ([#155](https://github.com/n0-computer/iroh/issues/155)) - ([2991cbb](https://github.com/n0-computer/iroh/commit/2991cbb6bb43b6217da9543a415cedaf06b4fe10))
- Netsim CI ([#135](https://github.com/n0-computer/iroh/issues/135)) - ([3a3fc46](https://github.com/n0-computer/iroh/commit/3a3fc46ba9faef7deff9f63a9b36e9a7ed00655e))
- Rename to iroh - ([e3012f0](https://github.com/n0-computer/iroh/commit/e3012f0cb444fa3a990d6037b57491dd7ecdef15))
- Move --keylog to common flags ([#776](https://github.com/n0-computer/iroh/issues/776)) - ([feeefa9](https://github.com/n0-computer/iroh/commit/feeefa9ded8bcec82117f8860030d86a232c228d))
- Make get work on IPv6 network ([#777](https://github.com/n0-computer/iroh/issues/777)) - ([c28a378](https://github.com/n0-computer/iroh/commit/c28a3783c51824c1dd5bafff019c079d33da2fa2))
- Remove MAX_DATA_LIMIT ([#780](https://github.com/n0-computer/iroh/issues/780)) - ([42a6235](https://github.com/n0-computer/iroh/commit/42a6235690c688e74d573976e08dc808e5f3d725))
- Remove Request.id from the protocol ([#782](https://github.com/n0-computer/iroh/issues/782)) - ([fd37cab](https://github.com/n0-computer/iroh/commit/fd37cab02c2bd43f88108205fd0f0de2ed94896f))

### 🐛 Bug Fixes

- *(bin)* Ensure progressbar works for stdout ([#81](https://github.com/n0-computer/iroh/issues/81)) - ([93107e3](https://github.com/n0-computer/iroh/commit/93107e37e8fdf1e3a37da435ee9d3701088255f8))
- *(ci)* Run clippy directly ([#140](https://github.com/n0-computer/iroh/issues/140)) - ([fc8fbeb](https://github.com/n0-computer/iroh/commit/fc8fbeb65c1468d54fe0873486d00ad692feddfb))
- *(cli)* Only write progress if TTY  and write it stderr only - ([55ff6ed](https://github.com/n0-computer/iroh/commit/55ff6ed6aa02ff35ef6133ce484bb1e7e48ee901))
- *(main)* Remove stderr tty check - ([588dbe7](https://github.com/n0-computer/iroh/commit/588dbe778b1255012b1584ecb77ccce9bdb2f414))
- Ensure data is flushed to disk - ([9f9292d](https://github.com/n0-computer/iroh/commit/9f9292d63dd49b195ed37637335e116a088a26e4))
- Keep reading and respect EOF - ([ae51187](https://github.com/n0-computer/iroh/commit/ae5118717b845952c1e6ba35df26db55027306c7))
- Keep reading and respect EOF - ([dbbf510](https://github.com/n0-computer/iroh/commit/dbbf510053afc151e94bfdeae3f4fafedac5ded0))
- Windows multi_client tests ([#66](https://github.com/n0-computer/iroh/issues/66)) - ([4befae2](https://github.com/n0-computer/iroh/commit/4befae261dbbe5f82ed5f77e5492113dee42b286))
- Ensure CI runs on main ([#100](https://github.com/n0-computer/iroh/issues/100)) - ([43a6ed5](https://github.com/n0-computer/iroh/commit/43a6ed505f0665aa0de58ebb840f946ee18baf3e))
- Catch `ctrl-c` to allow a normal shutdown & clean up any tempfiles that are created ([#122](https://github.com/n0-computer/iroh/issues/122)) - ([82e2f56](https://github.com/n0-computer/iroh/commit/82e2f5649bdaaa72b3c239d8723af276db6a44fc))
- Display CIDs in the CLI for the `Collection` ([#131](https://github.com/n0-computer/iroh/issues/131)) - ([b3ee39f](https://github.com/n0-computer/iroh/commit/b3ee39f92f431173810914534bfcaa3b2d469708))
- Fail if an on_blob function does not read all the content ([#139](https://github.com/n0-computer/iroh/issues/139)) - ([c266ab5](https://github.com/n0-computer/iroh/commit/c266ab5d9d1605bb6061a6ac637781672aa1056b))
- MSRV in CI ([#145](https://github.com/n0-computer/iroh/issues/145)) - ([2edb528](https://github.com/n0-computer/iroh/commit/2edb528007dd773e7f00fd4dd460506c8abf1681))
- Ensure we emit `TransferAborted` event if anything goes wrong during the transfer ([#150](https://github.com/n0-computer/iroh/issues/150)) - ([19e2b05](https://github.com/n0-computer/iroh/commit/19e2b058c52753149444f3e719347778c862f99d))

### 🚜 Refactor

- Make code library based - ([1c3373c](https://github.com/n0-computer/iroh/commit/1c3373c8c3a2012c9c4630a2d69edcb2a04a3795))
- Cleanup and improve address options - ([ba59337](https://github.com/n0-computer/iroh/commit/ba5933767d5df9eb4fd66aac9e395f6d02c218a0))
- Rename server & client - ([de34409](https://github.com/n0-computer/iroh/commit/de344092c9ff1a4063c54f32e6ae5822b238d4da))
- Use genawaiter instead of async-stream - ([5c48f5e](https://github.com/n0-computer/iroh/commit/5c48f5eec3ffb081ed9865796dac307265964049))
- Switch to callbacks instead of events - ([ea94e98](https://github.com/n0-computer/iroh/commit/ea94e982516f816650582d95e1a6a3fdf6f0319d))
- Named closures for the 3 callbacks - ([6617d39](https://github.com/n0-computer/iroh/commit/6617d3986840bd9ebef75c2786109446ac473806))
- Remove size from found - ([bd9d860](https://github.com/n0-computer/iroh/commit/bd9d8607750d1db1bacff763385cb50a0b0b59a2))
- Remove size from FoundCollection as well - ([7faf4bf](https://github.com/n0-computer/iroh/commit/7faf4bfd7a57f555e6614e62b95022d6e8eca831))
- Add debug instances for public types - ([b0cdec1](https://github.com/n0-computer/iroh/commit/b0cdec109d6d6a1047d624ddbe8a89e3c8ec3c93))
- Make AsyncSliceDecoder pub(crate) - ([6bc00b3](https://github.com/n0-computer/iroh/commit/6bc00b3558cd03b3f99355566d021c63769bae61))
- Make a few obvious things private - ([d63fea1](https://github.com/n0-computer/iroh/commit/d63fea1279fe90c7e3193420f8babb7864ece395))
- More privatization - ([5994474](https://github.com/n0-computer/iroh/commit/5994474c4d270569007570e8cb39138d9b7fc8b9))
- Move Blake3Cid to main for now - ([7158bc0](https://github.com/n0-computer/iroh/commit/7158bc047c9a42a25d12330dbc46ef9647331894))
- Make on_collection take a reference - ([34aa8e1](https://github.com/n0-computer/iroh/commit/34aa8e1514f086fd310867691ba0915eab85f349))
- Use multi threading when computing outboards - ([34cf223](https://github.com/n0-computer/iroh/commit/34cf223098e4287f0935f45cc44eb1562b864a35))

### 📚 Documentation

- Add readme and license - ([b37c135](https://github.com/n0-computer/iroh/commit/b37c1357b62d958f1c15ec0ec35928a479a457c0))
- Add lots of doc comments and enable deny(missing_docs) - ([8255467](https://github.com/n0-computer/iroh/commit/8255467c9a64c70a28bc6d4b62bacaadbc0f6b6d))
- Add docs for the 4 prefix bytes - ([838fa5c](https://github.com/n0-computer/iroh/commit/838fa5cb7eac3a474c72fbb3bea841128779849e))
- Add some comments - ([a4a3d54](https://github.com/n0-computer/iroh/commit/a4a3d546d12f8026a14d8333924e7c061a56a7bd))
- Updates for release - ([70f9912](https://github.com/n0-computer/iroh/commit/70f991230db511c4501c8ec0c950646aaf6379d1))

### 🧪 Testing

- Avoid file system - ([dc2fe24](https://github.com/n0-computer/iroh/commit/dc2fe24d173768b1270ff5622d158757b64f1a1c))
- Use differnt ports - ([4cb1a5a](https://github.com/n0-computer/iroh/commit/4cb1a5af3aae9401122367cf9a21daacee2b4b67))
- Use multithread runtime - ([48acbe8](https://github.com/n0-computer/iroh/commit/48acbe8272b9e07665256ec65fdb77b18bdc7ef5))
- Different port - ([40a60c7](https://github.com/n0-computer/iroh/commit/40a60c73a3eb845356876d6c28b252cbf47616b4))
- Different sizes - ([a1d6927](https://github.com/n0-computer/iroh/commit/a1d6927f9c907e612552605b198e3b165c6571f9))
- Add test to make sure that - ([14d8554](https://github.com/n0-computer/iroh/commit/14d85549c510d52bbdb6f6ab35a32b1fdc44333d))
- Use random free port to avoid collisions ([#104](https://github.com/n0-computer/iroh/issues/104)) - ([1abd7ec](https://github.com/n0-computer/iroh/commit/1abd7ecbff29dfdcaaa58f63994747460bd9e105))

### ⚙️ Miscellaneous Tasks

- Remove unused dependency - ([1cf338d](https://github.com/n0-computer/iroh/commit/1cf338d41a892c027391722a63ffdb929fe85206))
- Update MSRV to 1.64 - ([e2cd922](https://github.com/n0-computer/iroh/commit/e2cd922fd84de17eb55f137ea84de5f5cc915007))
- Remove duplicate tokio dependency ([#137](https://github.com/n0-computer/iroh/issues/137)) - ([8e42874](https://github.com/n0-computer/iroh/commit/8e42874a2355a42bd6e6f037382247a18614aedf))
- Improve safety of BytesMut buffer usage ([#778](https://github.com/n0-computer/iroh/issues/778)) - ([7fbeb4f](https://github.com/n0-computer/iroh/commit/7fbeb4fef40b53edb7f9b0c09869a05db904f18c))
- Add changelog for 0.3.0 - ([c8855f8](https://github.com/n0-computer/iroh/commit/c8855f8cba95875b0e095913e9357c01bdd23a38))
- Release iroh version 0.3.0 - ([7923829](https://github.com/n0-computer/iroh/commit/792382953805d769173b326d21a718d91a8ba2d3))

### Fix

- Duplicate `serde_hash` implementation & some spelling errors ([#72](https://github.com/n0-computer/iroh/issues/72)) - ([53ab719](https://github.com/n0-computer/iroh/commit/53ab7196a588242d9d7d50502d9565d3bcf714ad))

### Ref

- Take the collection hash from the db creation ([#93](https://github.com/n0-computer/iroh/issues/93)) - ([f60ce6f](https://github.com/n0-computer/iroh/commit/f60ce6ff8de87f5c1506651467e2d51c9fbde13d))
- Pub api tweaks ([#114](https://github.com/n0-computer/iroh/issues/114)) - ([eb48132](https://github.com/n0-computer/iroh/commit/eb48132c9cf84e68452a99052400e708c9e31fcc))
- On_collection doesn't need to be FnMut ([#136](https://github.com/n0-computer/iroh/issues/136)) - ([eac7b65](https://github.com/n0-computer/iroh/commit/eac7b65a6760c0cf55d455ca5a7e9e523698c7a1))
- Allow older rust version ([#142](https://github.com/n0-computer/iroh/issues/142)) - ([f3086a9](https://github.com/n0-computer/iroh/commit/f3086a9576fdc0cdfbd6b0646745bec9e91f7d60))
- Use our own bao crate - ([659d2d2](https://github.com/n0-computer/iroh/commit/659d2d22254ea1d3f185ec0d4c8be4e7bf4374df))


