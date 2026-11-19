# Changelog

All notable changes to iroh-relay will be documented in this file.

<!-- git-cliff: end of header -->
## [1.5.0](https://github.com/n0-computer/iroh/compare/v1.4.2..1.5.0) - 2026-11-19

### ⛰️  Features

- *(iroh-relay)* Fix potentially leaking connections during handshake ([#4621](https://github.com/n0-computer/iroh/issues/4621)) - ([9abdae4](https://github.com/n0-computer/iroh/commit/9abdae460b54a936257c3f72bca393ae2d44bccd))
- *(iroh-relay)* Keep the relay URL's path prefix ([#4617](https://github.com/n0-computer/iroh/issues/4617)) - ([5b98ddb](https://github.com/n0-computer/iroh/commit/5b98ddbaeb5fadea6ec8652e25b9fd1ef207e8e2))

### 🐛 Bug Fixes

- *(iroh-relay)* Keep proxy credentials out of the debug log ([#4653](https://github.com/n0-computer/iroh/issues/4653)) - ([f350394](https://github.com/n0-computer/iroh/commit/f35039493803c240595cc7b56a976b8bb14f8f05))
- *(iroh-relay)* Drop packets that cannot be encoded instead of disconnecting the recv side ([#4694](https://github.com/n0-computer/iroh/issues/4694)) - ([325b3d3](https://github.com/n0-computer/iroh/commit/325b3d3e13785e52d5e159852bd0fa732d063aad))
- *(iroh-relay)* Prevent empty datagrams payload from disconnecting recipient ([#4646](https://github.com/n0-computer/iroh/issues/4646)) - ([55181bf](https://github.com/n0-computer/iroh/commit/55181bfd33b67e70e5388adaccb218bf00312d2e))

### ⚙️ Miscellaneous Tasks

- *(*)* Dependabot updates ([#4652](https://github.com/n0-computer/iroh/issues/4652)) - ([3e9a854](https://github.com/n0-computer/iroh/commit/3e9a854c3292d2fe5958294674b604331d8a350a))

### Deps

- Upgrade noq, tokio-rustls-acme, and patchbay deps ([#4701](https://github.com/n0-computer/iroh/issues/4701)) - ([7a863f1](https://github.com/n0-computer/iroh/commit/7a863f1b917213da7c1a8e865b35f403a0fc8072))


## [1.4.2](https://github.com/n0-computer/iroh/compare/v1.4.1..1.4.2) - 2026-11-19

### 🐛 Bug Fixes

- *(iroh-relay)* Check the full frame length when decoding client frames - ([41b7244](https://github.com/n0-computer/iroh/commit/41b7244238c78fa3a0bd094e47e5639d264d8382))
- *(iroh-relay)* Bound the client actor's flushes by the write timeout - ([fe9e92e](https://github.com/n0-computer/iroh/commit/fe9e92eee1f91d77c8c6383d94323b0f43ec98bf))
- *(iroh-relay)* Stop reading after a ping until its pong is written - ([507ab37](https://github.com/n0-computer/iroh/commit/507ab37534d8f47ff0681761bcf3bfc359655aa6))
- *(iroh-relay)* Prevent empty datagrams payload from disconnecting recipient ([#4646](https://github.com/n0-computer/iroh/issues/4646)) - ([e58b1e5](https://github.com/n0-computer/iroh/commit/e58b1e5c53a4d8d0189b3432ccd879659f1afd0f))
- *(iroh-relay)* Drop packets that cannot be encoded instead of disconnecting the recv side ([#4694](https://github.com/n0-computer/iroh/issues/4694)) - ([ddb5460](https://github.com/n0-computer/iroh/commit/ddb546092f6dd7ed3f48c3e61d3bec19215eb5e7))


## [1.4.1](https://github.com/n0-computer/iroh/compare/v1.4.0..1.4.1) - 2026-10-21

### ⚙️ Miscellaneous Tasks

- Fix changelog ([#4628](https://github.com/n0-computer/iroh/issues/4628)) - ([efcb1c3](https://github.com/n0-computer/iroh/commit/efcb1c3f987127529458f2734a076acacf0254e3))



## [1.4.0](https://github.com/n0-computer/iroh/compare/v1.3.0..1.4.0) - 2026-10-20

### ⛰️  Features

- *(iroh-relay)* Send `X-Iroh-Endpoint-Id` header and deprecate `X-Iroh-NodeId` ([#4586](https://github.com/n0-computer/iroh/issues/4586)) - ([f953e82](https://github.com/n0-computer/iroh/commit/f953e82581bd4ede8ef09951f49b2f031cea36a7))

### 🐛 Bug Fixes

- *(iroh)* Reduce cache startup memory ([#4574](https://github.com/n0-computer/iroh/issues/4574)) - ([dce5173](https://github.com/n0-computer/iroh/commit/dce5173bc43c70441249a784012dbe7a1f5b3afe))
- *(iroh-relay)* Send correct Proxy-Authorization credentials ([#4591](https://github.com/n0-computer/iroh/issues/4591)) - ([d4490fc](https://github.com/n0-computer/iroh/commit/d4490fcfde8e4dc7260a44a2a982c654748595e2))
- *(iroh-relay)* Put a timeout on captive portal checks ([#4614](https://github.com/n0-computer/iroh/issues/4614)) - ([2624e32](https://github.com/n0-computer/iroh/commit/2624e3231754a9a6948d4037e1bf536140609941))

### ⚙️ Miscellaneous Tasks

- Update noq dependency - ([d506cb9](https://github.com/n0-computer/iroh/commit/d506cb967599c0d1901becf591e286930a8b48d2))

## [1.3.0](https://github.com/n0-computer/iroh/compare/v1.2.0..1.3.0) - 2026-09-28

### ⛰️  Features

- *(metrics)* Lookup/resolver stats ([#4543](https://github.com/n0-computer/iroh/issues/4543)) - ([b29c0a4](https://github.com/n0-computer/iroh/commit/b29c0a424c7bae7831ba1cb7e4a94e08ba04cfd5))

## [1.2.0](https://github.com/n0-computer/iroh/compare/v1.1.0..1.2.0) - 2026-09-09

### ⛰️  Features

- Switch to n0-dns-resolver and make fallback nameservers configurable ([#4419](https://github.com/n0-computer/iroh/issues/4419)) - ([1a68838](https://github.com/n0-computer/iroh/commit/1a68838b34c6c4646ada9fafaf65b29f9577a446))

### ⚙️ Miscellaneous Tasks

- *(*)* Upgrade to `noq`, `noq-proto`, `noq-udp` v1.3.0 ([#4518](https://github.com/n0-computer/iroh/issues/4518)) - ([cb5d12b](https://github.com/n0-computer/iroh/commit/cb5d12b5019966819f0e6eba23233885cd65cf7b))

## [1.1.0](https://github.com/n0-computer/iroh/compare/v1.0.3..1.1.0) - 2026-08-25

### ⛰️  Features

- *(iroh-relay, iroh)* Inform clients when they are rate-limited and warn log in iroh ([#4455](https://github.com/n0-computer/iroh/issues/4455)) - ([e68dbda](https://github.com/n0-computer/iroh/commit/e68dbda9ada25da61a2bcdff5eb12b9bc8e0ba1e))

### ⚙️ Miscellaneous Tasks

- *(*)* Update `noq` and `net-tools` dependencies ([#4487](https://github.com/n0-computer/iroh/issues/4487)) - ([1960e73](https://github.com/n0-computer/iroh/commit/1960e73f1494eb53a730f2dc408f91e599f620e7))

## [1.0.3](https://github.com/n0-computer/iroh/compare/v1.0.2..1.0.3) - 2026-07-20

### 🐛 Bug Fixes

- Remove vergen use from build.rs files ([#4426](https://github.com/n0-computer/iroh/issues/4426)) - ([1795b93](https://github.com/n0-computer/iroh/commit/1795b9363c68820661fd06cf679d94561ec66c0c))

### 📚 Documentation

- *(iroh-relay)* System deps and build command ([#4385](https://github.com/n0-computer/iroh/issues/4385)) - ([403af3c](https://github.com/n0-computer/iroh/commit/403af3c9ed8eeda07f72a4ac4617d67ca053ccb7))

### ⚙️ Miscellaneous Tasks

- Fixes for clippy from rust 1.97 ([#4404](https://github.com/n0-computer/iroh/issues/4404)) - ([8b097b2](https://github.com/n0-computer/iroh/commit/8b097b24880581bc0bd348ac9965fa05e84428c9))
- Bump cfg_aliases ([#4422](https://github.com/n0-computer/iroh/issues/4422)) - ([4e0a820](https://github.com/n0-computer/iroh/commit/4e0a820d07f9edd7f32caf352dbf82c0a17d4c42))
- Update to `noq` 1.1.0 - ([e84fe96](https://github.com/n0-computer/iroh/commit/e84fe96ddeb75ef5e408f06c14edde513f2b6be8))

## [1.0.2](https://github.com/n0-computer/iroh/compare/v1.0.1..1.0.2) - 2026-07-06

### ⛰️  Features

- *(relay)* Allow updating the per-client rate limit live ([#4381](https://github.com/n0-computer/iroh/issues/4381)) - ([c23446c](https://github.com/n0-computer/iroh/commit/c23446ce2ee2bf3a25121483c61d938645c2bcd0))

### 🐛 Bug Fixes

- *(iroh-relay)* Improve relay protocol proptests & properly handle invalid messages ([#4389](https://github.com/n0-computer/iroh/issues/4389)) - ([22cac74](https://github.com/n0-computer/iroh/commit/22cac742ca5e84da4542681e14b2d23b74c8330e))

### ⚙️ Miscellaneous Tasks

- *(*)* Add release configuration for generating the changelog - ([ead46e5](https://github.com/n0-computer/iroh/commit/ead46e50823e7ddcc4d142ea71511ed38a37260e))


