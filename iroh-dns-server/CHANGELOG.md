# Changelog

All notable changes to iroh-dns-server will be documented in this file.

<!-- git-cliff: end of header -->
## [1.4.1](https://github.com/n0-computer/iroh/compare/v1.4.0..1.4.1) - 2026-10-21

### ⚙️ Miscellaneous Tasks

- Fix changelog ([#4628](https://github.com/n0-computer/iroh/issues/4628)) - ([efcb1c3](https://github.com/n0-computer/iroh/commit/efcb1c3f987127529458f2734a076acacf0254e3))



## [1.4.0](https://github.com/n0-computer/iroh/compare/v1.3.0..1.4.0) - 2026-10-20

### 🐛 Bug Fixes

- *(dns-server)* Stop leaky idle connections ([#4620](https://github.com/n0-computer/iroh/issues/4620)) - ([be65184](https://github.com/n0-computer/iroh/commit/be6518477e399dd8aa995cddc393759f8c0a0c94))
- *(iroh)* Reduce cache startup memory ([#4574](https://github.com/n0-computer/iroh/issues/4574)) - ([dce5173](https://github.com/n0-computer/iroh/commit/dce5173bc43c70441249a784012dbe7a1f5b3afe))
- Increase listen backlog on dns server ([#4619](https://github.com/n0-computer/iroh/issues/4619)) - ([97941d6](https://github.com/n0-computer/iroh/commit/97941d63002d56e35a8e7a892ea5d11c72056651))

### 🚜 Refactor

- *(iroh-dns-server)* Update clap usage to modern v4 APIs ([#4567](https://github.com/n0-computer/iroh/issues/4567)) - ([12cd62b](https://github.com/n0-computer/iroh/commit/12cd62b5d1d689d4595b3770ca14bf58c44d3fc3))

## [1.3.0](https://github.com/n0-computer/iroh/compare/v1.2.0..1.3.0) - 2026-09-28

### ⛰️  Features

- *(metrics)* Lookup/resolver stats ([#4543](https://github.com/n0-computer/iroh/issues/4543)) - ([b29c0a4](https://github.com/n0-computer/iroh/commit/b29c0a424c7bae7831ba1cb7e4a94e08ba04cfd5))

## [1.2.0](https://github.com/n0-computer/iroh/compare/v1.1.0..1.2.0) - 2026-09-09

### ⛰️  Features

- *(iroh-dns)* Deprecate old nameserver builders ([#4506](https://github.com/n0-computer/iroh/issues/4506)) - ([2b4de03](https://github.com/n0-computer/iroh/commit/2b4de030ce5e0133f272871a76f0c685c63f552a))
- Switch to n0-dns-resolver and make fallback nameservers configurable ([#4419](https://github.com/n0-computer/iroh/issues/4419)) - ([1a68838](https://github.com/n0-computer/iroh/commit/1a68838b34c6c4646ada9fafaf65b29f9577a446))

## [1.1.0](https://github.com/n0-computer/iroh/compare/v1.0.3..1.1.0) - 2026-08-25

### 🐛 Bug Fixes

- *(iroh-dns-server)* Enable TCP keepalive on HTTP listeners ([#4462](https://github.com/n0-computer/iroh/issues/4462)) - ([735958f](https://github.com/n0-computer/iroh/commit/735958f81e9aa5868a2118db6195b33179e33cd0))
- Bind iroh-dns-server to both IPv4 and IPv6 ([#4432](https://github.com/n0-computer/iroh/issues/4432)) - ([bbc82b6](https://github.com/n0-computer/iroh/commit/bbc82b65545b3bbdf0afb9282d5a01aeb89f264b))

### 🧪 Testing

- *(iroh)* Update patchbay to 0.7.0 ([#4445](https://github.com/n0-computer/iroh/issues/4445)) - ([7d8c9bf](https://github.com/n0-computer/iroh/commit/7d8c9bf05d3f77dd0ef85f5f2f028f4fd0e72f55))

### ⚙️ Miscellaneous Tasks

- *(iroh-dns-server)* Replace `mainline` with `n0-mainline` and update `lru` ([#4470](https://github.com/n0-computer/iroh/issues/4470)) - ([82eed32](https://github.com/n0-computer/iroh/commit/82eed32993f09cf3af66b82b80e12d41350d2119))

## [1.0.3](https://github.com/n0-computer/iroh/compare/v1.0.2..1.0.3) - 2026-07-20

### 🐛 Bug Fixes

- Remove vergen use from build.rs files ([#4426](https://github.com/n0-computer/iroh/issues/4426)) - ([1795b93](https://github.com/n0-computer/iroh/commit/1795b9363c68820661fd06cf679d94561ec66c0c))

### ⚙️ Miscellaneous Tasks

- Fixes for clippy from rust 1.97 ([#4404](https://github.com/n0-computer/iroh/issues/4404)) - ([8b097b2](https://github.com/n0-computer/iroh/commit/8b097b24880581bc0bd348ac9965fa05e84428c9))
- Update semver checks for 1.0 stability ([#4401](https://github.com/n0-computer/iroh/issues/4401)) - ([5817271](https://github.com/n0-computer/iroh/commit/5817271c4a5fedc3e8387ec788ed42d68ba22064))

## [1.0.2](https://github.com/n0-computer/iroh/compare/v1.0.1..1.0.2) - 2026-07-06

### 🐛 Bug Fixes

- *(iroh-dns-server)* DNS write benchmark measurement ([#4382](https://github.com/n0-computer/iroh/issues/4382)) - ([9541a6d](https://github.com/n0-computer/iroh/commit/9541a6d1357fccc33123f0c4736a71493ef9aa3b))

### ⚙️ Miscellaneous Tasks

- *(*)* Add release configuration for generating the changelog - ([ead46e5](https://github.com/n0-computer/iroh/commit/ead46e50823e7ddcc4d142ea71511ed38a37260e))


