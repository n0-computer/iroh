# Changelog

All notable changes to iroh will be documented in this file.

## [0.13.0](https://github.com/n0-computer/iroh/compare/v0.12.0..0.13.0) - 2024-03-25

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
- *(iroh)* Only use flat db when enabled  - ([5bc9c04](https://github.com/n0-computer/iroh/commit/5bc9c0472a6d55c3cae450ca7bc9a270a72c20aa))
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
- Add MagicEndpoint to iroh-net  - ([4597cb3](https://github.com/n0-computer/iroh/commit/4597cb36e0be5ffcb5ae21a42e4a37648d455aad))
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
- *(iroh)* Pass derp-map on get-options  - ([b7fd889](https://github.com/n0-computer/iroh/commit/b7fd889e7806feeb941c0f611bbb3aa33a718b40))
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

- *(derp)* Fix test  - ([10782be](https://github.com/n0-computer/iroh/commit/10782befb3512a874215a8f43d1f221737f231b8))
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


