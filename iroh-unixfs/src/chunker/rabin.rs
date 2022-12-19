//! Implements a rabin based chunker, following the implementation from [here](https://github.com/ipfs-shipyard/DAGger/blob/master/internal/dagger/chunker/rabin/impl.go).

use std::io;

use bytes::{Bytes, BytesMut};
use futures::{stream::BoxStream, StreamExt};
use tokio::io::{AsyncRead, AsyncReadExt};

/// Rabin fingerprinting based chunker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rabin {
    init_state: u64,
    mask: u64,
    mins_sans_preheat: usize,
    preset: Preset,
    config: Config,
}

pub const GO_IPFS_V0_PRESET: Preset = Presets::GoIpfsV0.into_preset();

impl Default for Rabin {
    fn default() -> Self {
        Rabin::new(Config::default(), GO_IPFS_V0_PRESET)
    }
}

impl Rabin {
    pub fn new(config: Config, preset: Preset) -> Self {
        assert!(
            config.min_size < config.max_size,
            "Invalid config, max_size must be larger than min_size"
        );

        // Due to out_table[0] always being 0, this is simply the value 1
        // but derive it longform nevertheless
        let init_state = (preset.out_table[0].wrapping_shl(8) | 1)
            ^ (preset.mod_table[(preset.out_table[0] >> preset.deg_shift) as usize]);
        debug_assert_eq!(init_state, 1);

        Rabin {
            init_state,
            mins_sans_preheat: config.min_size - preset.window_size,
            mask: 1 << (config.mask_bits - 1),
            preset,
            config,
        }
    }

    pub fn chunks<'a, R: AsyncRead + Unpin + Send + 'a>(
        self,
        mut source: R,
    ) -> BoxStream<'a, io::Result<Bytes>> {
        async_stream::stream! {
            let target_size = 3 * self.config.max_size;
            let mut buf = BytesMut::with_capacity(target_size);
            let mut use_entire_buffer = false;
            let preset = &self.preset;

            while !use_entire_buffer {
                // Fill buffer
                let mut total_read = 0;
                while buf.len() < target_size {
                    let read = source.read_buf(&mut buf).await?;
                    total_read += read;
                    if read == 0 {
                        break;
                    }
                }

                // abort early if we have not received enough data
                if buf.len() < self.config.min_size {
                    if !buf.is_empty() {
                        yield Ok(buf.freeze());
                    }
                    break;
                }

                let post_buf_idx = buf.len();

                // read 0 bytes => the source is exhausted
                use_entire_buffer = total_read == 0;

                let mut cur_idx = 0;

                loop {
                    let last_idx = cur_idx;
                    let mut next_round_max = last_idx + self.config.max_size;

                    // we will be running out of data, but still *could* run a round
                    if next_round_max > post_buf_idx {
                        // abort early if we are allowed to
                        if !use_entire_buffer {
                            break;
                        }
                        // signify where we stop hard
                        next_round_max = post_buf_idx;
                    }

                    // in this case we will *NOT* be able to run another round at all
                    if cur_idx + self.config.min_size >= post_buf_idx {
                        if use_entire_buffer && post_buf_idx != cur_idx {
                            let chunk = buf.clone().freeze().slice(cur_idx..post_buf_idx);
                            yield Ok(chunk);
                        }
                        break;
                    }

                    // reset
                    let mut state = self.init_state;

                    // preheat
                    cur_idx += self.mins_sans_preheat;
                    for i in 1..=preset.window_size {
                        if i == preset.window_size {
                            state ^= preset.out_table[1];
                        } else {
                            state ^= preset.out_table[0];
                        }
                        let table_point = preset.mod_table[(state >> preset.deg_shift) as usize];
                        state = (state.wrapping_shl(8) | buf[cur_idx] as u64) ^ table_point;
                        cur_idx += 1;
                    }

                    // cycle
                    while cur_idx < next_round_max
                        && ((state & self.mask) != self.config.target_value)
                    {
                        state ^= preset.out_table[
                            buf[cur_idx - preset.window_size] as usize
                        ];
                        let table_point = preset.mod_table[(state >> preset.deg_shift) as usize];
                        state = (state.wrapping_shl(8) | (buf[cur_idx] as u64)) ^ table_point;
                        cur_idx += 1;
                    }

                    // always a find at this point, we bailed on short buffers earlier
                    let chunk = buf.clone().freeze().slice(last_idx..cur_idx);
                    yield Ok(chunk);
                }

                // remove processed data
                let _ = buf.split_to(cur_idx);
            }
        }
        .boxed()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preset {
    out_table: [u64; 256],
    mod_table: [u64; 256],
    window_size: usize,
    deg_shift: usize,
    polynomial: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// State value denoting a chunk boundary.
    pub target_value: u64,
    /// Amount of bits of state to compare to target on every iteration. For a random input the average chunk size is about `2**m`.
    pub mask_bits: usize,
    /// Maximum data chunk size.
    pub max_size: usize,
    /// Minimum data chunk size.
    pub min_size: usize,
}

impl Default for Config {
    fn default() -> Self {
        // The default used by IPFS.
        Config {
            target_value: 0,
            mask_bits: 18,
            max_size: 393_216, // (2**18)+(2**18)/2
            min_size: 87_381,  // (2**18)/3
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub enum Presets {
    GoIpfsV0,
}

impl Presets {
    pub const fn into_preset(self) -> Preset {
        Preset {
            polynomial: 0x3df305dfb2a805,
            window_size: 16,
            deg_shift: 45,
            out_table: [
                0x0,
                0x17fa63217c2ad7,
                0x1207c39d4afdab,
                0x5fda0bc36d77c,
                0x19fc82e5275353,
                0xe06e1c45b7984,
                0xbfb41786daef8,
                0x1c01225911842f,
                0xe0a0015fc0ea3,
                0x19f06334802474,
                0x1c0dc388b6f308,
                0xbf7a0a9cad9df,
                0x17f682f0db5df0,
                0xce1d1a77727,
                0x5f1416d91a05b,
                0x120b224ced8a8c,
                0x1c14002bf81d46,
                0xbee630a843791,
                0xe13c3b6b2e0ed,
                0x19e9a097ceca3a,
                0x5e882cedf4e15,
                0x1212e1efa364c2,
                0x17ef415395b3be,
                0x152272e99969,
                0x121e003e0413e5,
                0x5e4631f783932,
                0x19c3a34eee4e,
                0x17e3a08232c499,
                0xbe282db2340b6,
                0x1c18e1fa5f6a61,
                0x19e5414669bd1d,
                0xe1f22671597ca,
                0x5db0588429289,
                0x122166a93eb85e,
                0x17dcc615086f22,
                0x26a5347445f5,
                0x1c27876d65c1da,
                0xbdde44c19eb0d,
                0xe2044f02f3c71,
                0x19da27d15316a6,
                0xbd1059dbe9c2a,
                0x1c2b66bcc2b6fd,
                0x19d6c600f46181,
                0xe2ca521884b56,
                0x122d877899cf79,
                0x5d7e459e5e5ae,
                0x2a44e5d332d2,
                0x17d027c4af1805,
                0x19cf05a3ba8fcf,
                0xe356682c6a518,
                0xbc8c63ef07264,
                0x1c32a51f8c58b3,
                0x3387469ddc9c,
                0x17c9e467e1f64b,
                0x123444dbd72137,
                0x5ce27faab0be0,
                0x17c505b646816c,
                0x3f66973aabbb,
                0x5c2c62b0c7cc7,
                0x1238a50a705610,
                0xe39875361d23f,
                0x19c3e4721df8e8,
                0x1c3e44ce2b2f94,
                0xbc427ef570543,
                0xbb60b10852512,
                0x1c4c6831f90fc5,
                0x19b1c88dcfd8b9,
                0xe4babacb3f26e,
                0x124a89f5a27641,
                0x5b0ead4de5c96,
                0x4d4a68e88bea,
                0x17b7294994a13d,
                0x5bc0b05792bb1,
                0x12466824050166,
                0x17bbc89833d61a,
                0x41abb94ffccd,
                0x1c4089e05e78e2,
                0xbbaeac1225235,
                0xe474a7d148549,
                0x19bd295c68af9e,
                0x17a20b3b7d3854,
                0x58681a011283,
                0x5a5c8a637c5ff,
                0x125fab874bef28,
                0xe5e89de5a6b07,
                0x19a4eaff2641d0,
                0x1c594a431096ac,
                0xba329626cbc7b,
                0x19a80b2e8136f7,
                0xe52680ffd1c20,
                0xbafc8b3cbcb5c,
                0x1c55ab92b7e18b,
                0x5489cba665a4,
                0x17aeeaeada4f73,
                0x12534a56ec980f,
                0x5a9297790b2d8,
                0xe6d0e98c7b79b,
                0x19976db9bb9d4c,
                0x1c6acd058d4a30,
                0xb90ae24f160e7,
                0x17918c7de0e4c8,
                0x6bef5c9cce1f,
                0x5964fe0aa1963,
                0x126c2cc1d633b4,
                0x670e8d3bb938,
                0x179d6dac4793ef,
                0x1260cd10714493,
                0x59aae310d6e44,
                0x199b8c681cea6b,
                0xe61ef4960c0bc,
                0xb9c4ff55617c0,
                0x1c662cd42a3d17,
                0x12790eb33faadd,
                0x5836d9243800a,
                0x7ecd2e755776,
                0x1784ae0f097da1,
                0xb858c5618f98e,
                0x1c7fef7764d359,
                0x19824fcb520425,
                0xe782cea2e2ef2,
                0x1c730ea6c3a47e,
                0xb896d87bf8ea9,
                0xe74cd3b8959d5,
                0x198eae1af57302,
                0x58f8c43e4f72d,
                0x1275ef6298ddfa,
                0x17884fdeae0a86,
                0x722cffd22051,
                0x176c16210a4a24,
                0x9675007660f3,
                0x56bd5bc40b78f,
                0x1291b69d3c9d58,
                0xe9094c42d1977,
                0x196af7e55133a0,
                0x1c97575967e4dc,
                0xb6d34781bce0b,
                0x19661634f64487,
                0xe9c75158a6e50,
                0xb61d5a9bcb92c,
                0x1c9bb688c093fb,
                0x9a94d1d117d4,
                0x1760f7f0ad3d03,
                0x129d574c9bea7f,
                0x567346de7c0a8,
                0xb78160af25762,
                0x1c82752b8e7db5,
                0x197fd597b8aac9,
                0xe85b6b6c4801e,
                0x128494efd50431,
                0x57ef7cea92ee6,
                0x8357729ff99a,
                0x17793453e3d34d,
                0x572161f0e59c1,
                0x1288753e727316,
                0x1775d58244a46a,
                0x8fb6a3388ebd,
                0x1c8e94fa290a92,
                0xb74f7db552045,
                0xe89576763f739,
                0x197334461fddee,
                0x12b713a948d8ad,
                0x54d708834f27a,
                0xb0d034022506,
                0x174ab3157e0fd1,
                0xb4b914c6f8bfe,
                0x1cb1f26d13a129,
                0x194c52d1257655,
                0xeb631f0595c82,
                0x1cbd13bcb4d60e,
                0xb47709dc8fcd9,
                0xebad021fe2ba5,
                0x1940b300820172,
                0x541915993855d,
                0x12bbf278efaf8a,
                0x174652c4d978f6,
                0xbc31e5a55221,
                0xea31382b0c5eb,
                0x195970a3ccef3c,
                0x1ca4d01ffa3840,
                0xb5eb33e861297,
                0x175f91679796b8,
                0xa5f246ebbc6f,
                0x55852fadd6b13,
                0x12a231dba141c4,
                0xa913974ccb48,
                0x175370b630e19f,
                0x12aed00a0636e3,
                0x554b32b7a1c34,
                0x195591726b981b,
                0xeaff25317b2cc,
                0xb5252ef2165b0,
                0x1ca831ce5d4f67,
                0x1cda1d318f6f36,
                0xb207e10f345e1,
                0xedddeacc5929d,
                0x1927bd8db9b84a,
                0x5269fd4a83c65,
                0x12dcfcf5d416b2,
                0x17215c49e2c1ce,
                0xdb3f689eeb19,
                0x12d01d24736195,
                0x52a7e050f4b42,
                0xd7deb9399c3e,
                0x172dbd9845b6e9,
                0xb2c9fc15432c6,
                0x1cd6fce0281811,
                0x192b5c5c1ecf6d,
                0xed13f7d62e5ba,
                0xce1d1a777270,
                0x17347e3b0b58a7,
                0x12c9de873d8fdb,
                0x533bda641a50c,
                0x19329fff502123,
                0xec8fcde2c0bf4,
                0xb355c621adc88,
                0x1ccf3f4366f65f,
                0xec41d0f8b7cd3,
                0x193e7e2ef75604,
                0x1cc3de92c18178,
                0xb39bdb3bdabaf,
                0x17389feaac2f80,
                0xc2fccbd00557,
                0x53f5c77e6d22b,
                0x12c53f569af8fc,
                0x190118b9cdfdbf,
                0xefb7b98b1d768,
                0xb06db24870014,
                0x1cfcb805fb2ac3,
                0xfd9a5ceaaeec,
                0x1707f97d96843b,
                0x12fa59c1a05347,
                0x5003ae0dc7990,
                0x170b18ac31f31c,
                0xf17b8d4dd9cb,
                0x50cdb317b0eb7,
                0x12f6b810072460,
                0xef79a4916a04f,
                0x190df9686a8a98,
                0x1cf059d45c5de4,
                0xb0a3af5207733,
                0x515189235e0f9,
                0x12ef7bb349ca2e,
                0x1712db0f7f1d52,
                0xe8b82e033785,
                0x1ce99a7712b3aa,
                0xb13f9566e997d,
                0xeee59ea584e01,
                0x19143acb2464d6,
                0xb1f1887c9ee5a,
                0x1ce57ba6b5c48d,
                0x1918db1a8313f1,
                0xee2b83bff3926,
                0x12e39a62eebd09,
                0x519f9439297de,
                0xe459ffa440a2,
                0x171e3aded86a75,
            ],
            mod_table: [
                0x0,
                0x3df305dfb2a805,
                0x46150e60d7f80f,
                0x7be60bbf65500a,
                0x8c2a1cc1aff01e,
                0xb1d9191e1d581b,
                0xca3f12a1780811,
                0xf7cc177ecaa014,
                0x1185439835fe03c,
                0x125a73c5ced4839,
                0x15e4137e3881833,
                0x163b2323c3ab036,
                0x1947e2542f01022,
                0x1a98d209d42b827,
                0x1d26b2b2227e82d,
                0x1ef982efd954028,
                0x20d5b76d90d687d,
                0x230a87306bfc078,
                0x24b4e78b9da9072,
                0x276bd7d66683877,
                0x281716a18a29863,
                0x2bc826fc7103066,
                0x2c764647875606c,
                0x2fa9761a7c7c869,
                0x3150f4f5a528841,
                0x328fc4a85e02044,
                0x3531a413a85704e,
                0x36ee944e537d84b,
                0x39925539bfd785f,
                0x3a4d656444fd05a,
                0x3df305dfb2a8050,
                0x3e2c35824982855,
                0x41ab6edb21ad0fa,
                0x42745e86da878ff,
                0x45ca3e3d2cd28f5,
                0x46150e60d7f80f0,
                0x4969cf173b520e4,
                0x4ab6ff4ac0788e1,
                0x4d089ff1362d8eb,
                0x4ed7afaccd070ee,
                0x502e2d4314530c6,
                0x53f11d1eef798c3,
                0x544f7da5192c8c9,
                0x57904df8e2060cc,
                0x58ec8c8f0eac0d8,
                0x5b33bcd2f5868dd,
                0x5c8ddc6903d38d7,
                0x5f52ec34f8f90d2,
                0x617ed9b6b17b887,
                0x62a1e9eb4a51082,
                0x651f8950bc04088,
                0x66c0b90d472e88d,
                0x69bc787aab84899,
                0x6a63482750ae09c,
                0x6ddd289ca6fb096,
                0x6e0218c15dd1893,
                0x70fb9a2e84858bb,
                0x7324aa737faf0be,
                0x749acac889fa0b4,
                0x7745fa9572d08b1,
                0x78393be29e7a8a5,
                0x7be60bbf65500a0,
                0x7c586b0493050aa,
                0x7f875b59682f8af,
                0x8089edebb8709f1,
                0x8356ddb6435a1f4,
                0x84e8bd0db50f1fe,
                0x87378d504e259fb,
                0x884b4c27a28f9ef,
                0x8b947c7a59a51ea,
                0x8c2a1cc1aff01e0,
                0x8ff52c9c54da9e5,
                0x910cae738d8e9cd,
                0x92d39e2e76a41c8,
                0x956dfe9580f11c2,
                0x96b2cec87bdb9c7,
                0x99ce0fbf97719d3,
                0x9a113fe26c5b1d6,
                0x9daf5f599a0e1dc,
                0x9e706f0461249d9,
                0xa05c5a8628a618c,
                0xa3836adbd38c989,
                0xa43d0a6025d9983,
                0xa7e23a3ddef3186,
                0xa89efb4a3259192,
                0xab41cb17c973997,
                0xacffabac3f2699d,
                0xaf209bf1c40c198,
                0xb1d9191e1d581b0,
                0xb2062943e6729b5,
                0xb5b849f810279bf,
                0xb66779a5eb0d1ba,
                0xb91bb8d207a71ae,
                0xbac4888ffc8d9ab,
                0xbd7ae8340ad89a1,
                0xbea5d869f1f21a4,
                0xc122833099dd90b,
                0xc2fdb36d62f710e,
                0xc543d3d694a2104,
                0xc69ce38b6f88901,
                0xc9e022fc8322915,
                0xca3f12a17808110,
                0xcd81721a8e5d11a,
                0xce5e4247757791f,
                0xd0a7c0a8ac23937,
                0xd378f0f55709132,
                0xd4c6904ea15c138,
                0xd719a0135a7693d,
                0xd8656164b6dc929,
                0xdbba51394df612c,
                0xdc043182bba3126,
                0xdfdb01df4089923,
                0xe1f7345d090b176,
                0xe2280400f221973,
                0xe59664bb0474979,
                0xe64954e6ff5e17c,
                0xe935959113f4168,
                0xeaeaa5cce8de96d,
                0xed54c5771e8b967,
                0xee8bf52ae5a1162,
                0xf07277c53cf514a,
                0xf3ad4798c7df94f,
                0xf4132723318a945,
                0xf7cc177ecaa0140,
                0xf8b0d609260a154,
                0xfb6fe654dd20951,
                0xfcd186ef2b7595b,
                0xff0eb6b2d05f15e,
                0x10113dbd770e13e2,
                0x102cceb8a8bcbbe7,
                0x105728b317d9ebed,
                0x106adbb6c86b43e8,
                0x109d17a1b6a1e3fc,
                0x10a0e4a469134bf9,
                0x10db02afd6761bf3,
                0x10e6f1aa09c4b3f6,
                0x11096984f451f3de,
                0x11349a812be35bdb,
                0x114f7c8a94860bd1,
                0x11728f8f4b34a3d4,
                0x1185439835fe03c0,
                0x11b8b09dea4cabc5,
                0x11c356965529fbcf,
                0x11fea5938a9b53ca,
                0x121c66cbae037b9f,
                0x122195ce71b1d39a,
                0x125a73c5ced48390,
                0x126780c011662b95,
                0x12904cd76fac8b81,
                0x12adbfd2b01e2384,
                0x12d659d90f7b738e,
                0x12ebaadcd0c9db8b,
                0x130432f22d5c9ba3,
                0x1339c1f7f2ee33a6,
                0x134227fc4d8b63ac,
                0x137fd4f99239cba9,
                0x138818eeecf36bbd,
                0x13b5ebeb3341c3b8,
                0x13ce0de08c2493b2,
                0x13f3fee553963bb7,
                0x140b8b50c514c318,
                0x143678551aa66b1d,
                0x144d9e5ea5c33b17,
                0x14706d5b7a719312,
                0x1487a14c04bb3306,
                0x14ba5249db099b03,
                0x14c1b442646ccb09,
                0x14fc4747bbde630c,
                0x1513df69464b2324,
                0x152e2c6c99f98b21,
                0x1555ca67269cdb2b,
                0x15683962f92e732e,
                0x159ff57587e4d33a,
                0x15a2067058567b3f,
                0x15d9e07be7332b35,
                0x15e4137e38818330,
                0x1606d0261c19ab65,
                0x163b2323c3ab0360,
                0x1640c5287cce536a,
                0x167d362da37cfb6f,
                0x168afa3addb65b7b,
                0x16b7093f0204f37e,
                0x16ccef34bd61a374,
                0x16f11c3162d30b71,
                0x171e841f9f464b59,
                0x1723771a40f4e35c,
                0x17589111ff91b356,
                0x1765621420231b53,
                0x1792ae035ee9bb47,
                0x17af5d06815b1342,
                0x17d4bb0d3e3e4348,
                0x17e94808e18ceb4d,
                0x1819a363cc891a13,
                0x18245066133bb216,
                0x185fb66dac5ee21c,
                0x1862456873ec4a19,
                0x1895897f0d26ea0d,
                0x18a87a7ad2944208,
                0x18d39c716df11202,
                0x18ee6f74b243ba07,
                0x1901f75a4fd6fa2f,
                0x193c045f9064522a,
                0x1947e2542f010220,
                0x197a1151f0b3aa25,
                0x198ddd468e790a31,
                0x19b02e4351cba234,
                0x19cbc848eeaef23e,
                0x19f63b4d311c5a3b,
                0x1a14f8151584726e,
                0x1a290b10ca36da6b,
                0x1a52ed1b75538a61,
                0x1a6f1e1eaae12264,
                0x1a98d209d42b8270,
                0x1aa5210c0b992a75,
                0x1adec707b4fc7a7f,
                0x1ae334026b4ed27a,
                0x1b0cac2c96db9252,
                0x1b315f2949693a57,
                0x1b4ab922f60c6a5d,
                0x1b774a2729bec258,
                0x1b8086305774624c,
                0x1bbd753588c6ca49,
                0x1bc6933e37a39a43,
                0x1bfb603be8113246,
                0x1c03158e7e93cae9,
                0x1c3ee68ba12162ec,
                0x1c4500801e4432e6,
                0x1c78f385c1f69ae3,
                0x1c8f3f92bf3c3af7,
                0x1cb2cc97608e92f2,
                0x1cc92a9cdfebc2f8,
                0x1cf4d99900596afd,
                0x1d1b41b7fdcc2ad5,
                0x1d26b2b2227e82d0,
                0x1d5d54b99d1bd2da,
                0x1d60a7bc42a97adf,
                0x1d976bab3c63dacb,
                0x1daa98aee3d172ce,
                0x1dd17ea55cb422c4,
                0x1dec8da083068ac1,
                0x1e0e4ef8a79ea294,
                0x1e33bdfd782c0a91,
                0x1e485bf6c7495a9b,
                0x1e75a8f318fbf29e,
                0x1e8264e46631528a,
                0x1ebf97e1b983fa8f,
                0x1ec471ea06e6aa85,
                0x1ef982efd9540280,
                0x1f161ac124c142a8,
                0x1f2be9c4fb73eaad,
                0x1f500fcf4416baa7,
                0x1f6dfcca9ba412a2,
                0x1f9a30dde56eb2b6,
                0x1fa7c3d83adc1ab3,
                0x1fdc25d385b94ab9,
                0x1fe1d6d65a0be2bc,
            ],
        }
    }
}

#[cfg(test)]
mod bootstrap {
    const DEG_TARGET: usize = 53; // Largest prime smaller than (64 - 8)

    // const DEG_SHIFT: usize = DEG_TARGET - 8;

    pub fn generate_lookup_tables(pol: u64, w_size: usize) -> ([u64; 256], [u64; 256]) {
        // Calculate table for sliding out bytes. The byte to slide out is used as
        // the index for the table, the value contains the following:
        // out_table[b] = Hash(b || 0 ||        ...        || 0)
        //                          \ windowsize-1 zero bytes /
        // To slide out byte b_0 for window size w with known hash
        // H := H(b_0 || ... || b_w), it is sufficient to add out_table[b_0]:
        //    H(b_0 || ... || b_w) + H(b_0 || 0 || ... || 0)
        //  = H(b_0 + b_0 || b_1 + 0 || ... || b_w + 0)
        //  = H(    0     || b_1 || ...     || b_w)
        //
        // Afterwards a new byte can be shifted in.
        let mut out_table = [0; 256];
        let mut mod_table = [0; 256];

        for b in 0u64..256 {
            let mut h = modulus(b, pol);
            for _ in 0..w_size - 1 {
                h = modulus(h << 8, pol);
            }
            out_table[b as usize] = h;
        }

        // Calculate table for reduction mod Polynomial
        // mod_table[b] = A | B, where A = (b(x) * x^k mod pol) and  B = b(x) * x^k
        //
        // The 8 bits above deg(Polynomial) determine what happens next and so
        // these bits are used as a lookup to this table. The value is split in
        // two parts: Part A contains the result of the modulus operation, part
        // B is used to cancel out the 8 top bits so that one XOR operation is
        // enough to reduce modulo Polynomial
        for b in 0u64..256 {
            mod_table[b as usize] = modulus(b << DEG_TARGET, pol) | b << DEG_TARGET;
        }

        (out_table, mod_table)
    }

    /// The degree of the polynomial.
    const fn deg(pol: u64) -> i64 {
        64 - (pol.leading_zeros() as i64) - 1
    }

    /// Modulus result of numerator%denominator.
    /// see https://en.wikipedia.org/wiki/Division_algorithm
    fn modulus(mut numerator: u64, denominator: u64) -> u64 {
        assert_ne!(denominator, 0, "division by zero");
        if numerator == 0 {
            return 0;
        }

        let denom_deg = deg(denominator);

        let mut deg_diff = deg(numerator) - denom_deg;
        while deg_diff >= 0 {
            numerator ^= denominator << usize::try_from(deg_diff).unwrap();
            deg_diff = deg(numerator) - denom_deg;
        }

        numerator
    }
}

#[cfg(test)]
mod tests {
    use futures::TryStreamExt;
    use proptest::prelude::*;
    use rand::{rngs::StdRng, SeedableRng};

    use super::*;

    #[tokio::test]
    async fn test_simple_chunks() {
        let chunker = Rabin::new(Config::default(), GO_IPFS_V0_PRESET);

        println!("1 chunk");
        let data: Vec<u8> = (0..1024u32).flat_map(|i| i.to_le_bytes()).collect();
        let bytes = std::io::Cursor::new(&data);
        let split = chunker.clone().chunks(bytes);
        let result: Vec<_> = split.try_collect().await.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], &data);

        println!(">= 4 chunks");
        let data: Vec<u8> = (0..393_216u32).flat_map(|i| i.to_le_bytes()).collect();
        test_rabin_roundtrip_data(data).await;
    }

    #[tokio::test]
    async fn test_more_chunks() {
        let seed = 1;
        let mut rng = StdRng::seed_from_u64(seed);
        for size in [
            0,
            100,
            1024,
            1024 * 512,
            1024 * 1024,
            1024 * 1024 * 5,
            1024 * 1024 * 100,
        ] {
            println!("size {size}");
            let mut data = vec![0u8; size];
            rng.fill_bytes(&mut data);
            test_rabin_roundtrip_data(data).await;
            println!("----");
        }
    }

    async fn test_rabin_roundtrip_data(data: Vec<u8>) {
        let config = Config::default();
        let chunker = Rabin::new(config.clone(), GO_IPFS_V0_PRESET);

        let mut rng = StdRng::seed_from_u64(0);
        // split into randomized chunks
        let mut chunks: Vec<Vec<u8>> = Vec::new();
        let mut index = 0;
        while index < data.len() {
            let split = rng.gen_range(index..=data.len());
            if split != index {
                let chunk = data[index..split].to_vec();
                index = split;
                chunks.push(chunk);
            }
        }
        println!(
            "chunks: {:?}",
            chunks.iter().map(|c| c.len()).collect::<Vec<_>>()
        );
        let stream = futures::stream::iter(chunks.iter().map(|s| io::Result::Ok(&s[..])));
        let reader = tokio_util::io::StreamReader::new(stream);
        let split = chunker.chunks(reader);
        let chunks = split.try_collect::<Vec<_>>().await.unwrap();

        if data.is_empty() {
            assert!(chunks.is_empty());
        } else if data.len() < config.min_size {
            assert_eq!(chunks.len(), 1);
        }

        assert_eq!(chunks.iter().map(|v| v.len()).sum::<usize>(), data.len());
        let mut together = Vec::with_capacity(data.len());
        for (i, chunk) in chunks.iter().enumerate() {
            assert!(chunk.len() <= config.max_size);
            if data.len() >= config.min_size && i < chunks.len() - 1 {
                assert!(chunk.len() >= config.min_size)
            }
            together.extend_from_slice(chunk);
        }

        assert_eq!(data, together);
    }

    fn arb_random_slice(max: usize) -> impl Strategy<Value = Vec<u8>> {
        (0usize..max, any::<u64>()).prop_map(|(len, seed)| {
            let mut rng = StdRng::seed_from_u64(seed);
            let mut data = vec![0u8; len];
            rng.fill_bytes(&mut data);
            data
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            fork: true,
            .. ProptestConfig::default()
        })]

        #[ignore]
        #[test]
        fn test_rabin_roundtrip_small(data in arb_random_slice(1024 * 1024 * 2)) {
            let rt = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap();
            rt.block_on(async move { test_rabin_roundtrip_data(data).await });
        }

        #[ignore]
        #[test]
        fn test_rabin_roundtrip_large(data in arb_random_slice(1024 * 1024 * 20)) {
            let rt = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap();
            rt.block_on(async move { test_rabin_roundtrip_data(data).await });
        }
    }

    #[test]
    fn test_go_preset() {
        let preset = GO_IPFS_V0_PRESET;

        let (out_table, mod_table) =
            bootstrap::generate_lookup_tables(preset.polynomial, preset.window_size);
        assert_eq!(out_table, preset.out_table);
        assert_eq!(mod_table, preset.mod_table);
    }
}
