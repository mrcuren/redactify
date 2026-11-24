//! Cryptocurrency addresses (CRYPTO_ADDRESS): validators + rules.
//!
//! Bitcoin mainnet only (testnet coins carry no value; BIP173: "bc" for
//! mainnet, "tb" for testnet):
//! - base58check (P2PKH `1...`, P2SH `3...`): BIP13 "base58-encode:
//!   [one-byte version][20-byte hash][4-byte checksum]", "the 4-byte
//!   checksum is the first four bytes of the double SHA256 hash of the
//!   version and hash"; the mainnet version bytes are 0 (P2PKH) and 5
//!   (P2SH) and the alphabet is
//!   `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz` (Bitcoin
//!   Core `src/kernel/chainparams.cpp` `base58Prefixes`, `src/base58.cpp`
//!   `pszBase58`);
//! - segwit (`bc1...`): BIP173 (Bech32, the "bc" part, witness version
//!   0..16, a 2-to-40-byte program, at most 4 zero padding bits, v0
//!   programs of 20 or 32 bytes, no mixed case) and BIP350 (Bech32m with
//!   the constant 0x2bc830a3 for witness versions 1..16, Bech32 for v0).
//!
//! Ethereum: EIP-55 mixed-case checksum addresses only. A letter of the
//! 40 hex digits is uppercase exactly when the matching nibble of the
//! Keccak-256 hash of the lowercase hex is 8 or more. All-lowercase and
//! all-uppercase addresses carry no checksum (EIP-55) and are not claimed:
//! a checksum-less identifier needs a context cue, and no official cue
//! vocabulary exists for wallet addresses.
//!
//! Sources (retrieved 2026-10-31): bitcoin/bips at 5aadddb511a5
//! (bip-0013, bip-0173, bip-0350); bitcoin/bitcoin master
//! (`chainparams.cpp`, `base58.cpp`, `src/test/data/key_io_valid.json`,
//! `key_io_invalid.json`); ethereum/ERCs `ERCS/erc-55.md`. Keccak-256 is
//! the Keccak[r=1088, c=512] sponge of FIPS 202 without the SHA-3 domain
//! suffix; its permutation is checked against the Keccak team's
//! `ShortMsgKAT_SHA3-256.txt` (XKCP at 5585d0213203) and its padding
//! against the EIP-55 addresses (tests below).
//!
//! Every address checksum is strong enough to claim without a cue (score
//! 1.0): 32 bits (base58check), a BCH code (Bech32/Bech32m), about 15
//! bits on average (EIP-55, per its rationale).

use crate::guard::audit::sha256;
use crate::pii::entity::EntityType;
use crate::pii::locales::{rule, ContextPolicy, Rule};

/// The Bitcoin base58 alphabet (Bitcoin Core `pszBase58`).
const BASE58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// The Bech32 character set, value order (BIP173 table).
const BECH32: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// BIP173 `bech32_polymod` generator.
const BECH32_GEN: [u32; 5] = [
    0x3b6a_57b2,
    0x2650_8e6d,
    0x1ea1_19fa,
    0x3d42_33dd,
    0x2a14_62b3,
];

/// BIP350 `BECH32M_CONST`.
const BECH32M_CONST: u32 = 0x2bc8_30a3;

/// Returns `true` if `addr` is a valid Bitcoin MAINNET address: a
/// base58check P2PKH (`1...`) or P2SH (`3...`) address with a correct
/// double-SHA-256 checksum, or a segwit address (`bc1...`, Bech32 for
/// witness version 0, Bech32m for 1..16) that passes every BIP173 /
/// BIP350 decoding rule.
///
/// # Examples
/// ```
/// use redactify::valid_btc_address;
/// // Bitcoin Core key_io_valid.json mainnet vectors
/// assert!(valid_btc_address("1FsSia9rv4NeEwvJ2GvXrX7LyxYspbN2mo"));
/// assert!(valid_btc_address("bc1qvyq0cc6rahyvsazfdje0twl7ez82ndmuac2lhv"));
/// // one changed character, a testnet address
/// assert!(!valid_btc_address("1FsSia9rv4NeEwvJ2GvXrX7LyxYspbN2mp"));
/// assert!(!valid_btc_address("tb1qcrh3yqn4nlleplcez2yndq2ry8h9ncg3qh7n54"));
/// ```
#[must_use]
pub fn valid_btc_address(addr: &str) -> bool {
    valid_base58check(addr) || valid_segwit(addr)
}

/// A mainnet base58check address: 25 decoded bytes (version 0 or 5,
/// 20-byte hash, 4-byte checksum).
fn valid_base58check(addr: &str) -> bool {
    let Some(raw) = base58_decode(addr) else {
        return false;
    };
    if raw.len() != 25 || !matches!(raw[0], 0 | 5) {
        return false;
    }
    let check = sha256(&sha256(&raw[..21]));
    raw[21..] == check[..4]
}

/// Decodes a base58 string (each leading `1` is one leading zero byte);
/// `None` for a character outside the alphabet or an input longer than any
/// address (35 characters).
fn base58_decode(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() || s.len() > 35 {
        return None;
    }
    let zeros = s.bytes().take_while(|&b| b == b'1').count();
    // big-endian base-256 accumulator of the non-zero part
    let mut num: Vec<u8> = Vec::with_capacity(s.len());
    for b in s.bytes().skip(zeros) {
        let mut carry = BASE58.iter().position(|&c| c == b)? as u32;
        for byte in num.iter_mut().rev() {
            carry += u32::from(*byte) * 58;
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            num.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let mut out = vec![0u8; zeros];
    out.extend(num);
    Some(out)
}

/// A mainnet segwit address (BIP173 / BIP350 decoding rules).
fn valid_segwit(addr: &str) -> bool {
    // BIP173: at most 90 characters; no mixed case
    if addr.len() > 90
        || (addr.bytes().any(|b| b.is_ascii_lowercase())
            && addr.bytes().any(|b| b.is_ascii_uppercase()))
    {
        return false;
    }
    let lower = addr.to_ascii_lowercase();
    let Some((hrp, data)) = lower.rsplit_once('1') else {
        return false;
    };
    if hrp != "bc" || data.len() < 6 {
        return false;
    }
    let Some(values) = data
        .bytes()
        .map(|b| BECH32.iter().position(|&c| c == b).map(|v| v as u8))
        .collect::<Option<Vec<u8>>>()
    else {
        return false;
    };
    let polymod = bech32_polymod(hrp, &values);
    let (version, payload) = match values.split_first() {
        Some((&v, rest)) => (v, &rest[..rest.len().saturating_sub(6)]),
        None => return false,
    };
    if version > 16 {
        return false;
    }
    // BIP350: v0 uses Bech32 (constant 1), v1..v16 use Bech32m
    let expected = if version == 0 { 1 } else { BECH32M_CONST };
    if polymod != expected {
        return false;
    }
    let Some(program) = convert_5_to_8(payload) else {
        return false;
    };
    (2..=40).contains(&program.len()) && (version != 0 || matches!(program.len(), 20 | 32))
}

/// BIP173 `bech32_polymod(bech32_hrp_expand(hrp) + data)`.
fn bech32_polymod(hrp: &str, data: &[u8]) -> u32 {
    let expanded = hrp
        .bytes()
        .map(|b| b >> 5)
        .chain(std::iter::once(0))
        .chain(hrp.bytes().map(|b| b & 31))
        .chain(data.iter().copied());
    let mut chk: u32 = 1;
    for v in expanded {
        let top = chk >> 25;
        chk = ((chk & 0x1ff_ffff) << 5) ^ u32::from(v);
        for (i, g) in BECH32_GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

/// Regroups 5-bit values into bytes (BIP173 decoding: an incomplete group
/// at the end must be 4 bits or less and all zeroes, and is discarded).
fn convert_5_to_8(values: &[u8]) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut out = Vec::with_capacity(values.len() * 5 / 8);
    for &v in values {
        acc = (acc << 5) | u32::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    (bits <= 4 && (acc & ((1 << bits) - 1)) == 0).then_some(out)
}

/// Returns `true` if `addr` is an EIP-55 checksummed Ethereum address:
/// `0x` plus 40 hex digits with BOTH upper- and lowercase letters, each
/// letter uppercase exactly when the matching nibble of the Keccak-256
/// hash of the lowercase hex digits is 8 or more. All-lowercase and
/// all-uppercase addresses carry no checksum and return `false`.
///
/// # Examples
/// ```
/// use redactify::valid_eth_address;
/// // EIP-55 specification test addresses
/// assert!(valid_eth_address("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"));
/// assert!(valid_eth_address("0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"));
/// // a wrong case on one letter; no checksum in the lowercase form
/// assert!(!valid_eth_address("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD"));
/// assert!(!valid_eth_address("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"));
/// ```
#[must_use]
pub fn valid_eth_address(addr: &str) -> bool {
    let Some(hex) = addr.strip_prefix("0x") else {
        return false;
    };
    if hex.len() != 40 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    let mixed =
        hex.bytes().any(|b| b.is_ascii_uppercase()) && hex.bytes().any(|b| b.is_ascii_lowercase());
    if !mixed {
        return false;
    }
    let hash = keccak256(hex.to_ascii_lowercase().as_bytes());
    hex.bytes().enumerate().all(|(i, b)| {
        let nibble = if i % 2 == 0 {
            hash[i / 2] >> 4
        } else {
            hash[i / 2] & 0x0f
        };
        b.is_ascii_digit() || b.is_ascii_uppercase() == (nibble >= 8)
    })
}

/// Keccak-f[1600] round constants RC[0..24] (FIPS 202 section 3.2.5; the
/// tests re-derive them with algorithms 5 and 6).
const KECCAK_RC: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

/// The rho offsets along the pi walk (FIPS 202 sections 3.2.2 and 3.2.3:
/// step `t` rotates by `(t+1)(t+2)/2 mod 64`; re-derived by the tests).
const KECCAK_RHO: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

/// The lane index (`x + 5y`) visited at each step of the pi walk starting
/// from lane (1, 0) (FIPS 202 section 3.2.3; re-derived by the tests).
const KECCAK_PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

/// The Keccak-f[1600] permutation (24 rounds of theta, rho, pi, chi, iota).
fn keccak_f1600(st: &mut [u64; 25]) {
    for rc in KECCAK_RC {
        // theta
        let mut col = [0u64; 5];
        for (x, c) in col.iter_mut().enumerate() {
            *c = st[x] ^ st[x + 5] ^ st[x + 10] ^ st[x + 15] ^ st[x + 20];
        }
        for x in 0..5 {
            let d = col[(x + 4) % 5] ^ col[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                st[x + 5 * y] ^= d;
            }
        }
        // rho and pi
        let mut carried = st[1];
        for (&lane, &rot) in KECCAK_PI.iter().zip(&KECCAK_RHO) {
            let next = st[lane];
            st[lane] = carried.rotate_left(rot);
            carried = next;
        }
        // chi
        for y in 0..5 {
            let row = [
                st[5 * y],
                st[5 * y + 1],
                st[5 * y + 2],
                st[5 * y + 3],
                st[5 * y + 4],
            ];
            for x in 0..5 {
                st[x + 5 * y] = row[x] ^ (!row[(x + 1) % 5] & row[(x + 2) % 5]);
            }
        }
        // iota
        st[0] ^= rc;
    }
}

/// The 256-bit output of the Keccak[r=1088, c=512] sponge over `data`
/// with the domain byte `suffix` (0x01: the original Keccak padding used
/// by Ethereum; 0x06: SHA3-256 of FIPS 202) and the final `0x80` bit.
fn keccak_sponge_256(data: &[u8], suffix: u8) -> [u8; 32] {
    const RATE: usize = 136;
    let mut st = [0u64; 25];
    let absorb = |st: &mut [u64; 25], block: &[u8]| {
        for (lane, chunk) in st.iter_mut().zip(block.chunks_exact(8)) {
            *lane ^= u64::from_le_bytes(chunk.try_into().expect("8-byte chunk"));
        }
        keccak_f1600(st);
    };
    let mut blocks = data.chunks_exact(RATE);
    for block in &mut blocks {
        absorb(&mut st, block);
    }
    let rest = blocks.remainder();
    let mut last = [0u8; RATE];
    last[..rest.len()].copy_from_slice(rest);
    last[rest.len()] ^= suffix;
    last[RATE - 1] ^= 0x80;
    absorb(&mut st, &last);
    let mut out = [0u8; 32];
    for (dst, lane) in out.chunks_exact_mut(8).zip(&st) {
        dst.copy_from_slice(&lane.to_le_bytes());
    }
    out
}

/// Keccak-256 as Ethereum uses it (the original Keccak padding).
fn keccak256(data: &[u8]) -> [u8; 32] {
    keccak_sponge_256(data, 0x01)
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn base58_rule() -> Rule {
    rule!(
        id = "crypto::btc_base58",
        EntityType::CryptoAddress,
        r"(?<![0-9A-Za-z])[13][1-9A-HJ-NP-Za-km-z]{25,34}(?![0-9A-Za-z])",
        Some(valid_btc_address),
        ContextPolicy::None,
        1.0
    )
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn bech32_rule() -> Rule {
    // BIP173: the "bc" part, the separator `1`, 11..71 data characters
    // (segwit addresses are 14 to 74 characters long), one case
    rule!(
        id = "crypto::btc_bech32",
        EntityType::CryptoAddress,
        r"(?<![0-9A-Za-z])(?:bc1[02-9ac-hj-np-z]{11,71}|BC1[02-9AC-HJ-NP-Z]{11,71})(?![0-9A-Za-z])",
        Some(valid_btc_address),
        ContextPolicy::None,
        1.0
    )
}

#[allow(clippy::redundant_pub_crate)]
pub(crate) fn eth_rule() -> Rule {
    rule!(
        id = "crypto::eth",
        EntityType::CryptoAddress,
        r"(?<![0-9A-Za-z])0x[0-9a-fA-F]{40}(?![0-9A-Za-z])",
        Some(valid_eth_address),
        ContextPolicy::None,
        1.0
    )
}

#[cfg(test)]
mod tests {
    use super::{keccak256, keccak_sponge_256, KECCAK_PI, KECCAK_RC, KECCAK_RHO};

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    #[test]
    fn round_constants_follow_fips202_algorithms_5_and_6() {
        // Algorithm 5: rc(t) from the LFSR x^8 + x^6 + x^5 + x^4 + 1
        fn rc(t: usize) -> u64 {
            if t % 255 == 0 {
                return 1;
            }
            let mut r: u16 = 0b0000_0001; // bit 0 = R[0]
            for _ in 0..t % 255 {
                r <<= 1;
                let b8 = (r >> 8) & 1;
                r ^= b8 | (b8 << 4) | (b8 << 5) | (b8 << 6);
                r &= 0xff;
            }
            u64::from(r & 1)
        }
        // Algorithm 6: RC[2^j - 1] = rc(j + 7 i_r), j = 0..6
        for (ir, &want) in KECCAK_RC.iter().enumerate() {
            let derived = (0..7).fold(0u64, |acc, j| acc | (rc(j + 7 * ir) << ((1 << j) - 1)));
            assert_eq!(derived, want, "round {ir}");
        }
    }

    #[test]
    fn rho_offsets_and_pi_walk_follow_fips202() {
        // rho: step t rotates lane (x, y) by (t+1)(t+2)/2, then
        // (x, y) <- (y, (2x + 3y) mod 5); pi moves lane (x, y) to
        // (y, (2x + 3y) mod 5) as well, so the walk visits those lanes
        let (mut x, mut y) = (1usize, 0usize);
        for t in 0..24 {
            assert_eq!(
                KECCAK_RHO[t] as usize,
                ((t + 1) * (t + 2) / 2) % 64,
                "rho {t}"
            );
            let (nx, ny) = (y, (2 * x + 3 * y) % 5);
            assert_eq!(KECCAK_PI[t], nx + 5 * ny, "pi {t}");
            (x, y) = (nx, ny);
        }
    }

    #[test]
    fn sha3_256_matches_the_keccak_team_kat() {
        // XKCP tests/TestVectors/ShortMsgKAT_SHA3-256.txt (byte-aligned
        // entries): Len = 0, 8, 16, 1088 (exactly one 136-byte block: the
        // padding opens a second block) and 2040 bits (two blocks)
        let kat = [
            ("", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
            ("cc", "677035391cd3701293d385f037ba32796252bb7ce180b00b582dd9b20aaad7f0"),
            ("41fb", "39f31b6e653dfcd9caed2602fd87f61b6254f581312fb6eeec4d7148fa2e72aa"),
            (
                "b32d95b0b9aad2a8816de6d06d1f86008505bd8c14124f6e9a163b5a2ade55f835d0ec3880ef50700d3b25e42cc0af050ccd1be5e555b23087e04d7bf9813622780c7313a1954f8740b6ee2d3f71f768dd417f520482bd3a08d4f222b4ee9dbd015447b33507dd50f3ab4247c5de9a8abd62a8decea01e3b87c8b927f5b08beb37674c6f8e380c04",
                "df673f4105379ff6b755eeab20ceb0dc77b5286364fe16c59cc8a907aff07732",
            ),
            (
                "3a3a819c48efde2ad914fbf00e18ab6bc4f14513ab27d0c178a188b61431e7f5623cb66b23346775d386b50e982c493adbbfc54b9a3cd383382336a1a0b2150a15358f336d03ae18f666c7573d55c4fd181c29e6ccfde63ea35f0adf5885cfc0a3d84a2b2e4dd24496db789e663170cef74798aa1bbcd4574ea0bba40489d764b2f83aadc66b148b4a0cd95246c127d5871c4f11418690a5ddf01246a0c80a43c70088b6183639dcfda4125bd113a8f49ee23ed306faac576c3fb0c1e256671d817fc2534a52f5b439f72e424de376f4c565cca82307dd9ef76da5b7c4eb7e085172e328807c02d011ffbf33785378d79dc266f6a5be6bb0e4a92eceebaeb1",
                "c11f3522a8fb7b3532d80b6d40023a92b489addad93bf5d64b23f35e9663521c",
            ),
        ];
        for (msg, md) in kat {
            assert_eq!(
                hex(&keccak_sponge_256(&unhex(msg), 0x06)),
                md,
                "Msg = {msg}"
            );
        }
    }

    #[test]
    fn keccak256_differs_from_sha3_only_by_the_domain_suffix() {
        let msg = b"a message";
        assert_ne!(keccak256(msg), keccak_sponge_256(msg, 0x06));
        assert_eq!(keccak256(msg), keccak_sponge_256(msg, 0x01));
    }
}
