//! Cryptocurrency addresses (CRYPTO_ADDRESS): Bitcoin mainnet base58check
//! and segwit (bech32 / bech32m) addresses and EIP-55 checksummed Ethereum
//! addresses, every vector taken from the issuing project's own test data
//! (retrieved 2026-10-31):
//!
//! - Bitcoin Core `src/test/data/key_io_valid.json` (SHA-256
//!   90bd1d35d12763e0d00c5400b2c9fe551e532a821e1e466c20cad3aced70a7fe, last
//!   changed in commit 7c200ece8057) and `key_io_invalid.json` (SHA-256
//!   c3ca74ddad7c01faaca7c26063537feb73ff2be03eb7fc83a42a655d2979261d);
//! - BIP350 "Test vectors for v0-v16 native segregated witness addresses"
//!   (bitcoin/bips at 5aadddb511a5);
//! - EIP-55 (ERC-55) specification test addresses.

use redactify::{detect, valid_btc_address, valid_eth_address, EntityType};

/// key_io_valid.json: every non-private-key entry with `"chain": "main"`.
const BTC_MAINNET: [&str; 14] = [
    "1FsSia9rv4NeEwvJ2GvXrX7LyxYspbN2mo",
    "36j4NfKv6Akva9amjWrLG6MuSQym1GuEmm",
    "bc1qvyq0cc6rahyvsazfdje0twl7ez82ndmuac2lhv",
    "bc1qyucykdlhp62tezs0hagqury402qwhk589q80tqs5myh3rxq34nwqhkdhv7",
    "bc1p83n3au0rjylefxq2nc2xh2y4jzz4pm6zxj4mw5pagdjjr2a9f36s6jjnnu",
    "bc1z2rksukkjr8",
    "1FjL87pn8ky6Vbavd1ZHeChRXtoxwRGCRd",
    "3BZECeAH8gSKkjrTx8PwMrNQBLG18yHpvf",
    "bc1qhxt04s5xnpy0kxw4x99n5hpdf5pmtzpqs52es2",
    "bc1qgc9ljrvdf2e0zg9rmmq86xklqwfys7r6wptjlacdgrcdc7sa6ggqu4rrxf",
    "bc1pve739yap4uxjvfk0jrey69078u0gasm2nwvv483ec6zkzulgw9xqu4w9fd",
    "bc1zmjtqxkzs89",
    "1G9A9j6W8TLuh6dEeVwWeyibK1Uc5MfVFV",
    "33GA3ZXbw5o5HeUrBEaqkWXFYYZmdxGRRP",
];

/// BIP350 valid segwit vectors with the mainnet human-readable part `bc`.
const BIP350_MAINNET: [&str; 5] = [
    "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
    "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y",
    "BC1SW50QGDZ25J",
    "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs",
    "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
];

/// BIP350 invalid segwit vectors with the `bc` part (reason in the BIP).
const BIP350_INVALID_MAINNET: [&str; 10] = [
    // Bech32 instead of Bech32m
    "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",
    "BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL",
    // Bech32m instead of Bech32
    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh",
    // invalid character in checksum
    "bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4",
    // invalid witness version
    "BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R",
    // invalid program length (1 byte, 41 bytes, v0 not 20/32)
    "bc1pw5dgrnzv",
    "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav",
    "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
    // zero padding of more than 4 bits
    "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf",
    // empty data section
    "bc1gmk9yu",
];

/// EIP-55 specification test addresses (mixed-case checksum).
const EIP55: [&str; 4] = [
    "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
    "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
    "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
    "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
];

/// The CRYPTO_ADDRESS spans `detect` reports in `text`.
fn found(text: &str) -> Vec<&str> {
    detect(text)
        .into_iter()
        .filter(|e| e.kind == EntityType::CryptoAddress)
        .map(|e| &text[e.start..e.end])
        .collect()
}

#[test]
fn bitcoin_core_mainnet_vectors_are_valid_and_detected_whole() {
    for addr in BTC_MAINNET.iter().chain(&BIP350_MAINNET) {
        assert!(valid_btc_address(addr), "{addr}");
        let text = format!("send to {addr} today");
        assert_eq!(found(&text), [*addr], "{text}");
    }
}

#[test]
fn bech32_accepts_one_case_only() {
    // BIP173: decoders MUST NOT accept mixed-case strings; an all-uppercase
    // form is the same address
    let lower = "bc1qvyq0cc6rahyvsazfdje0twl7ez82ndmuac2lhv";
    assert!(valid_btc_address(&lower.to_uppercase()));
    let mut mixed = lower.to_owned();
    mixed.replace_range(4..5, "V");
    assert!(!valid_btc_address(&mixed), "{mixed}");
}

#[test]
fn testnet_and_regtest_addresses_are_not_claimed() {
    let other: Vec<&str> = [
        "mzK2FFDEhxqHcmrJw1ysqFkVyhUULo45hZ",
        "2NC2hEhe28ULKAJkW5MjZ3jtTMJdvXmByvK",
        "n4fajahJrAuKbN7uNsKjLjQkz9Qn5ewJXQ",
        "tb1qcrh3yqn4nlleplcez2yndq2ry8h9ncg3qh7n54",
        "tb1p35n52jy6xkm4wd905tdy8qtagrn73kqdz73xe4zxpvq9t3fp50aqk3s6gz",
        "tb1rgv5m6uvdk3kc7qsuz0c79v88ycr5w4wa",
    ]
    .to_vec();
    for addr in other {
        assert!(!valid_btc_address(addr), "{addr}");
        assert!(found(&format!("addr {addr}")).is_empty(), "{addr}");
    }
}

#[test]
fn bitcoin_core_and_bip350_invalid_vectors_are_rejected() {
    let core_invalid = [
        "1GAdfviErV2Ew95FPtZyikz2qGP3gyCB6Hyu94sedAkPpA523m3fQwps9YKUZkKgQckGPKhRsFR",
        "37G2kMDLpmWVhimxRdzwNfE8JFvWXnJYnVcXeeGrek2qumdJuK7XArcVVpRtLLjRra3t64BEPF2",
        "bc10uexgzna2dpfk0vjt35srz6a27ps6m0l89jweznt83n2sqn2fx4hvn9ym5af8wut34sfrqhk3",
        "bc1qdsuzmn04k2z8vryw8l4dj8m5ygqgnne5n",
        "bc1qpu6d26mrulzetu4jqhd7rsunv9aqru26f5c4j8",
        "bc1p702xksx4z3uqf0u2phllxkfe5cgu0adxptqs0uelx0tqt8e885sqryes2l",
        "bc10lyxwnxa70l270e6fcmxr4x7dtgu2yvy7gzkurwxy4zhdvgaqrrn6pfg2flyhqzy5t5se8yu3",
        "bc1qtsvlht6730n04f2mpaj5vv8hrledn5n5ug8c79",
        "bc1prklpq7tjcawg89cmwwqr3u5apwav36xa4zz56ady7crsllm6mpnqts7p86",
        "39TKsUQ5QpEL1wowc6GMUqak94ijirPuP69ooV3xsFmiKQX2dau",
        "AZEah8d1EK362okRBS66e8SvdtYkrE8tsX",
        "KzNbAQ4mexfAxa6RKBzHQqfoTycaeWpv2p",
    ];
    for addr in core_invalid.iter().chain(&BIP350_INVALID_MAINNET) {
        assert!(!valid_btc_address(addr), "{addr}");
        assert!(found(&format!("addr {addr}")).is_empty(), "{addr}");
    }
}

#[test]
fn a_single_changed_base58_character_fails_the_checksum() {
    // double-SHA-256 checksum (BIP13: the first four bytes)
    assert!(valid_btc_address("1FsSia9rv4NeEwvJ2GvXrX7LyxYspbN2mo"));
    assert!(!valid_btc_address("1FsSia9rv4NeEwvJ2GvXrX7LyxYspbN2mp"));
    assert!(!valid_btc_address("1GsSia9rv4NeEwvJ2GvXrX7LyxYspbN2mo"));
}

#[test]
fn eip55_specification_addresses_are_valid_and_detected() {
    for addr in EIP55 {
        assert!(valid_eth_address(addr), "{addr}");
        assert_eq!(found(&format!("pay {addr}.")), [addr]);
    }
}

#[test]
fn eth_addresses_without_the_mixed_case_checksum_are_not_claimed() {
    // EIP-55: all-lowercase / all-uppercase addresses carry no checksum
    for addr in EIP55 {
        let lower = format!("0x{}", addr[2..].to_lowercase());
        let upper = format!("0x{}", addr[2..].to_uppercase());
        assert!(!valid_eth_address(&lower), "{lower}");
        assert!(!valid_eth_address(&upper), "{upper}");
    }
    // one letter with the wrong case fails the checksum
    assert!(!valid_eth_address(
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD"
    ));
}

#[test]
fn addresses_next_to_cjk_text_are_found() {
    let text = "\u{5730}\u{5740}1FsSia9rv4NeEwvJ2GvXrX7LyxYspbN2mo\u{8C22}\u{8C22}";
    assert_eq!(found(text), ["1FsSia9rv4NeEwvJ2GvXrX7LyxYspbN2mo"]);
}

#[test]
fn an_address_is_masked_whole_and_never_as_a_card_fragment() {
    for addr in EIP55.iter().chain(&BTC_MAINNET) {
        let text = format!("wallet {addr}");
        let kinds: Vec<EntityType> = detect(&text).iter().map(|e| e.kind).collect();
        assert_eq!(kinds, [EntityType::CryptoAddress], "{text}");
        assert_eq!(redactify::redact(&text), "wallet [CRYPTO_ADDRESS]");
    }
}
