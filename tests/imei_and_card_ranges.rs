//! IMEI, card number ranges, cue-unlocked VINs, grouped TCKNs, `S` passports,
//! compact plates and version numbers (measured against the nm-kvkk-pii-6K
//! test split and a third-party negative fixture set; see the rule modules
//! for the sources).

use redactify::{detect, valid_credit_card, Detector, EntityType};

fn kinds(text: &str) -> Vec<(EntityType, String)> {
    detect(text).into_iter().map(|e| (e.kind, e.text)).collect()
}

#[test]
fn nm_kvkk_device_identifiers_are_imeis_not_cards() {
    // nm-kvkk-pii-6K: 39 IMEIs, every one Luhn-valid, none a CREDIT_CARD
    for (text, imei) in [
        ("Cihaz kimliği: 351524205681913", "351524205681913"),
        (
            "Toga adına kayıtlı cihazın IMEI bilgisi 353250104553577 olarak izlenir",
            "353250104553577",
        ),
        (
            "cihaz bilgileri ekranında 867236055436929 numarası görünür",
            "867236055436929",
        ),
        ("IMEI: 35-152420-568191-3", "35-152420-568191-3"),
        // third-party holdout: prefix 94 is no reporting body, the cue
        // unlocks it
        ("IMEI: 944739086974724", "944739086974724"),
    ] {
        assert_eq!(kinds(text), [(EntityType::Imei, imei.to_owned())], "{text}");
    }
}

#[test]
fn imei_is_masked_with_its_own_label() {
    let out = Detector::new().redact("Kayıtlı Cihaz IMEI: 353250108234257");
    assert_eq!(out, "Kayıtlı Cihaz IMEI: [IMEI]");
}

#[test]
fn real_card_shapes_stay_cards() {
    // 16-digit Visa, Mastercard 2-series, TROY; 15-digit American Express;
    // 14-digit Diners Club; 13-digit Visa
    for number in [
        "4111 1111 1111 1111",
        "2221 0000 0000 0009",
        "9792 0000 0000 0003",
        "3782 822463 10005",
        "3056 930902 5904",
        "4222222222222",
    ] {
        let text = format!("kart {number} ile ödendi");
        assert_eq!(
            kinds(&text),
            [(EntityType::CreditCard, number.to_owned())],
            "{text}"
        );
        assert!(valid_credit_card(number), "{number}");
    }
}

#[test]
fn negative_fixture_card_shapes_are_no_cards() {
    // third-party negative fixtures: all-zero numbers and the all-zero tail
    // of an invalid IBAN; a 15-digit IMSI of nm-kvkk-pii-6K
    for text in [
        "Hediye çeki kodu 0000000000000000 geçersiz sayılır.",
        "Kargo takip kodu 8888888888888888 teslimat aşamasında.",
        "TR00 0000 0000 0000 0000 0000 00 sistem tarafından reddedildi.",
        "Mobil doğrulama tanımlayıcısı: 286014552090041",
    ] {
        assert!(
            !detect(text)
                .iter()
                .any(|e| e.kind == EntityType::CreditCard),
            "{text}"
        );
    }
}

#[test]
fn a_vin_cue_unlocks_vins_without_the_us_check_digit() {
    assert_eq!(
        kinds("Şasi/VIN numarası: VSS6L5KNDCB0GYVYN"),
        [(EntityType::Vin, "VSS6L5KNDCB0GYVYN".to_owned())]
    );
    assert!(kinds("kod VSS6L5KNDCB0GYVYN").is_empty());
}

#[test]
fn grouped_tckn_and_s_passports() {
    assert_eq!(
        kinds("T.C. kimlik 232.475.469.02 şeklinde iletildi"),
        [(EntityType::Tckn, "232.475.469.02".to_owned())]
    );
    assert_eq!(
        kinds("Pasaport numarası: S44075190"),
        [(EntityType::Passport, "S44075190".to_owned())]
    );
    // the passport stays cue-gated
    assert!(kinds("kod S44075190").is_empty());
}

#[test]
fn compact_plates() {
    assert_eq!(
        kinds("Plaka: 34kk3058"),
        [(EntityType::Plaka, "34kk3058".to_owned())]
    );
    // uppercase compact plates are masked without a cue (leak-averse; see
    // `tr::plaka`), lowercase ones need a cue
    assert_eq!(
        kinds("06AB1234"),
        [(EntityType::Plaka, "06AB1234".to_owned())]
    );
    assert_eq!(
        kinds("Otomobil 34ABC123 trafikte"),
        [(EntityType::Plaka, "34ABC123".to_owned())]
    );
    assert!(kinds("34abc123 kodu girildi.").is_empty());
}

#[test]
fn version_numbers_are_not_ip_addresses() {
    assert!(kinds("Sürüm 1.2.3.4 yayımlandı, hata düzeltmeleri içeriyor.").is_empty());
    assert_eq!(
        kinds("Sunucu 8.8.8.8 yanıt vermiyor"),
        [(EntityType::IpAddress, "8.8.8.8".to_owned())]
    );
}
