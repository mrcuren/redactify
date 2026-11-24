//! Turkish record fields through the public `Detector`: postal address,
//! date and place of birth, card security code and expiry, customer,
//! policy, SGK and MERSİS numbers (`tr` pack, default locale set).
//!
//! Each rule file documents its source and policy; this suite checks the
//! end-to-end labels and spans on a realistic multi-field record, the
//! cue requirements, and that everyday Turkish text without those fields
//! stays clean.

use redactify::{Detector, EntityType};

fn found(text: &str) -> Vec<(EntityType, String)> {
    Detector::new()
        .detect(text)
        .into_iter()
        .map(|e| (e.kind, e.text))
        .collect()
}

fn of_kind(text: &str, kind: EntityType) -> Vec<String> {
    found(text)
        .into_iter()
        .filter(|(k, _)| *k == kind)
        .map(|(_, t)| t)
        .collect()
}

#[test]
fn a_full_record_yields_every_field_with_its_label() {
    let record = "\
Ad Soyad: Ayşe Yılmaz
T.C. Kimlik No: 10000000146
Doğum Tarihi: 23.06.1971
Doğum Yeri: Kütahya
İkamet Adresi: Kalemköy Mahallesi Papatya Sokak No:32 D:14 35990 Kınık/İzmir
Müşteri No: 1344536
Poliçe Numarası: POL-2020-968665
SGK Sicil No: 9572017271586
Kurum MERSİS numarası: 0647064329700019
Kart güvenlik kodu (CVV): 656
Son Kullanma Tarihi: 06/27
";
    let got = found(record);
    for (kind, text) in [
        (EntityType::Tckn, "10000000146"),
        (EntityType::DateOfBirth, "23.06.1971"),
        (EntityType::PlaceOfBirth, "Kütahya"),
        (
            EntityType::Address,
            "Kalemköy Mahallesi Papatya Sokak No:32 D:14 35990 Kınık/İzmir",
        ),
        (EntityType::CustomerNumber, "1344536"),
        (EntityType::PolicyNumber, "POL-2020-968665"),
        (EntityType::Sgk, "9572017271586"),
        (EntityType::Mersis, "0647064329700019"),
        (EntityType::CardCvv, "656"),
        (EntityType::CardExpiry, "06/27"),
    ] {
        assert!(
            got.contains(&(kind, text.to_owned())),
            "{kind}: {text} missing in {got:?}"
        );
    }
}

#[test]
fn an_expiry_followed_by_its_code_on_one_line_keeps_both_labels() {
    for (text, expiry, code) in [
        ("SKT 06/27 CVV 123", "06/27", "123"),
        ("Kart 4111 1111 1111 1111 SKT 08/28 CVV 431", "08/28", "431"),
        ("Son kullanma tarihi 12/29 CVV 456", "12/29", "456"),
    ] {
        let got = found(text);
        assert!(
            got.contains(&(EntityType::CardExpiry, expiry.to_owned()))
                && got.contains(&(EntityType::CardCvv, code.to_owned())),
            "{text}: {got:?}"
        );
        assert!(
            of_kind(text, EntityType::Plaka).is_empty(),
            "{text}: {got:?}"
        );
    }
}

#[test]
fn new_labels_round_trip_through_from_str() {
    for kind in [
        EntityType::DateOfBirth,
        EntityType::PlaceOfBirth,
        EntityType::CardCvv,
        EntityType::CardExpiry,
        EntityType::CustomerNumber,
        EntityType::PolicyNumber,
        EntityType::Sgk,
        EntityType::Mersis,
    ] {
        assert_eq!(kind.as_str().parse::<EntityType>(), Ok(kind));
    }
}

#[test]
fn prose_addresses_are_whole_spans() {
    assert_eq!(
        of_kind(
            "Sigortalının ikamet ettiği Sasalı Merkez Mah. 9sokak Sk. No:80 Daire:3 Çiğli/İzmir adresindeki binadır.",
            EntityType::Address
        ),
        vec!["Sasalı Merkez Mah. 9sokak Sk. No:80 Daire:3 Çiğli/İzmir"]
    );
    assert_eq!(
        of_kind(
            "Katılımcı adresi: Burhaniye Mahallesi, Diyar Çıkmazı Sok., No: 79, Kat: 6, Daire: 2, Üsküdar / İstanbul",
            EntityType::Address
        ),
        vec!["Burhaniye Mahallesi, Diyar Çıkmazı Sok., No: 79, Kat: 6, Daire: 2, Üsküdar / İstanbul"]
    );
}

#[test]
fn cue_gated_fields_stay_clean_without_their_cue() {
    for text in [
        // dates that are not birth dates
        "Düzenleme Tarihi: 14.02.2025",
        "Toplantı 12.03.2024 tarihinde Ankara'da yapıldı.",
        // place names without a birth cue
        "Teslimat ili: Aydın, ilçe: İncirliova",
        // 3-4 digit and MM/YY values without a card cue
        "Oda No: 407, Kat: 3",
        "Oran 12/27 olarak hesaplandı.",
        // digit runs without a customer / policy / SGK / MERSİS cue
        "Sipariş No: 1344536",
        "Kargo Takip No: 725012345678",
        "Referans: 0647064329700019",
        "Protokol No: 2025/1563",
        // a bare `müşteri` or `poliçe` is not a cue
        "Müşteri hizmetleri 2125550000",
        "Poliçe primi: 125000",
    ] {
        let got = found(text);
        assert!(
            !got.iter().any(|(k, _)| matches!(
                k,
                EntityType::DateOfBirth
                    | EntityType::PlaceOfBirth
                    | EntityType::CardCvv
                    | EntityType::CardExpiry
                    | EntityType::CustomerNumber
                    | EntityType::PolicyNumber
                    | EntityType::Sgk
                    | EntityType::Mersis
            )),
            "{text}: {got:?}"
        );
    }
}

#[test]
fn everyday_text_holds_no_address() {
    for text in [
        "Atatürk Caddesi bugün trafiğe kapalı.",
        "Kurtuluş Mahallesi'nde yeni bir park açıldı.",
        "Kızılay Mahallesi Atatürk Caddesi'nde yürüyüş yaptık.",
        "Bağdat Caddesi ile İstiklal Caddesi karşılaştırıldı.",
        "Ürün Kodu: CG-TRM-500, Miktar: 1 adet, Koli: 38 x 28 x 22 cm",
        "Madde 5 uyarınca No: 12 sayılı karar uygulanır.",
    ] {
        assert!(
            of_kind(text, EntityType::Address).is_empty(),
            "{text}: {:?}",
            found(text)
        );
    }
}

#[test]
fn checksummed_identifiers_keep_their_label_under_the_new_cues() {
    // a valid TCKN next to an SGK or customer-number cue stays a TCKN
    for text in ["SGK sicil no: 10000000146", "Müşteri No: 10000000146"] {
        assert_eq!(
            found(text),
            vec![(EntityType::Tckn, "10000000146".to_owned())],
            "{text}"
        );
    }
    // an uncued Luhn-valid 16-digit run stays a card number
    assert_eq!(
        found("Kart: 4111111111111111"),
        vec![(EntityType::CreditCard, "4111111111111111".to_owned())]
    );
}

#[test]
fn turkish_credential_keys_are_masked() {
    use redactify::guard::find_secret_spans;
    // 8 alphanumerics: the assignment floor of the secrets layer
    const V: &str = "Xk1!m7Pq9";
    for key in [
        "Şifre: ",
        "şifre=",
        "ŞİFRE: ",
        "SIFRE: ",
        "sifre: ",
        "Geçici şifre: ",
        "Wi-Fi şifresi: ",
        "Şifreniz: ",
        "parola=",
        "Parola: ",
        "PAROLA: ",
        "Geçici parola: ",
        "geçici_parola: ",
        "kullanici.sifre=",
        "\"şifre\": \"",
        // dotted capital / dotless i spellings: the prefilter must not skip
        // these, or the value stays in clear
        "SİFRE: ",
        "Sİfre: ",
        "şİfre: ",
        "Şıfre: ",
        "şıfre: ",
        "sıfre: ",
        "ſifre: ",
    ] {
        let text = format!("{key}{V}");
        let spans = find_secret_spans(&text);
        assert_eq!(spans.len(), 1, "{text}: {spans:?}");
        assert_eq!(&text[spans[0].start..spans[0].end], V, "{text}");
    }
    // the word is not the key, or the value is no password
    for text in [
        "parola uzunluğu: 12",
        "Parola uzunluğu: en az 12 karakter",
        "şifre sıfırlama bağlantısı: gönderildi",
        "Şifre: ********",
        "Şifre: 123456",
        "Şifre: Girilmedi",
        "parolasız giriş: kapalıdır",
    ] {
        assert!(
            find_secret_spans(text).is_empty(),
            "{text}: {:?}",
            find_secret_spans(text)
        );
    }
}

#[test]
fn turkish_password_labels_are_masked_by_the_guard() {
    use redactify::{Guard, GuardTarget};
    for key in [
        "SİFRE", "Sİfre", "şİfre", "Şıfre", "şıfre", "sıfre", "ŞİFRE", "Parola",
    ] {
        let text = format!("{key}: Xk1!m7Pq9");
        let out = Guard::new(GuardTarget::UserPrompt).sanitize(&text).text;
        assert!(!out.contains("Xk1!m7Pq9"), "{text} -> {out}");
    }
}

#[test]
fn sgk_and_mersis_never_split_an_email_a_url_or_a_detected_phone() {
    // with the cue on the line
    for (text, kind) in [
        ("SGK: ali12345678@firma.com", EntityType::Email),
        ("SGK: ali1234567890123@firma.com", EntityType::Email),
        ("Gönder: ali12345678@gmail.com (SGK)", EntityType::Email),
        ("Mersis: x1234567890123456@firma.com", EntityType::Email),
        (
            "SGK https://ornek.com/u/1234567890123?ad=ahmet.yilmaz",
            EntityType::Url,
        ),
    ] {
        let got = found(text);
        assert_eq!(got.len(), 1, "{text}: {got:?}");
        assert_eq!(got[0].0, kind, "{text}: {got:?}");
    }
    // with the cue in the caller's context (every line of the input)
    let ctx = ["SGK sicil numaranızı ve e-postanızı yazar mısınız?"];
    let det = Detector::new().with_context(&ctx);
    for (text, masked) in [
        ("ali12345678@gmail.com", "[EMAIL]"),
        ("ali1234567890123@gmail.com", "[EMAIL]"),
        (
            "https://ornek.com/profil/1234567890123/ahmet-yilmaz",
            "[URL]",
        ),
    ] {
        assert_eq!(det.redact(text), masked, "{text}");
    }
    // a phone that contains a cued 8-12 digit token is masked whole
    assert_eq!(det.redact("telefon +90 5321234567"), "telefon [PHONE]");
    // no phone rule claims an 8-digit subscriber part: its digits stay
    // masked (as SGK), never in clear
    let out = det.redact("telefon +90 212 12345678");
    assert!(!out.contains("12345678"), "{out}");
    // a cued 8-digit value is found
    assert_eq!(det.redact("12345678"), "[SGK]");
    // a bare cued SGK number is still found
    assert_eq!(det.redact("9572017271586"), "[SGK]");
}

#[test]
fn an_identifier_after_an_address_leaves_the_address_masked() {
    for (text, address, other) in [
        (
            "Ahmet Yılmaz, Atatürk Mah. Gül Sok. No:5 Kadıköy/İstanbul, 12345678950",
            "Atatürk Mah. Gül Sok. No:5 Kadıköy/İstanbul",
            (EntityType::Tckn, "12345678950"),
        ),
        (
            "Atatürk Mah. Gül Sok. No: 5 Kadıköy/İstanbul 05322345678",
            "Atatürk Mah. Gül Sok. No: 5 Kadıköy/İstanbul",
            (EntityType::Phone, "05322345678"),
        ),
        (
            "Atatürk Mah. Gül Sok. No: 5 Kadıköy/İstanbul, 05322345678",
            "Atatürk Mah. Gül Sok. No: 5 Kadıköy/İstanbul",
            (EntityType::Phone, "05322345678"),
        ),
        (
            "Atatürk Mah. Gül Sok. No: 5, 05322345678",
            "Atatürk Mah. Gül Sok. No: 5",
            (EntityType::Phone, "05322345678"),
        ),
        (
            "Atatürk Mah. Gül Sok. No:5, 12345678950, Kadıköy",
            "Atatürk Mah. Gül Sok. No:5",
            (EntityType::Tckn, "12345678950"),
        ),
        (
            "Atatürk Mah. Gül Sok. No: 5 / 4111111111111111",
            "Atatürk Mah. Gül Sok. No: 5",
            (EntityType::CreditCard, "4111111111111111"),
        ),
    ] {
        let got = found(text);
        assert!(
            got.contains(&(EntityType::Address, address.to_owned())),
            "{text}: {got:?}"
        );
        assert!(
            got.contains(&(other.0, other.1.to_owned())),
            "{text}: {got:?}"
        );
    }
    // a 5-digit postal code is kept, before the place or at the line end
    assert_eq!(
        of_kind(
            "Atatürk Mah. Gül Sok. No: 5 Kadıköy/İstanbul 34710",
            EntityType::Address
        ),
        vec!["Atatürk Mah. Gül Sok. No: 5 Kadıköy/İstanbul 34710"]
    );
    assert_eq!(
        of_kind(
            "Daire: 11 değil; Kalemköy Mah. Papatya Sok. No:32 D:14 35990 Kınık/İzmir, 05322345678",
            EntityType::Address
        ),
        vec!["Kalemköy Mah. Papatya Sok. No:32 D:14 35990 Kınık/İzmir"]
    );
}

#[test]
fn long_hostile_lines_finish_and_stay_clean() {
    // 200,000-character lines built from the units the new patterns
    // consume (capitalized words + keywords, digits, separators): the scan
    // must finish (no backtracking-budget error drops a finding) and claim
    // nothing that is not there. (`12.03.` and `12/` repeated are left
    // out: the scan of those lines was already incomplete before the
    // record rules, through an older rule; the record rules alone pass
    // them in the unit test of `pii::locales::tr`.)
    for unit in [
        "Ab ", "Mah. ", "Ab Mah. ", "No:1 ", "1/2 ", "Doğum ", "1 ", "POL-1-", "İzmir ", "ü",
    ] {
        let text = unit.repeat(200_000 / unit.len());
        let report = Detector::new().scan(&text);
        assert!(report.is_complete(), "{unit:?}: incomplete scan");
        assert!(
            report
                .entities
                .iter()
                .all(|e| e.kind != EntityType::Address),
            "{unit:?}: {} address spans",
            report.entities.len()
        );
    }
    // a real address at the end of a long line is still found
    let text = format!(
        "{}Adres: Bağdat Caddesi No:5 Daire:10 Kadıköy/İstanbul",
        "kelime ".repeat(28_000)
    );
    assert_eq!(
        of_kind(&text, EntityType::Address),
        vec!["Bağdat Caddesi No:5 Daire:10 Kadıköy/İstanbul"]
    );
}
