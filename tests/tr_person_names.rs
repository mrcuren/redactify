//! Label-free Turkish person names (`tr::person`) and the labeled-rule cue
//! fixes (`tr::name`), through the public API.

use redactify::{detect, redact, DetectionSource, Detector, EntityType, JsonRedactor};

fn names(text: &str) -> Vec<String> {
    detect(text)
        .into_iter()
        .filter(|e| e.kind == EntityType::Name)
        .map(|e| e.text)
        .collect()
}

#[test]
fn free_prose_name_is_masked_and_restored_byte_exact() {
    let text = "Bu rapor Ayşe Demir tarafından hazırlandı, Ayşe'nin onayı alındı.";
    assert_eq!(names(text), ["Ayşe Demir", "Ayşe"]);
    let (anon, vault) = Detector::new().pseudonymize(text);
    assert_eq!(
        anon,
        "Bu rapor [NAME_1] tarafından hazırlandı, [NAME_2]'nin onayı alındı."
    );
    assert_eq!(vault.restore(&anon), text);
}

#[test]
fn inflected_and_cased_forms() {
    for (text, want) in [
        ("Dosya Ahmet'in masasında.", "Ahmet"),
        ("Bunu Ayşe'ye ilet.", "Ayşe"),
        ("dosya Ahmetin masasında.", "Ahmet"),
        ("Ahmet Yılmazın telefonu", "Ahmet Yılmaz"),
        ("AHMET'in kaydı açık.", "AHMET"),
        ("imza: Ahmet YILMAZ", "Ahmet YILMAZ"),
        ("Sayın Ahmet Yılmaz, başvurunuz alındı.", "Ahmet Yılmaz"),
        ("Kaya Hanım toplantıda.", "Kaya"),
        ("Dr. Neval Dinçer muayene etti.", "Neval Dinçer"),
    ] {
        assert_eq!(names(text), [want], "{text:?}");
    }
    // the suffix and the title stay visible
    assert_eq!(redact("Ahmet'in"), "[NAME]'in");
    assert_eq!(redact("Dr. Neval Dinçer"), "Dr. [NAME]");
}

#[test]
fn customer_cue_in_turkish_spelling() {
    // measured before: "Musteri: Ahmet Yılmaz" -> NAME, the three below -> nothing
    for text in [
        "Müşteri: Ahmet Yılmaz",
        "müşteri Ahmet Yılmaz aradı",
        "Müşteri Ahmet Yılmaz aradı",
    ] {
        assert_eq!(names(text), ["Ahmet Yılmaz"], "{text:?}");
    }
    // the labeled rule claims a name the lexicon does not hold
    let explained = Detector::new().explain("Müşteri: Jean Dupont");
    assert_eq!(explained.len(), 1);
    assert_eq!(explained[0].0.text, "Jean Dupont");
    assert_eq!(
        explained[0].1.source,
        DetectionSource::Rule { id: "tr::name" }
    );
}

#[test]
fn organisations_addresses_and_words_are_not_names() {
    for text in [
        "Ahmet Yılmaz Holding hisseleri yükseldi.",
        "Ahmet Yılmaz Portföy Yönetimi A.Ş. açıkladı.",
        "Teslimat: Fevzi Çakmak Caddesi No: 12",
        "Deniz kenarında yürüdük.",
        "Umut verici bir gelişme oldu.",
        "Türk lirası ile ödenir.",
        "Kampanya adı: Bahar Dönemi Fırsatları",
        "Müşteri Hizmetleri Birimi",
        "Can you help me?",
    ] {
        assert!(names(text).is_empty(), "{text:?}: {:?}", names(text));
    }
}

#[test]
fn explanation_names_the_scanner() {
    let explained = Detector::new().explain("dosyada Ahmet Yılmaz imzası var");
    assert_eq!(explained.len(), 1);
    assert_eq!(
        explained[0].1.source,
        DetectionSource::Rule { id: "tr::person" }
    );
    assert!(!explained[0].1.validator_passed);
    assert_eq!(explained[0].1.score, explained[0].0.score);
}

#[test]
fn scanner_runs_only_with_the_turkish_pack() {
    let text = "Bu rapor Ayşe Demir tarafından hazırlandı.";
    assert!(Detector::new()
        .with_locales(&["en"])
        .detect(text)
        .is_empty());
    assert_eq!(
        Detector::new().with_locales(&["tr"]).detect(text)[0].text,
        "Ayşe Demir"
    );
}

#[test]
fn json_values_are_masked_and_keys_reported() {
    let mut doc = serde_json::json!({"ad_soyad": "Ayşe Demir", "not": "Ahmet'in dosyası"});
    let report = JsonRedactor::new().redact(&mut doc);
    assert_eq!(
        doc,
        serde_json::json!({"ad_soyad": "[NAME]", "not": "[NAME]'in dosyası"})
    );
    assert_eq!(report.findings.len(), 2);
    // a name used as a member name is reported, the key is kept
    let mut doc = serde_json::json!({"Ahmet Yılmaz": 1});
    let report = JsonRedactor::new().redact(&mut doc);
    assert_eq!(doc, serde_json::json!({"Ahmet Yılmaz": 1}));
    assert!(report.findings.iter().all(|f| f.in_key), "{report:?}");
}
