//! KVKK art. 6 special categories (`tr::special`): record fields and
//! person-linked terms are claimed with their category label, bare terms
//! in general text are not, and the scanner keeps streaming == batch.

use redactify::policy::stream::{GuardEvent, StreamingGuard};
use redactify::policy::{sanitize, GuardTarget};
use redactify::{DetectionSource, Detector, EntityType};

const SPECIAL: [EntityType; 10] = [
    EntityType::SpecialHealth,
    EntityType::SpecialGenetic,
    EntityType::SpecialBiometric,
    EntityType::SpecialSexLife,
    EntityType::SpecialCriminal,
    EntityType::SpecialBelief,
    EntityType::SpecialEthnicity,
    EntityType::SpecialPolitical,
    EntityType::SpecialAttire,
    EntityType::SpecialMembership,
];

fn special(text: &str) -> Vec<(EntityType, String)> {
    let tr = ["tr"];
    Detector::new()
        .with_locales(&tr)
        .detect(text)
        .into_iter()
        .filter(|e| SPECIAL.contains(&e.kind))
        .map(|e| (e.kind, e.text))
        .collect()
}

fn one(kind: EntityType, text: &str) -> Vec<(EntityType, String)> {
    vec![(kind, text.to_owned())]
}

#[test]
fn labels_are_stable_and_parse_back() {
    let labels = [
        "SPECIAL_HEALTH",
        "SPECIAL_GENETIC",
        "SPECIAL_BIOMETRIC",
        "SPECIAL_SEX_LIFE",
        "SPECIAL_CRIMINAL",
        "SPECIAL_BELIEF",
        "SPECIAL_ETHNICITY",
        "SPECIAL_POLITICAL",
        "SPECIAL_ATTIRE",
        "SPECIAL_MEMBERSHIP",
    ];
    for (kind, label) in SPECIAL.iter().zip(labels) {
        assert_eq!(kind.as_str(), label);
        assert_eq!(label.parse::<EntityType>(), Ok(*kind));
        // word evidence without a checksum: the NAME tier
        assert_eq!(kind.priority(), EntityType::Name.priority());
    }
}

#[test]
fn record_fields_are_claimed_whole() {
    let cases = [
        (
            "Tanı: Esansiyel hipertansiyon",
            EntityType::SpecialHealth,
            "Esansiyel hipertansiyon",
        ),
        ("Kan grubu: 0 Rh-", EntityType::SpecialHealth, "0 Rh-"),
        (
            "Kullanılan ilaç: Metformin 1000 mg",
            EntityType::SpecialHealth,
            "Metformin 1000 mg",
        ),
        (
            "Engellilik durumu: Sürekli kısmi iş göremezlik",
            EntityType::SpecialHealth,
            "Sürekli kısmi iş göremezlik",
        ),
        (
            "Biyometrik veri referansı: Parmak izi şablonu",
            EntityType::SpecialBiometric,
            "Parmak izi şablonu",
        ),
        (
            "Genetik veri referansı: PGx varyant profili",
            EntityType::SpecialGenetic,
            "PGx varyant profili",
        ),
        (
            "Etnik köken beyanı: Laz kökenli",
            EntityType::SpecialEthnicity,
            "Laz kökenli",
        ),
        (
            "Dini inanç beyanı: İslam inancına bağlı",
            EntityType::SpecialBelief,
            "İslam inancına bağlı",
        ),
        (
            "Siyasi parti: Yeni Ufuklar Partisi",
            EntityType::SpecialPolitical,
            "Yeni Ufuklar Partisi",
        ),
        (
            "Cinsel yönelim: Biseksüel",
            EntityType::SpecialSexLife,
            "Biseksüel",
        ),
        (
            "Adli sicil kaydı: 2019 tarihli hapis cezası",
            EntityType::SpecialCriminal,
            "2019 tarihli hapis cezası",
        ),
        (
            "Üye olduğu sendika: Tez-Koop-İş",
            EntityType::SpecialMembership,
            "Tez-Koop-İş",
        ),
    ];
    for (text, kind, value) in cases {
        assert_eq!(special(text), one(kind, value), "{text}");
    }
}

#[test]
fn person_linked_terms_are_claimed() {
    let cases = [
        (
            "Diyabetim var, insülin kullanıyorum.",
            EntityType::SpecialHealth,
            &["Diyabet", "insülin"][..],
        ),
        (
            "Hastanın bilinen tanısı esansiyel hipertansiyon olup düzenli kontrol önerildi.",
            EntityType::SpecialHealth,
            &["esansiyel hipertansiyon"],
        ),
        ("Ben Müslümanım.", EntityType::SpecialBelief, &["Müslüman"]),
        (
            "Ahmet Yılmaz sendika üyesi olarak çalışıyor.",
            EntityType::SpecialMembership,
            &["sendika üyesi"],
        ),
        (
            "Eşcinselim ve bunu saklamıyorum.",
            EntityType::SpecialSexLife,
            &["Eşcinsel"],
        ),
        (
            "Sabıka kaydım temiz değil.",
            EntityType::SpecialCriminal,
            &["Sabıka kaydı"],
        ),
        (
            "Yeni Ufuklar Partisi üyesiyim.",
            EntityType::SpecialPolitical,
            &["Yeni Ufuklar Partisi"],
        ),
        (
            "Başörtülüyüm ve işyerinde sorun yaşıyorum.",
            EntityType::SpecialAttire,
            &["Başörtülü"],
        ),
        (
            "Müşterimiz Kürt kökenli olduğunu belirtti.",
            EntityType::SpecialEthnicity,
            &["Kürt kökenli"],
        ),
    ];
    for (text, kind, values) in cases {
        let want: Vec<(EntityType, String)> =
            values.iter().map(|v| (kind, (*v).to_owned())).collect();
        assert_eq!(special(text), want, "{text}");
    }
}

#[test]
fn blood_group_cue_in_possessive_forms() {
    assert_eq!(
        special("Kan grubum A Rh+, sigorta formuna yazmam gerekiyor mu?"),
        one(EntityType::SpecialHealth, "A Rh+")
    );
    assert_eq!(
        special("Sistemde kan grubunuz 0 Rh- olarak görünüyor."),
        one(EntityType::SpecialHealth, "0 Rh-")
    );
    assert!(special("Kan grubunuz nedir?").is_empty());
}

#[test]
fn capitalized_sentences_need_strong_evidence() {
    let found = special("MÜŞTERİ NURAY ÇAKIR KANSER TEDAVİSİ GÖRÜYOR, KREDİ ERTELEME TALEBİ VAR");
    assert_eq!(found, one(EntityType::SpecialHealth, "KANSER"));
    for text in [
        "HASTA BİLGİLENDİRME: DİYABET",
        "MÜŞTERİ KANSER TARAMASI KAMPANYASI",
    ] {
        assert!(special(text).is_empty(), "{text}: {:?}", special(text));
    }
}

#[test]
fn bare_terms_in_general_text_are_not_claimed() {
    for text in [
        "Diyabet hastalarında kan şekeri takibi önemlidir.",
        "Hipertansiyon dünyada en yaygın kronik hastalıklardan biridir.",
        "Cami avlusunda kermes düzenlendi.",
        "Müslüman nüfusun yoğun olduğu ülkelerde ramazan bayramı kutlanır.",
        "Sendika genel kurulu yarın toplanıyor.",
        "Roman okumayı çok seviyorum.",
        "Kan grubu 0 Rh- olanlar evrensel vericidir.",
        "Parmak izi okuyucuları kapı girişlerine takıldı.",
        "Seçim sonuçları akşam açıklanacak.",
        "Kronik hastalık: Yok",
        "Engellilik durumu: Engelli değil",
        "Ayakta tedavi: Poliçe kapsamında",
        "Irk: Holştayn",
        "DİYABET YÖNETİM PLANI",
        "Op. Dr. Bedia Refika Sakallı",
        "Uzm. Aslıhan Kurt için portföy raporu",
        "Mumun alevi rüzgârda söndü.",
        "Bu konuyu daha ayrıntılı paylaşmak isterim.",
        "Lazım olan belgeler listede yer alıyor.",
    ] {
        assert!(special(text).is_empty(), "{text}: {:?}", special(text));
    }
}

#[test]
fn the_scanner_id_names_the_category() {
    let tr = ["tr"];
    let explained = Detector::new()
        .with_locales(&tr)
        .explain("Tanı: Astım ve Kan grubu: A Rh+");
    let ids: Vec<_> = explained
        .iter()
        .filter(|(e, _)| e.kind == EntityType::SpecialHealth)
        .map(|(_, why)| why.source)
        .collect();
    assert!(!ids.is_empty());
    for id in ids {
        assert_eq!(
            id,
            DetectionSource::Rule {
                id: "tr::special_health"
            }
        );
    }
}

#[test]
fn every_category_reports_its_own_type_on_one_line() {
    // ten categories on one line: the shared per-line analysis must hand
    // each scanner exactly its own findings
    let text = "Diyabetim var; Müslümanım; Kürdüm; eşcinselim; sendikalıyım; \
                hükümlüyüm; başörtülüyüm; komünistim";
    let kinds: Vec<EntityType> = special(text).into_iter().map(|(k, _)| k).collect();
    for kind in [
        EntityType::SpecialHealth,
        EntityType::SpecialBelief,
        EntityType::SpecialEthnicity,
        EntityType::SpecialSexLife,
        EntityType::SpecialMembership,
        EntityType::SpecialCriminal,
        EntityType::SpecialAttire,
        EntityType::SpecialPolitical,
    ] {
        assert_eq!(
            kinds.iter().filter(|&&k| k == kind).count(),
            1,
            "{kind}: {kinds:?}"
        );
    }
}

/// A newline-free line long enough for intra-line emission, with findings
/// of every path around the emission points.
fn long_line() -> String {
    let mut s = String::new();
    for i in 0..8 {
        s.push_str("uzun bir satir yazilir ve akis devam eder, ");
        match i % 4 {
            0 => s.push_str("Hastanın bilinen tanısı esansiyel hipertansiyon olarak kaydedildi; "),
            1 => s.push_str("| Kan grubu: AB Rh+ | Tanı: Tip 2 diyabet | "),
            2 => s.push_str("ben de diyabet nedeniyle metformin 1000 mg kullanıyorum ve "),
            _ => s.push_str("kan grubum 0 Rh- ve NURAY ÇAKIR KANSER TEDAVİSİ GÖRÜYOR, "),
        }
    }
    s
}

#[test]
fn stream_equals_batch_at_every_split() {
    let text = long_line();
    let target = GuardTarget::UserPrompt;
    let batch = sanitize(&text, &target);
    assert!(batch.text.contains("[SPECIAL_HEALTH"), "{}", batch.text);
    for i in (0..=text.len()).filter(|&i| text.is_char_boundary(i)) {
        let mut sg = StreamingGuard::new(target);
        let mut out = String::new();
        let events = sg
            .push(&text[..i])
            .into_iter()
            .chain(sg.push(&text[i..]))
            .chain(sg.finish());
        for ev in events {
            if let GuardEvent::Segment { text, .. } = ev {
                out.push_str(&text);
            }
        }
        assert_eq!(out, batch.text, "split at {i}");
    }
}

#[test]
fn long_hostile_lines_finish() {
    let tr = ["tr"];
    let d = Detector::new().with_locales(&tr);
    for unit in [
        "diyabet ",
        "Tanı: x ",
        "ben ",
        "kan grubu A Rh+ ",
        "kan grubum A Rh+ ",
        "ü:",
        "Partisi ",
        "Diyabetim ",
        "KANSER ",
        "NURAY ÇAKIR KANSER ",
    ] {
        let text = unit.repeat(200_000 / unit.len());
        let started = std::time::Instant::now();
        let _ = d.detect(&text);
        assert!(started.elapsed().as_secs() < 30, "{unit:?} took too long");
    }
}
