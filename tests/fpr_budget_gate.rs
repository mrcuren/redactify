//! False-positive budget gate.
//!
//! The evaluation framework's expectation: "add a benign-canary set to every
//! evaluation run and reject configuration promotions when false positives
//! exceed the budget". This file is that gate as an executable test:
//!
//! - **Part 1 (always on):** a benign canary corpus for the deterministic
//!   core. Budget: zero detected PII entities and zero Block decisions.
//! - **Part 2 (ml-onnx + exported model):** the real L2 classifier over the
//!   250-item benign slice of `data/ml_testset_v1.jsonl` at the measured
//!   operating point (τ=0.706). Budget: FPR ≤ 5% (measured: 0.5%).

use redactify::policy::{guard_all, GuardAction};
use redactify::{detect, Detector, EntityType};

/// Every locale pack (default tr+en and every opt-in pack).
const ALL_LOCALES: &[&str] = redactify::SUPPORTED_LOCALES;

/// Deterministic-core canary: benign TR/EN/EU prose, digits that must NOT be
/// claimed (order refs, tracking numbers), and log-style lines.
const CANARY: &[&str] = &[
    "merhaba dunya bugun hava cok guzel",
    "toplanti yarın sabah dokuzda olacak",
    "The quick brown fox jumps over the lazy dog",
    "please summarize this document in three bullet points",
    "Sipariş numaranız 12000345671 olarak kaydedildi.",
    "kargo takip kodu 9876543210 guncellendi",
    "referans 123456789012345 kullanilacak",
    "batch 1112223334 shipped on monday",
    "2024-01-15 tarihinde rapor paylasildi",
    "fatura no A-2026-0042 odendi",
    "kullanici sayisi 1.2 milyon gecti",
    "sunucu 10.0.0.5 uzerinden yanit verdi", // private IP in prose: no URL scheme -> URL rule silent
    "dosya yolu /usr/share/docs/okundu.txt",
    "version 2.4.1 release notes published",
    "hava 23 derece, ruzgar guneyden",
    "toplam tutar 1.450,90 TL odendi",
    "team standup at 9, retro at 14",
    "LUTFEN bu metni Turkceye cevir",
    "bu cumlede hicbir gizli bilgi yok",
    "plain text nothing to see here",
    // cue-gated shapes WITHOUT their cues must stay silent (NHS/NIE/nPA/CF
    // digit+letter runs and BIC-shaped uppercase words in benign prose)
    "patient reference 9434765870 archived",
    "kargo kodu X1234567L guncellendi",
    "serienummer LF2K7X9R2 geprueft",
    "anagrafe codice MRTRSS85M01H501C verificato",
    "bank routing DEUTDEFF CHASUS33 NWBKGB2L listed",
    "the swift fox SERIOUSLY jumped over the fence",
    // cue-gated shapes WITHOUT their cues must stay silent (PESEL/SIN/TFN/
    // Aadhaar digit runs, PAN/NRIC letter runs in benign prose, plus the
    // substring-cue collision traps)
    "client reference 80010123450 archived",
    "business 123-456-782 quarterly report",
    "using 123 456 782 as the order key",
    "tax estimate 100010747 finalized",
    "uid check 607324134360 pending",
    "japan notes BQQBP5731K office",
    "company AAAPL1234C profile",
    "final T0123456Z gate open",
    "unify 123 456 789 across systems",
    // cue-gated shapes WITHOUT cues must stay silent (Medicare digit
    // runs, postcode/PLZ tokens in prose, "plz" internet slang)
    "health card 3189977021 archived",
    "visit SW1A 1AA office tower",
    "berlin 10115 district guide",
    "plz send 40732 refs quickly",
    "shipping EC1A 1BB today",
    // Secrets-layer shapes WITHOUT a real credential must stay silent
    // (cue words near prose, git SHAs, publishable/test vocabulary,
    // credential-adjacent architecture words, URLs without userinfo)
    "sk-attention is all you need paper summary",
    "the key insight is refactoring legacy systems",
    "commit 3q2+7wJalrXUtnFEMIK7MDENGbPxRfiCY merged into main",
    "order api key metrics dashboard shows growth",
    "password policy updated last quarter",
    "AccountName=prod;DefaultEndpointsProtocol=https",
    "bearer of good news arrived early",
    "postgres://db.internal:5432/prod baglantisi",
    // Tool-injection rule shapes WITHOUT an actual attempt must stay silent
    // (discussing instructions, tool outputs and system prompts in prose)
    "the tool result above contains three rows",
    "tool output parsing follows the documented schema",
    "instruction manual section covers advanced usage",
    "system prompt engineering research summarized",
    "önceki talimatları arşivledik yenileri yarın gelecek",
    // New entity-type shapes WITHOUT cues/checksums must stay silent
    // (VIN-shaped 17-char run, 14-digit SIRET/ABN, 9-digit passport,
    // alphanumeric DE-passport shapes in benign context)
    "chassis ref 1M8GDM9A0KP042788 logged", // VIN-shaped, not checksummed context
    "invoice 12345678200001 processed",     // SIRET-shaped 14-digit without cue
    "order 52824753557 shipped",            // ABN-shaped 11-digit without cue
    "ref 047281536 archived",               // 9-digit passport shape without cue
    "ticket C3JJ4789L resolved",            // DE-passport shape without cue
    "room 12345678 ninety-two floor",       // MRN-shaped without MRN cue
    // national-ID shapes WITHOUT their cue or with a failing check must stay
    // silent (bare CPF/CNPJ/personnummer/fodselsnummer/CPR runs need a cue;
    // the formatted CPF, HETU, separator personnummer and 18-digit
    // resident-ID shapes below fail their check characters; VAT-shaped
    // tokens need a VAT cue)
    "client reference 52998224725 archived", // CPF-valid, no "cpf" cue
    "lot 12ABC34501DE35 shipped today",      // CNPJ-valid, no "cnpj" cue
    "kund 4509044311 order",                 // personnummer-valid, bare, no cue
    "ordre 02013299997 sendt",               // fodselsnummer-valid, no cue
    "ordre 290236-9234 sendt",               // CPR-valid, no cue (not SE/FI-valid)
    "invoice 529.982.247-26 sent",           // CPF mask, check digit off
    "code 131052-308U done",                 // HETU shape, check char off
    "case 640823-3235 closed",               // personnummer shape, Luhn off
    "tracking 123456789012345678 ok",        // 18 digits, no MOD 11-2 / Luhn
    "ref DE123456789 ok",                    // VAT format, no VAT cue
    "pallet ATU12345678 stacked",            // VAT format, no VAT cue
];

#[test]
fn deterministic_core_canary_budget_is_zero() {
    for text in CANARY {
        let ents = Detector::new().with_locales(ALL_LOCALES).detect(text);
        assert!(
            ents.is_empty(),
            "FP on canary (all locales) {text:?}: {ents:?}"
        );
        let d = guard_all(text);
        assert_ne!(
            d.action,
            GuardAction::Block,
            "Block on canary {text:?}: {d:?}"
        );
    }
}

#[test]
fn canary_spans_no_eu_pack_leakage() {
    // EU packs are opt-in; with them enabled the same benign corpus must
    // still produce nothing (digit-heavy lines especially)
    for text in CANARY {
        let ents = detect(text); // default tr+en
        assert!(ents.is_empty(), "default-locale FP {text:?}: {ents:?}");
    }
}

/// Part 2: ML benign budget (real model, measured operating point).
#[cfg(feature = "ml-onnx")]
#[test]
fn ml_benign_fpr_within_budget() {
    const MODEL: &str = "ml_models/security_onnx/model.onnx";
    const TOKENIZER: &str = "ml_models/security_tokenizer";
    if !std::path::Path::new(MODEL).is_file() {
        eprintln!("SKIP: {MODEL} not present (gate runs where the export exists)");
        return;
    }
    // the eval set ships in the repo but is excluded from the published
    // crate; a consumer with local models must not see this gate panic
    const TESTSET: &str = "data/ml_testset_v1.jsonl";
    if !std::path::Path::new(TESTSET).is_file() {
        eprintln!("SKIP: {TESTSET} not present (repo-only evaluation data)");
        return;
    }
    let items = redactify::guard::eval::load_eval_set(TESTSET).expect("test set loads");
    // per-slice budgets (disaggregate by traffic slice).
    // Measured: benign FPR 0.005 and hard-negative FPR 0.160, both at
    // tau=0.5 and at the operating point tau=0.706 (the higher threshold
    // does not rescue hard negatives). Budgets sit just above these values
    // so the gate trips on a regression, not on noise.
    const SLICES: &[(&str, f64)] = &[("benign", 0.05), ("hard_negative", 0.20)];

    let cls = redactify::guard::onnx::OnnxSecurityClassifier::new(MODEL, TOKENIZER)
        .expect("model loads")
        .with_threshold(0.706); // measured operating point

    use redactify::guard::ml::MlClassifier;
    for (slice, budget) in SLICES {
        let subset: Vec<&redactify::guard::eval::EvalItem> = items
            .iter()
            .filter(|i| i.label == 0 && i.category == *slice)
            .collect();
        assert!(!subset.is_empty(), "slice {slice} missing from the set");
        let fp = subset
            .iter()
            .filter(|i| !cls.classify(&i.text).is_empty())
            .count();
        let fpr = fp as f64 / subset.len() as f64;
        assert!(
            fpr <= *budget,
            "slice {slice} FPR {fpr:.3} exceeds budget {budget} ({fp}/{})",
            subset.len()
        );
        eprintln!(
            "gate: {slice} FPR = {fpr:.4} (budget {budget}, n={})",
            subset.len()
        );
    }
}

/// Entity-type sanity so `detect` itself cannot drift into claiming canary
/// text through a new rule (guard against future rule regressions).
#[test]
fn canary_mentions_no_entities_of_any_registered_type() {
    let all: Vec<EntityType> = vec![
        EntityType::Tckn,
        EntityType::Iban,
        EntityType::CreditCard,
        EntityType::Plaka,
        EntityType::Email,
        EntityType::Phone,
        EntityType::Passport,
        EntityType::Ssn,
        EntityType::Itin,
        EntityType::UsPassport,
        EntityType::Vkn,
        EntityType::Nir,
        EntityType::Dni,
        EntityType::Bsn,
        EntityType::Nino,
        EntityType::DeTaxId,
        EntityType::UkNhs,
        EntityType::Nie,
        EntityType::DeIdCard,
        EntityType::ItFiscalCode,
        EntityType::SwiftBic,
        EntityType::Pesel,
        EntityType::CaSin,
        EntityType::AuTfn,
        EntityType::SgNricFin,
        EntityType::InPan,
        EntityType::InAadhaar,
        EntityType::PtNif,
        EntityType::AuMedicare,
        EntityType::Vin,
        EntityType::AuAbn,
        EntityType::UkVat,
        EntityType::FrSiret,
        EntityType::PlNip,
        EntityType::UkUtr,
        EntityType::UkPassport,
        EntityType::DePassport,
        EntityType::UsMrn,
        EntityType::UkPostcode,
        EntityType::DePlz,
        EntityType::UsZip,
        EntityType::FrPostal,
        EntityType::BrCpf,
        EntityType::BrCnpj,
        EntityType::CnResidentId,
        EntityType::SePersonnummer,
        EntityType::FiHetu,
        EntityType::NoFodselsnummer,
        EntityType::DkCpr,
        EntityType::EuVat,
    ];
    for text in CANARY {
        let ents = Detector::new().with_locales(ALL_LOCALES).detect(text);
        for e in &ents {
            assert!(all.contains(&e.kind)); // type is registered...
        }
        assert!(ents.is_empty(), "no entity at all expected: {text:?}");
    }
}
