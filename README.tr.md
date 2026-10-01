# redactify (Türkçe)

> Bu dosya README.md'nin Türkçe sürümüdür. İngilizce (birincil) dokümantasyon:
> [README.md](README.md)

**Checksum doğrulamalı PII tespit & maskeleme** - yapılandırılmış tanımlayıcılar için.

v0.3, **Türk tanımlayıcı setiyle** gelir - TCKN, TR-IBAN, VKN (vergi no), pasaport
numarası, araç plakası, telefon (mobil + sabit hat), kredi kartı, e-posta. Mimari
(desen + checksum doğrulayıcı + öncelik + güven skoru) ülke-bağımsızdır; diğer
ülkelerin tanımlayıcılarına genişletmek için tasarlandı.

## Neden checksum?

Yapılandırılmış tanımlayıcılar matematik taşır: TCKN 11 hane + iki kontrol basamağı,
VKN kendi checksum'ı, IBAN mod-97, plaka 81 il kodu. Çıplak bir 11 haneli sayıyı
"TCKN" sanmak yanlış-pozitif seli üretir; **checksum'ı doğrulamak maskelemeyi
hassaslaştırır**. Rastgele bir sipariş numarası asla TCKN sanılmaz - gerçek biri de
asla kaçmaz.

## Kurulum

```toml
[dependencies]
redactify = "0.3.0"
```

Minimal, denetlenebilir bağımlılıklar. Model yok, ağ yok. MSRV: **1.80**.

## Hızlı başlangıç

```rust
use redactify::{detect, redact, detect_with_threshold, EntityType};

// Maskeleme:
assert_eq!(
    redact("TCKN'm 12345678950, IBAN TR33 0006 1005 1978 6457 8413 26, mail a@b.com"),
    "TCKN'm [TCKN], IBAN [IBAN], mail [EMAIL]"
);

// Checksum geçmeyen sipariş numarası DEĞİŞMEZ (hassasiyet):
assert_eq!(
    redact("Sipariş numaranız 12000345671 olarak kaydedildi."),
    "Sipariş numaranız 12000345671 olarak kaydedildi."
);

// Tipli span'lar (byte offset + güven skoru):
let ents = detect("Plakası 34-ABC-123, TCKN 12345678950");
assert_eq!(ents[0].kind, EntityType::Plaka);
assert_eq!(ents[0].score, 0.95);  // yakında "plaka" ipucu
assert_eq!(ents[1].score, 1.0);   // checksum doğrulandı → kesin
```

### Guardrails L0 tohumu - girdi normalizasyonu

v0.3, guardrails katmanının ilk taşını ekler:
NFKC normalizasyonu (homoglyph/tam-genişlik atlatması), görünmez-karakter temizliği
ve base64 şüpheli çözümü:

```rust
use redactify::normalize::normalize_for_scan;
let dirty = "kimlik ＴＣＫＮ １２３４５６７８９５０"; // tam-genişlik rakamlar
assert!(redactify::detect(dirty).is_empty());
assert!(redactify::detect(&normalize_for_scan(dirty))
    .iter().any(|e| e.kind == redactify::EntityType::Tckn));
```

### Deterministik guard kuralları ve politika (OWASP LLM05 savunmaları)

`guard`, model gerektirmeden bilinen tehlike kalıplarını tarar: SQL enjeksiyon
imzaları, XSS/HTML enjeksiyonu, SSRF riskli URL'ler (bulut metadata ucu, RFC1918
aralıkları, localhost, `file:`), karakter-bölme hilesi ve base64 içine gizlenmiş
PII. `policy`, sinyalleri ve PII bulgularını gerekçeli karara çevirir:

```rust
use redactify::policy::{guard_all, GuardAction};

assert_eq!(guard_all("http://10.0.0.5/admin").action, GuardAction::Block);
assert_eq!(guard_all("TCKN 12345678950").action, GuardAction::Mask);
assert_eq!(guard_all("merhaba dunya").action, GuardAction::Allow);
```

Her karar, insan tarafından okunabilir bir `rationale` taşır (hangi kural, hangi
skor, hangi eşik). URL sınıflandırması asla DNS çözümlemez: yalnızca literal
adresler değerlendirilir, hostname'ler hakkında varsayım yapılmaz.

### CLI

```text
redactify "TCKN 12345678950, vergi no 1234567890"   # argümandan
cat belge.txt | redactify                           # stdin'den (UTF-8)
```

## Tespit modeli

| Varlık | Doğrulama | Skor | Not |
|---|---|---|---|
| `TCKN` | 11 hane, 2 kontrol basamağı (NVI) | **1.0** | ilk hane ≠ 0 |
| `IBAN` | ISO-13616 mod-97 | **1.0** | TR + 24 hane |
| `VKN` | 10 hane, tek kontrol basamağı | **1.0** | **bağlam ipucu şart** (±18 karakterte `vergi`/`VKN`/`tax`) |
| `CREDIT_CARD` | Luhn, ≥ 13 hane | **1.0** | boşluk/tire ayraçlı |
| `PASSPORT` | `U` + 8 hane (biyometrik) | **0.90** | checksum yok → yakın `pasaport` ipucu **şart** |
| `PLAKA` | il 01-81 + plaka alfabesi | **0.85 → 0.95** (ipucuyla) | `[A-PR-VY-Z]` (Q/W/X yok), seri 2-4 hane, boşluk/tire |
| `EMAIL` | katı regex | **0.85** | |
| `PHONE` | yapısal desen | **0.80** | mobil `5xx`; sabit hat - alan kodu sonrası ayraç zorunlu |

**Çakışma önceliği:** IBAN > CREDIT_CARD > PLAKA > TCKN > EMAIL > PHONE > PASSPORT > VKN.

**Tarama satır-bazlıdır** (ReDoS azaltımı).

## Doğrulama (bu repoda fiilen koşuldu)

| Kapı | Sonuç |
|---|---|
| `fmt` + `clippy -D warnings` | ✅ temiz |
| `cargo test` | ✅ **70 test** |
| Korpus (155 satır: 140 gold + 15 distractor) | ✅ **140/140**, **0 FP** |
| Diferansiyel referans seti (`examples/parity.rs`) | ✅ **184/184** bayt-bayt özdeş |
| İşleme hızı (185 metin, süreç-içi) | ~**57 ms** |

## Dürüst limitler

- Checksum'lar yanlış-pozitifleri keser; **gerçek dünya recall'ı garanti etmez**.
- VKN/pasaport bağlam kuralları recall'dan fedakârlık yapar (bilinçli).
- Parantezli telefon biçimleri kapsam dışı.
- İsim/adres checksum içermez → kapsam dışı. Bu bir **tanımlayıcı redaktör**dür; tam
  anonimleştirici ve KVKK/GDPR uyum garantisi değildir.

## Katkı ve lisans

Katkı: [CONTRIBUTING.md](CONTRIBUTING.md) · Davranış: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) ·
Güvenlik: [SECURITY.md](SECURITY.md)

Apache-2.0 - [LICENSE](LICENSE), [NOTICE](NOTICE).
