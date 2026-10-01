//! Quick-start example - `cargo run --example quickstart`

fn main() {
    let metin = "Merhaba, ben Ayşe. TCKN'm 12345678950. \
Maaşımı TR33 0006 1005 1978 6457 8413 26 IBAN'ıma yatırabilirsiniz. \
Firmamızın vergi numarası 1234567890. \
Bana 0532 123 45 67 numaralı telefondan veya ayse@ornek.com.tr adresinden ulaşın. \
Aracımın plakası 34 ABC 123. Kartım 4111 1111 1111 1111.\n\n\
NOT: Sipariş numaranız 12000345671 - bu bir TCKN DEĞİL (checksum tutmuyor), maskelenmemeli.";

    println!("=== DETECTIONS ===");
    for e in redactify::detect(metin) {
        println!("{:<13} [{}..{}] {}", e.kind, e.start, e.end, e.text);
    }

    println!("\n=== MASKED ===");
    println!("{}", redactify::redact(metin));
}
