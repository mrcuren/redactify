//! Custom entity labels: a custom rule reports and masks its own label
//! (`[EMPLOYEE_ID]`) instead of borrowing the closest built-in type.

use redactify::{CustomLabelError, CustomRule, Detector, EntityType};

#[test]
fn a_custom_rule_masks_with_its_own_label() {
    let employee = EntityType::custom("EMPLOYEE_ID").expect("label");
    assert_eq!(employee.as_str(), "EMPLOYEE_ID");
    let rule = CustomRule::new(employee, r"\bE\d{6}\b").expect("pattern");
    let rules = [&rule];
    let d = Detector::new().with_custom_rules(&rules);
    assert_eq!(
        d.redact("personel E123456 izinde"),
        "personel [EMPLOYEE_ID] izinde"
    );
    assert_eq!(d.detect("personel E123456")[0].kind, employee);
}

#[test]
fn the_same_label_is_the_same_type() {
    let a = EntityType::custom("PROJECT_CODE").expect("label");
    let b = EntityType::custom("PROJECT_CODE").expect("label");
    assert_eq!(a, b);
    assert_eq!("PROJECT_CODE".parse::<EntityType>(), Ok(a));
}

#[test]
fn labels_follow_the_built_in_label_shape() {
    // uppercase ASCII letters, digits and `_`, starting with a letter
    for bad in ["", "employee_id", "1ABC", "A-B", "A B", "\u{130}D", "_X"] {
        assert_eq!(
            EntityType::custom(bad),
            Err(CustomLabelError::InvalidLabel),
            "{bad:?}"
        );
    }
    let too_long = "A".repeat(redactify::MAX_CUSTOM_LABEL_LEN + 1);
    assert_eq!(
        EntityType::custom(&too_long),
        Err(CustomLabelError::InvalidLabel)
    );
    assert!(EntityType::custom(&"A".repeat(redactify::MAX_CUSTOM_LABEL_LEN)).is_ok());
}

#[test]
fn a_built_in_label_cannot_be_reused() {
    assert_eq!(EntityType::custom("TCKN"), Err(CustomLabelError::BuiltIn));
    assert_eq!(
        EntityType::custom("CREDIT_CARD"),
        Err(CustomLabelError::BuiltIn)
    );
}

#[test]
fn parsing_never_registers_a_new_label() {
    assert!("NEVER_REGISTERED_LABEL_XYZ".parse::<EntityType>().is_err());
}

#[test]
fn checksummed_built_ins_outrank_a_custom_label_on_the_same_span() {
    let custom = EntityType::custom("INTERNAL_NUMBER").expect("label");
    let rule = CustomRule::new(custom, r"\b\d{11}\b").expect("pattern");
    let rules = [&rule];
    let d = Detector::new().with_custom_rules(&rules);
    // a valid TCKN keeps its checksummed type; another 11-digit run is custom
    assert_eq!(d.detect("no 12345678950")[0].kind, EntityType::Tckn);
    assert_eq!(d.detect("no 12345678951")[0].kind, custom);
}

#[test]
fn vault_placeholders_use_the_custom_label() {
    let ticket = EntityType::custom("TICKET_ID").expect("label");
    let rule = CustomRule::new(ticket, r"\bT-\d{4}\b").expect("pattern");
    let rules = [&rule];
    let (anon, vault) = Detector::new()
        .with_custom_rules(&rules)
        .pseudonymize("bkz T-1234");
    assert_eq!(anon, "bkz [TICKET_ID_1]");
    assert_eq!(vault.restore(&anon), "bkz T-1234");
}

#[cfg(feature = "serde")]
#[test]
fn serde_uses_the_label_and_never_registers_from_input() {
    let ticket = EntityType::custom("SERDE_TICKET").expect("label");
    assert_eq!(serde_json::to_string(&ticket).unwrap(), "\"SERDE_TICKET\"");
    let back: EntityType = serde_json::from_str("\"SERDE_TICKET\"").unwrap();
    assert_eq!(back, ticket);
    assert!(serde_json::from_str::<EntityType>("\"UNREGISTERED_FROM_JSON\"").is_err());
    // built-in labels keep their canonical spelling
    assert_eq!(
        serde_json::to_string(&EntityType::Pesel).unwrap(),
        "\"PL_PESEL\""
    );
}
