//! Executable URL schemes in model output: `javascript:` and `vbscript:`,
//! including the spellings a browser still runs: ASCII tab / newline
//! inside the scheme (the URL parser strips them) and character
//! references (`&#106;`, `&colon;`, `&Tab;`, `&NewLine;`).

use redactify::guard::xss_risk;
use redactify::policy::{GuardAction, GuardTarget};
use redactify::Guard;

fn decision(text: &str, target: GuardTarget) -> GuardAction {
    Guard::new(target).decide(text).action
}

#[test]
fn script_schemes_are_blocked_in_every_spelling() {
    for text in [
        "[x](vbscript:msgbox(1))",
        "see VBScript:msgbox(1)",
        "[x](java\tscript:alert(1))",
        "[x](java\nscript:alert(1))",
        "[x](java\rscript:alert(1))",
        "[x](jav\tascri\npt:alert(1))",
        "[x](vb\tscript:msgbox(1))",
        r#"<a href="jav&#x09;ascript:alert(1)">x</a>"#,
        "[x](javascript&colon;alert(1))",
        "[x](&#106;avascript:alert(1))",
        "[x](java&Tab;script:alert(1))",
        "[x](java&NewLine;script:alert(1))",
        "[x](&#118;bscript:msgbox(1))",
    ] {
        for target in [GuardTarget::ModelOutput, GuardTarget::UserPrompt] {
            assert_eq!(
                decision(text, target),
                GuardAction::Block,
                "{text:?} as {target:?}"
            );
        }
    }
}

#[test]
fn xss_rule_reports_the_split_and_vb_schemes() {
    for text in [
        "java\tscript:alert(1)",
        "vbscript:x",
        "j\na\tv\ra\ns\tc\nr\ti\np\tt:x",
    ] {
        let s = xss_risk(text);
        assert!(s.is_some_and(|s| s.score >= 0.9), "{text:?}");
    }
}

#[test]
fn ordinary_text_and_escaped_markup_stay_clean() {
    for text in [
        "The answer is 42.",
        "see [docs](https://example.com/javascript-tutorial)",
        "java script is a phrase, not a scheme",
        "visual basic script editors",
        "javascript is a language",
        "&lt;b&gt;bold&lt;/b&gt; and AT&amp;T",
        "time: 10&colon;30 is not a scheme",
    ] {
        assert_ne!(
            decision(text, GuardTarget::ModelOutput),
            GuardAction::Block,
            "{text:?}"
        );
    }
}

#[test]
fn existing_javascript_and_data_detection_is_unchanged() {
    assert_eq!(
        decision("[x](javascript:alert(1))", GuardTarget::ModelOutput),
        GuardAction::Block
    );
    assert_eq!(
        decision("[x](  JaVaScRiPt:alert(1))", GuardTarget::ModelOutput),
        GuardAction::Block
    );
    assert_eq!(
        decision(
            "[x](data:text/html;base64,PHNjcmlwdD4=)",
            GuardTarget::ModelOutput
        ),
        GuardAction::Block
    );
}
