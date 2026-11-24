//! End-to-end ONNX inference verification against hand-built fixtures.
//!
//! No network, no 537MB model: this test encodes minimal-but-valid ONNX
//! protobuf models and a WordPiece `tokenizer.json` at test time, then runs
//! the REAL `ort` inference path through the public classifiers. The two
//! core fixtures:
//!
//! - **constant model** (logits `[0.2, 3.0]`): proves session loading,
//!   declared-input wiring, warmup validation, output extraction and the
//!   softmax math.
//! - **input-dependent model** (`logits = cast(reduce_sum(input_ids +
//!   attention_mask))`): proves the token tensors we build actually REACH
//!   the graph - different texts must yield different scores.
//!
//! Field numbers below are the ONNX protobuf definitions (onnx.proto):
//! ModelProto{ir_version=1, graph=7, opset_import=8},
//! GraphProto{node=1, name=2, input=11, output=12},
//! NodeProto{input=1, output=2, name=3, op_type=4, attribute=5},
//! AttributeProto{name=1, i=3, t=5, ints=8, type=20; INT=2, TENSOR=4, INTS=7},
//! ValueInfoProto{name=1, type=2}, TypeProto{tensor_type=1},
//! TypeProto.Tensor{elem_type=1}, TensorProto{dims=1, data_type=2,
//! float_data=4}. Element types: FLOAT=1, INT64=7.
#![cfg(feature = "ml-onnx")]

use std::time::Duration;

use redactify::guard::ml::{FailMode, MlClassifier, MlHealth};
use redactify::guard::onnx::{OnnxCategoricalClassifier, OnnxSecurityClassifier};
use redactify::policy::GuardCategory;

// ------------------------------------------------------------ protobuf

fn varint(mut n: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let b = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(b);
            return out;
        }
        out.push(b | 0x80);
    }
}

fn key(field: u32, wire: u32) -> Vec<u8> {
    varint(u64::from(field << 3 | wire))
}

/// length-delimited field
fn ld(field: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = key(field, 2);
    out.extend(varint(payload.len() as u64));
    out.extend_from_slice(payload);
    out
}

/// varint field
fn vint(field: u32, v: u64) -> Vec<u8> {
    let mut out = key(field, 0);
    out.extend(varint(v));
    out
}

fn str_field(field: u32, s: &str) -> Vec<u8> {
    ld(field, s.as_bytes())
}

fn packed_f32(field: u32, vals: &[f32]) -> Vec<u8> {
    let mut p = Vec::new();
    for v in vals {
        p.extend_from_slice(&v.to_le_bytes());
    }
    ld(field, &p)
}

fn packed_varints(field: u32, vals: &[u64]) -> Vec<u8> {
    let mut p = Vec::new();
    for v in vals {
        p.extend(varint(*v));
    }
    ld(field, &p)
}

// ------------------------------------------------------------ onnx pieces

/// TensorProto{dims, FLOAT data}
fn tensor_f32(dims: &[u64], floats: &[f32]) -> Vec<u8> {
    let mut t = packed_varints(1, dims);
    t.extend(vint(2, 1)); // data_type FLOAT
    t.extend(packed_f32(4, floats));
    t
}

/// ValueInfoProto with a tensor type of `elem_type` and unknown shape.
fn value_info(name: &str, elem_type: u64) -> Vec<u8> {
    let tensor = vint(1, elem_type); // Tensor.elem_type
    let ttype = ld(1, &tensor); // TypeProto.tensor_type
    let mut vi = str_field(1, name);
    vi.extend(ld(2, &ttype));
    vi
}

/// AttributeProto{name, INT}
fn attr_int(name: &str, v: u64) -> Vec<u8> {
    let mut a = str_field(1, name);
    a.extend(vint(20, 2)); // type INT
    a.extend(vint(3, v));
    a
}

/// AttributeProto{name, TENSOR}
fn attr_tensor(name: &str, t: &[u8]) -> Vec<u8> {
    let mut a = str_field(1, name);
    a.extend(vint(20, 4)); // type TENSOR
    a.extend(ld(5, t));
    a
}

fn node(idx: usize, op: &str, inputs: &[&str], outputs: &[&str], attrs: &[&[u8]]) -> Vec<u8> {
    let mut n = Vec::new();
    for i in inputs {
        n.extend(str_field(1, i));
    }
    for o in outputs {
        n.extend(str_field(2, o));
    }
    n.extend(str_field(3, &format!("n{idx}")));
    n.extend(str_field(4, op));
    for a in attrs {
        n.extend(ld(5, a));
    }
    n
}

fn model(nodes: &[Vec<u8>], outputs: &[(&str, u64)]) -> Vec<u8> {
    let mut g = Vec::new();
    for n in nodes {
        g.extend(ld(1, n));
    }
    g.extend(str_field(2, "fixture-graph"));
    // declared-but-unconsumed graph inputs are legal ONNX; our classifiers
    // read exactly these names when deciding what to feed
    g.extend(ld(11, &value_info("input_ids", 7)));
    g.extend(ld(11, &value_info("attention_mask", 7)));
    for (name, elem) in outputs {
        g.extend(ld(12, &value_info(name, *elem)));
    }

    let opset = {
        let mut o = str_field(1, ""); // domain ""
        o.extend(vint(2, 13)); // since 13: ReduceSum still takes `axes` as attribute
        o
    };

    let mut m = vint(1, 9); // ir_version
    m.extend(ld(7, &g));
    m.extend(ld(8, &opset));
    m
}

/// Model A: constant `logits = [0.2, 3.0]` regardless of input.
fn constant_model() -> Vec<u8> {
    let t = tensor_f32(&[1, 2], &[0.2, 3.0]);
    let n = node(
        0,
        "Constant",
        &[],
        &["logits"],
        &[&attr_tensor("value", &t)],
    );
    model(&[n], &[("logits", 1)])
}

/// Model B: `logits[0] = float(sum(all(input_ids + attention_mask)))`.
fn input_dependent_model() -> Vec<u8> {
    let n1 = node(0, "Add", &["input_ids", "attention_mask"], &["sum"], &[]);
    // opset 13 ReduceSum takes `axes` as an input, not an attribute; omitting
    // it reduces ALL dims (keepdims=1 -> shape [1,1])
    let n2 = node(
        1,
        "ReduceSum",
        &["sum"],
        &["red"],
        &[&attr_int("keepdims", 1)],
    );
    let n3 = node(2, "Cast", &["red"], &["logits"], &[&attr_int("to", 1)]); // to=FLOAT
    model(&[n1, n2, n3], &[("logits", 1)])
}

// ------------------------------------------------------------ tokenizer

const TOKENIZER_JSON: &str = r###"{
  "version": "1.0",
  "truncation": null,
  "padding": null,
  "added_tokens": [],
  "normalizer": {
    "type": "BertNormalizer",
    "clean_text": true,
    "handle_chinese_chars": true,
    "strip_accents": null,
    "lowercase": true
  },
  "pre_tokenizer": { "type": "BertPreTokenizer" },
  "post_processor": null,
  "decoder": null,
  "model": {
    "type": "WordPiece",
    "unk_token": "[UNK]",
    "continuing_subword_prefix": "##",
    "max_input_chars_per_word": 100,
    "vocab": {
      "[PAD]": 0, "[UNK]": 1, "[CLS]": 2, "[SEP]": 3,
      "warmup": 4, "hello": 5, "world": 6, "a": 7, "bb": 8, "ccc": 9
    }
  }
}"###;

/// Writes both fixtures into a unique temp dir; returns (model_path, tokenizer_path).
///
/// The dir is unique per CALL (name + pid + a process-wide sequence number):
/// several tests reuse the same fixture `name` and run on parallel threads -
/// a shared path would let one test's `cleanup` delete the files another
/// test is loading (a flaky race, observed before the sequence counter).
fn write_fixtures(name: &str, model: &[u8]) -> (std::path::PathBuf, std::path::PathBuf) {
    use std::sync::atomic::{AtomicU32, Ordering};
    static FIXTURE_SEQ: AtomicU32 = AtomicU32::new(0);
    let seq = FIXTURE_SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "redactify-onnx-fixture-{}-{}-{}",
        name,
        std::process::id(),
        seq
    ));
    std::fs::create_dir_all(&dir).expect("fixture dir");
    let model_path = dir.join("model.onnx");
    let tok_dir = dir.join("tokenizer");
    std::fs::create_dir_all(&tok_dir).expect("tokenizer dir");
    std::fs::write(&model_path, model).expect("model written");
    std::fs::write(tok_dir.join("tokenizer.json"), TOKENIZER_JSON).expect("tokenizer written");
    (model_path, tok_dir)
}

fn cleanup(path: &std::path::Path) {
    if let Some(dir) = path.parent() {
        let _ = std::fs::remove_dir_all(dir);
    }
}

// ------------------------------------------------------------ tests

#[test]
fn constant_model_full_pipeline() {
    let (model_path, tok_dir) = write_fixtures("constant", &constant_model());
    let cls = OnnxSecurityClassifier::new(model_path.to_str().unwrap(), tok_dir.to_str().unwrap())
        .expect("fixture model loads (warmup included)");

    // softmax([0.2, 3.0]) with positive = last -> 1/(1+e^-2.8) ≈ 0.9427
    let s = cls.score("hello").expect("score");
    assert!((s - 0.9427).abs() < 1e-3, "score was {s}");
    // deterministic
    let s2 = cls.score("hello").expect("score 2");
    assert_eq!(s, s2);
    // classify() emits above the default 0.5 threshold
    let out = cls.classify("hello");
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].0, GuardCategory::Jailbreak); // default positive category
    assert!((out[0].1 - s).abs() < 1e-6);

    cleanup(&model_path);
}

#[test]
fn positive_index_override_flips_score() {
    // citizenlab-style model: id2label = {0: attack, 1: benign} -> positive
    // class is index 0, not the last
    let (model_path, tok_dir) = write_fixtures("posidx", &constant_model());
    let cls = OnnxSecurityClassifier::new(model_path.to_str().unwrap(), tok_dir.to_str().unwrap())
        .unwrap();
    // default (positive = last): softmax([0.2, 3.0]) ~ 0.943
    let s_default = cls.score("hello").unwrap();
    assert!((s_default - 0.9427).abs() < 1e-3);
    // index 0: ~0.057
    let s_first = cls.with_positive_index(0).score("hello").unwrap();
    assert!((s_first - 0.0573).abs() < 1e-3, "got {s_first}");
    assert!((s_default + s_first - 1.0).abs() < 1e-6);
    cleanup(&model_path);
}

#[test]
fn input_dependent_model_proves_tensor_flow() {
    let (model_path, tok_dir) = write_fixtures("dependent", &input_dependent_model());
    let cls = OnnxSecurityClassifier::new(model_path.to_str().unwrap(), tok_dir.to_str().unwrap())
        .expect("fixture model loads");

    // "hello" -> id 5, one token, mask 1 -> logits[0] = 5 + 1 = 6 -> sigmoid(6)
    let s_hello = cls.score("hello").expect("score hello");
    assert!(
        (s_hello - 1.0 / (1.0 + (-6.0f32).exp())).abs() < 1e-4,
        "got {s_hello}"
    );
    // "ccc" -> id 9 -> logits[0] = 10 -> sigmoid(10): DIFFERENT value proves
    // the tokenized input actually reaches the graph
    let s_ccc = cls.score("ccc").expect("score ccc");
    assert!(
        (s_ccc - s_hello).abs() > 1e-3,
        "scores must depend on input"
    );
    // determinism across calls
    assert_eq!(cls.score("hello").unwrap(), s_hello);

    cleanup(&model_path);
}

#[test]
fn categorical_classifier_maps_classes() {
    let (model_path, tok_dir) = write_fixtures("constant", &constant_model());
    let map = vec![GuardCategory::PromptInjection, GuardCategory::Jailbreak];
    let cls = OnnxCategoricalClassifier::new(
        model_path.to_str().unwrap(),
        tok_dir.to_str().unwrap(),
        map,
    )
    .expect("categorical fixture model loads");

    // softmax([0.2, 3.0]) = [~0.057, ~0.943]; threshold 0.9 -> single pair
    let out = cls.classify("hello");
    assert_eq!(out.len(), 1, "pairs: {out:?}");
    assert_eq!(out[0].0, GuardCategory::Jailbreak);
    assert!((out[0].1 - 0.9427).abs() < 1e-3);
    // softmax mode: probabilities sum to 1
    let probs = cls.probs("hello").expect("probs");
    let sum: f32 = probs.iter().map(|(_, p)| p).sum();
    assert!((sum - 1.0).abs() < 1e-5);

    // multi-label mode: independent sigmoids do not sum to 1
    let ml = cls.multi_label(true);
    let probs = ml.probs("hello").expect("probs ml");
    let sum: f32 = probs.iter().map(|(_, p)| p).sum();
    assert!(sum > 1.0, "sigmoid probs should not sum to 1, got {sum}");

    cleanup(&model_path);
}

#[test]
fn class_count_mismatch_fails_at_construction() {
    let (model_path, tok_dir) = write_fixtures("mismatch", &constant_model());
    // 2-class fixture vs 3-entry map -> fail fast with a clear message
    let map = vec![
        GuardCategory::Hate,
        GuardCategory::Insult,
        GuardCategory::Violence,
    ];
    let err = OnnxCategoricalClassifier::new(
        model_path.to_str().unwrap(),
        tok_dir.to_str().unwrap(),
        map,
    )
    .unwrap_err();
    assert!(
        err.message.contains("class") && err.message.contains("3"),
        "message: {}",
        err.message
    );

    cleanup(&model_path);
}

#[test]
fn classifier_is_send_and_sync() {
    // MlClassifier contract requires Send + Sync for sharing across threads
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<OnnxSecurityClassifier>();
    assert_send_sync::<OnnxCategoricalClassifier>();
    assert_send_sync::<redactify::guard::onnx::OnnxStreamGuardClassifier>();
    assert_send_sync::<redactify::guard::onnx::OnnxNerRecognizer>();
}

/// Model C: four constant heads, the Qwen3Guard-Stream export shape:
/// query_risk (1,1,3), query_category (1,1,9), resp_risk (1,1,3),
/// resp_category (1,1,8). One token of input ("a" in the fixture vocab).
fn stream_heads_model() -> Vec<u8> {
    let mut cats9 = vec![0.0_f32; 9];
    cats9[8] = 4.0; // Jailbreak slot dominant
    let mut cats8 = vec![0.0_f32; 8];
    cats8[0] = 1.0;
    let n0 = node(
        0,
        "Constant",
        &[],
        &["query_risk"],
        &[&attr_tensor(
            "value",
            &tensor_f32(&[1, 1, 3], &[0.2, 0.2, 4.0]),
        )],
    );
    let n1 = node(
        1,
        "Constant",
        &[],
        &["query_category"],
        &[&attr_tensor("value", &tensor_f32(&[1, 1, 9], &cats9))],
    );
    let n2 = node(
        2,
        "Constant",
        &[],
        &["resp_risk"],
        &[&attr_tensor(
            "value",
            &tensor_f32(&[1, 1, 3], &[0.0, 0.0, 1.0]),
        )],
    );
    let n3 = node(
        3,
        "Constant",
        &[],
        &["resp_category"],
        &[&attr_tensor("value", &tensor_f32(&[1, 1, 8], &cats8))],
    );
    model(
        &[n0, n1, n2, n3],
        &[
            ("query_risk", 1),
            ("query_category", 1),
            ("resp_risk", 1),
            ("resp_category", 1),
        ],
    )
}

#[test]
fn stream_guard_classifier_four_heads() {
    use redactify::guard::onnx::{OnnxStreamGuardClassifier, RiskBand};

    let (model_path, tok_dir) = write_fixtures("stream", &stream_heads_model());
    let cls =
        OnnxStreamGuardClassifier::new(model_path.to_str().unwrap(), tok_dir.to_str().unwrap())
            .expect("4-head fixture model loads (head validation incl.)");

    // "a" is a single token in the fixture vocab -> seq = 1
    let s = cls.score("a").expect("score");
    // softmax([0.2, 0.2, 4.0]): p_unsafe ~ 0.957, p_safe ~ 0.021
    assert!((s.p_unsafe - 0.957).abs() < 1e-2, "p_unsafe {}", s.p_unsafe);
    assert_eq!(s.risk, RiskBand::Unsafe);
    assert_eq!(s.category_slot, 8);
    assert_eq!(s.category_name, "Jailbreak");
    assert_eq!(s.category, GuardCategory::Jailbreak);
    assert!((s.score - (1.0 - s.p_safe)).abs() < 1e-6);
    assert!(s.score > 0.97, "score {}", s.score);

    // threshold gate
    let out = cls.classify("a");
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].0, GuardCategory::Jailbreak);
    assert_eq!(cls.health(), MlHealth::Ok);
    let strict = cls.with_threshold(0.999);
    assert!(strict.classify("a").is_empty());

    cleanup(&model_path);
}

#[test]
fn stream_guard_rejects_wrong_head_shape() {
    use redactify::guard::onnx::OnnxStreamGuardClassifier;

    // binary-constant model (single logits output): the 4 named heads are
    // missing -> construction must fail fast
    let (model_path, tok_dir) = write_fixtures("streambad", &constant_model());
    let err =
        OnnxStreamGuardClassifier::new(model_path.to_str().unwrap(), tok_dir.to_str().unwrap())
            .unwrap_err();
    assert!(err.message.contains("missing"), "message: {}", err.message);
    cleanup(&model_path);
}

/// Model D: two constant outputs declared in the order `aux`, `logits` -
/// the FIRST output is not the logits tensor.
fn first_output_not_logits_model() -> Vec<u8> {
    let aux = node(
        0,
        "Constant",
        &[],
        &["aux"],
        &[&attr_tensor(
            "value",
            &tensor_f32(&[1, 3], &[5.0, -5.0, 0.0]),
        )],
    );
    let logits = node(
        1,
        "Constant",
        &[],
        &["logits"],
        &[&attr_tensor("value", &tensor_f32(&[1, 2], &[0.2, 3.0]))],
    );
    model(&[aux, logits], &[("aux", 1), ("logits", 1)])
}

#[test]
fn runtime_reads_the_output_the_warmup_validated() {
    // the warmup validates `logits`, so every later call must read
    // `logits` too, not the FIRST output (`aux` here)
    let (model_path, tok_dir) = write_fixtures("firstaux", &first_output_not_logits_model());
    let cls = OnnxSecurityClassifier::new(model_path.to_str().unwrap(), tok_dir.to_str().unwrap())
        .expect("fixture model loads");
    // softmax([0.2, 3.0]) positive-last ~ 0.9427; reading `aux` would give
    // softmax([5, -5, 0]) last ~ 0.0067
    let s = cls.score("hello").expect("score");
    assert!((s - 0.9427).abs() < 1e-3, "score was {s}");

    // class-count validation and runtime agree on the same tensor too
    let cat = OnnxCategoricalClassifier::new(
        model_path.to_str().unwrap(),
        tok_dir.to_str().unwrap(),
        vec![GuardCategory::PromptInjection, GuardCategory::Jailbreak],
    )
    .expect("2-class logits match the 2-entry map");
    let probs = cat.probs("hello").expect("probs");
    assert_eq!(probs.len(), 2);
    assert!((probs[1].1 - 0.9427).abs() < 1e-3, "{probs:?}");
    cleanup(&model_path);
}

#[test]
fn healthy_classifiers_report_ok() {
    let (model_path, tok_dir) = write_fixtures("health", &constant_model());
    let sec = OnnxSecurityClassifier::new(model_path.to_str().unwrap(), tok_dir.to_str().unwrap())
        .unwrap();
    let cat = OnnxCategoricalClassifier::new(
        model_path.to_str().unwrap(),
        tok_dir.to_str().unwrap(),
        vec![GuardCategory::PromptInjection, GuardCategory::Jailbreak],
    )
    .unwrap();
    let _ = sec.classify("hello");
    let _ = cat.classify("hello");
    assert_eq!(sec.health(), MlHealth::Ok);
    assert_eq!(cat.health(), MlHealth::Ok);
    cleanup(&model_path);
}

#[test]
fn timeout_degrades_the_lane_and_follows_the_fail_mode() {
    let (model_path, tok_dir) = write_fixtures("timeout", &constant_model());
    // a zero timeout times out every inference
    let closed =
        OnnxSecurityClassifier::new(model_path.to_str().unwrap(), tok_dir.to_str().unwrap())
            .unwrap()
            .with_timeout(Duration::ZERO);
    assert_eq!(closed.timeout(), Duration::ZERO);
    // default fail-closed: the timeout blocks instead of opening the door
    assert_eq!(
        closed.classify("hello"),
        vec![(GuardCategory::Jailbreak, 1.0)]
    );
    // the lane is degraded now: the next call fails fast, and health says why
    let err = closed.score("hello").unwrap_err();
    assert!(err.message.contains("failing fast"), "{}", err.message);
    match closed.health() {
        MlHealth::Degraded(reason) => {
            assert!(reason.contains("timeout"), "{reason}");
            assert!(reason.contains("lane degraded"), "{reason}");
        }
        other => panic!("expected Degraded, got {other:?}"),
    }

    // fail-open: the same failure emits nothing (L0/L1 decide alone), but
    // the degradation is still reported
    let open = OnnxCategoricalClassifier::new(
        model_path.to_str().unwrap(),
        tok_dir.to_str().unwrap(),
        vec![GuardCategory::Hate, GuardCategory::Violence],
    )
    .unwrap()
    .with_fail_mode(FailMode::Open)
    .with_timeout(Duration::ZERO);
    assert!(open.classify("hello").is_empty());
    assert!(matches!(open.health(), MlHealth::Degraded(_)));
    cleanup(&model_path);
}

#[test]
fn shared_options_round_trip_through_the_builders() {
    let (model_path, tok_dir) = write_fixtures("options", &constant_model());
    let cls = OnnxSecurityClassifier::new(model_path.to_str().unwrap(), tok_dir.to_str().unwrap())
        .unwrap();
    // defaults
    assert_eq!(cls.threshold(), 0.5);
    assert_eq!(cls.fail_mode(), FailMode::Closed);
    assert_eq!(cls.timeout(), Duration::from_secs(2));
    assert_eq!(cls.max_len(), 512);
    let cls = cls
        .with_threshold(0.8)
        .with_fail_mode(FailMode::Open)
        .with_timeout(Duration::from_millis(1500))
        .with_max_len(128)
        .expect("valid truncation bound");
    assert_eq!(cls.threshold(), 0.8);
    assert_eq!(cls.fail_mode(), FailMode::Open);
    assert_eq!(cls.timeout(), Duration::from_millis(1500));
    assert_eq!(cls.max_len(), 128);
    // the threshold still gates emission (fixture score ~0.943 < 0.95)
    assert!(cls.with_threshold(0.95).classify("hello").is_empty());
    cleanup(&model_path);
}

/// Model E: token-classification shape `[1, 1, 3]` (one token), labels
/// `O, B-PER, I-PER`, with B-PER dominant.
fn ner_one_token_model() -> Vec<u8> {
    let n = node(
        0,
        "Constant",
        &[],
        &["logits"],
        &[&attr_tensor(
            "value",
            &tensor_f32(&[1, 1, 3], &[0.0, 6.0, 0.0]),
        )],
    );
    model(&[n], &[("logits", 1)])
}

#[test]
fn ner_fixture_recognizes_and_reports_health() {
    use redactify::guard::onnx::OnnxNerRecognizer;
    use redactify::{EntityType, NerHealth, NerRecognizer};

    let (model_path, tok_dir) = write_fixtures("ner", &ner_one_token_model());
    let labels = vec!["O".to_owned(), "B-PER".to_owned(), "I-PER".to_owned()];
    let ner = OnnxNerRecognizer::new(
        model_path.to_str().unwrap(),
        tok_dir.to_str().unwrap(),
        labels.clone(),
    )
    .expect("NER fixture loads");
    assert_eq!(ner.threshold(), 0.7);
    // "hello" is one token in the fixture vocab: one Name span
    let ents = ner.recognize("hello");
    assert_eq!(ents.len(), 1, "{ents:?}");
    assert_eq!(ents[0].kind, EntityType::Name);
    assert_eq!(ents[0].text, "hello");
    assert_eq!(ner.health(), NerHealth::Ok);

    // a timed-out inference fails open (no spans) and is REPORTED
    let slow = OnnxNerRecognizer::new(
        model_path.to_str().unwrap(),
        tok_dir.to_str().unwrap(),
        labels,
    )
    .unwrap()
    .with_timeout(Duration::ZERO);
    assert!(slow.recognize("hello").is_empty());
    assert!(
        matches!(slow.health(), NerHealth::Degraded(m) if m.contains("lane degraded")),
        "{:?}",
        slow.health()
    );
    cleanup(&model_path);
}

#[test]
fn ml_error_preserves_source_chain() {
    use redactify::guard::onnx::MlError;
    use std::error::Error;
    // io-backed conversion keeps the io error reachable via source()
    let io_err = std::io::Error::other("disk on fire");
    let ml = MlError::from(io_err);
    assert!(ml.message.contains("io:"));
    let src = ml.source().expect("source must be preserved");
    assert_eq!(src.to_string(), "disk on fire");
    // message-only errors have no source
    let bare = MlError::new("plain");
    assert!(bare.source().is_none());
}

// ------------------------------------------------- encoder adapter (model.toml)

/// Writes `model.toml` (and optionally `config.json`) next to the fixture
/// model; returns the `model.toml` path.
fn write_spec(
    model_path: &std::path::Path,
    toml: &str,
    config: Option<&str>,
) -> std::path::PathBuf {
    let dir = model_path.parent().expect("fixture dir");
    if let Some(json) = config {
        std::fs::write(dir.join("config.json"), json).expect("config.json written");
    }
    let spec = dir.join("model.toml");
    std::fs::write(&spec, toml).expect("model.toml written");
    spec
}

const BINARY_SPEC: &str = r#"
id = "fixture-encoder"
model = "model.onnx"
tokenizer = "tokenizer"
[head]
kind = "binary"
labels = ["benign", "jailbreak"]
positive = "jailbreak"
category = "JAILBREAK"
"#;

#[test]
fn encoder_scores_match_the_security_classifier_bit_for_bit() {
    use redactify::guard::classifier::{ClassifyRequest, GuardClassifier, Role};
    use redactify::guard::onnx::OnnxEncoder;

    // two logits (constant model) and one logit (input-dependent model)
    let cases = [
        ("encconst", constant_model(), BINARY_SPEC.to_owned()),
        (
            "encdep",
            input_dependent_model(),
            BINARY_SPEC
                .replace(r#"["benign", "jailbreak"]"#, r#"["jailbreak"]"#)
                .replace("fixture-encoder", "fixture-sigmoid"),
        ),
    ];
    for (name, bytes, toml) in cases {
        let (model_path, tok_dir) = write_fixtures(name, &bytes);
        let legacy =
            OnnxSecurityClassifier::new(model_path.to_str().unwrap(), tok_dir.to_str().unwrap())
                .unwrap();
        let guarded = OnnxEncoder::from_model_toml(write_spec(&model_path, &toml, None))
            .expect("encoder loads from model.toml");
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        for text in ["hello", "ccc", "hello world bb", "a"] {
            let expected = legacy.score(text).unwrap();
            let verdict = guarded
                .inner()
                .classify(&ClassifyRequest::new(text, Role::Prompt, deadline))
                .unwrap();
            assert_eq!(verdict.scores.len(), 1);
            assert_eq!(
                verdict.scores[0].score.to_bits(),
                expected.to_bits(),
                "{name} {text}"
            );
            assert_eq!(verdict.scores[0].raw_label, "jailbreak");
            // the wrapper emits the same pairs as the legacy classifier
            assert_eq!(
                guarded.classify(text),
                legacy.classify(text),
                "{name} {text}"
            );
        }
        assert!(!guarded.inner().labels_verified(), "no config.json here");
        cleanup(&model_path);
    }
}

#[test]
fn encoder_verifies_labels_against_config_json() {
    use redactify::guard::onnx::OnnxEncoder;

    let (model_path, _tok) = write_fixtures("encok", &constant_model());
    let good = r#"{"id2label": {"0": "benign", "1": "jailbreak"}}"#;
    let clf = OnnxEncoder::from_model_toml(write_spec(&model_path, BINARY_SPEC, Some(good)))
        .expect("matching id2label loads");
    assert!(clf.inner().labels_verified());
    cleanup(&model_path);

    // the inverted order is refused: the positive class would be read from
    // the benign logit
    let (model_path, _tok) = write_fixtures("encbad", &constant_model());
    let inverted = r#"{"id2label": {"0": "jailbreak", "1": "benign"}}"#;
    let err = OnnxEncoder::from_model_toml(write_spec(&model_path, BINARY_SPEC, Some(inverted)))
        .unwrap_err();
    assert!(
        err.message.contains("disagree with config.json"),
        "{}",
        err.message
    );
    cleanup(&model_path);
}

#[test]
fn encoder_refuses_a_label_count_that_does_not_match_the_logits() {
    use redactify::guard::onnx::OnnxEncoder;

    let (model_path, _tok) = write_fixtures("enccount", &constant_model());
    let three = BINARY_SPEC
        .replace(r#"kind = "binary""#, r#"kind = "categorical""#)
        .replace(r#"["benign", "jailbreak"]"#, r#"["a", "b", "c"]"#)
        .replace(
            "positive = \"jailbreak\"\ncategory = \"JAILBREAK\"",
            "categories = { b = \"HATE\" }",
        );
    let err = OnnxEncoder::from_model_toml(write_spec(&model_path, &three, None)).unwrap_err();
    assert!(
        err.message.contains("2 logits") && err.message.contains("3 labels"),
        "{}",
        err.message
    );
    cleanup(&model_path);
}

#[test]
fn encoder_categorical_head_maps_labels_and_skips_unmapped_ones() {
    use redactify::guard::onnx::OnnxEncoder;

    let (model_path, _tok) = write_fixtures("enccat", &constant_model());
    let spec = r#"
id = "fixture-categorical"
model = "model.onnx"
tokenizer = "tokenizer"
threshold = 0.9
[head]
kind = "categorical"
labels = ["safe", "hate"]
[head.categories]
hate = "HATE"
"#;
    let clf = OnnxEncoder::from_model_toml(write_spec(&model_path, spec, None)).unwrap();
    // softmax([0.2, 3.0]) -> hate ~0.943 >= 0.9; "safe" is never emitted
    let out = clf.classify("hello");
    assert_eq!(out.len(), 1, "{out:?}");
    assert_eq!(out[0].0, GuardCategory::Hate);
    assert!((out[0].1 - 0.9427).abs() < 1e-3);
    cleanup(&model_path);
}

#[test]
fn timeouts_surface_ml_degraded_in_decisions() {
    use redactify::guard::ml::MlRouter;
    use redactify::guard::onnx::OnnxEncoder;
    use redactify::guard::SignalKind;
    use redactify::{Guard, GuardAction, GuardTarget};

    let (model_path, tok_dir) = write_fixtures("encdeg", &constant_model());
    // a legacy ONNX classifier: fail-closed blocks AND names the timeout
    let legacy =
        OnnxSecurityClassifier::new(model_path.to_str().unwrap(), tok_dir.to_str().unwrap())
            .unwrap()
            .with_timeout(Duration::ZERO);
    let d = Guard::new(GuardTarget::UserPrompt)
        .with_ml(MlRouter::default(), Some(&legacy), None)
        .decide("hello");
    assert_eq!(d.action, GuardAction::Block);
    let deg = d
        .signals
        .iter()
        .find(|s| s.kind == SignalKind::MlDegraded)
        .expect("ML_DEGRADED on a timed-out ONNX call");
    assert!(deg.rationale.contains("(timeout)"), "{}", deg.rationale);

    // the encoder through model.toml, fail-open: Log instead of Allow
    let spec = BINARY_SPEC.replace(
        "tokenizer = \"tokenizer\"",
        "tokenizer = \"tokenizer\"\nfail_mode = \"open\"\ntimeout_ms = 0",
    );
    let open = OnnxEncoder::from_model_toml(write_spec(&model_path, &spec, None)).unwrap();
    assert_eq!(open.fail_mode(), FailMode::Open);
    let d = Guard::new(GuardTarget::UserPrompt)
        .with_ml(MlRouter::default(), Some(&open), None)
        .decide("hello");
    assert_eq!(d.action, GuardAction::Log, "{}", d.rationale);
    assert!(d.signals.iter().any(|s| s.kind == SignalKind::MlDegraded));
    cleanup(&model_path);
}

#[test]
fn model_toml_validation_rejects_bad_specs() {
    use redactify::guard::onnx::ModelSpec;
    let base = std::path::Path::new("/models");
    let bad = [
        (
            BINARY_SPEC.replace("positive = \"jailbreak\"", "positive = \"evil\""),
            "not in `labels`",
        ),
        (
            BINARY_SPEC.replace("JAILBREAK", "ML_DEGRADED"),
            "not a content category",
        ),
        (
            BINARY_SPEC.replace("kind = \"binary\"", "kind = \"ranking\""),
            "head.kind",
        ),
        (format!("threshold = 1.5\n{BINARY_SPEC}"), "threshold"),
        (format!("fail_mode = \"maybe\"\n{BINARY_SPEC}"), "fail_mode"),
        (
            format!("roles = [\"system\"]\n{BINARY_SPEC}"),
            "unknown role",
        ),
        (
            format!("max_chars = 100\nchunk_overlap_chars = 100\n{BINARY_SPEC}"),
            "below `max_chars`",
        ),
        (format!("unknown_key = 1\n{BINARY_SPEC}"), "unknown"),
        (
            BINARY_SPEC.replace(r#"["benign", "jailbreak"]"#, r#"["x", "x"]"#),
            "duplicate label",
        ),
    ];
    for (toml, needle) in bad {
        let err = ModelSpec::from_toml_str(&toml, base).expect_err(needle);
        assert!(err.message.contains(needle), "{needle}: {}", err.message);
    }
    let ok = ModelSpec::from_toml_str(BINARY_SPEC, base).unwrap();
    assert_eq!(ok.max_tokens, 512);
    assert_eq!(ok.max_chars, 1_800);
    assert_eq!(ok.timeout, Duration::from_secs(2));
    assert_eq!(ok.fail_mode, FailMode::Closed);
}
