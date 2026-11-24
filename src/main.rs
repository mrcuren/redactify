//! `redactify` CLI - detects PII in text, prints a masked output, and
//! optionally runs the full guard pipeline (deterministic rules + policy).
//!
//! Usage:
//! ```text
//! redactify "TCKN'm 12345678950"                  # PII detect + mask
//! redactify --guard "http://169.254.169.254/x"    # full guard decision
//! cat document.txt | redactify                     # from stdin (UTF-8)
//! cat document.txt | redactify --guard -l uk -     # `-` = stdin, uk pack
//! ```

use std::io::Read;

/// `println!` that never panics: a closed stdout (`redactify --guard - |
/// grep -q x`) must not turn the decision's exit code (1 on Block) into
/// the 101 of a printing panic.
macro_rules! say {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stdout().lock(), $($arg)*);
    }};
}

fn print_usage() {
    say!(
        "redactify {} - checksum-validated PII detection & redaction + guard runtime

USAGE:
    redactify [FLAGS] [TEXT | -]              detect + mask PII
    redactify --guard [FLAGS] [TEXT | -]      full guard decision (exit 1 on Block)
    redactify --sanitize [FLAGS] [TEXT | -]   decision + sanitized text (exit 1 on Block)
    redactify --encode [FLAGS] [TEXT | -]     HTML-entity encode
    redactify --vault [FLAGS] [TEXT | -]      reversible pseudonymization demo
    redactify --stream [FLAGS]                incremental stdin->stdout guard: masks each
                                              completed line as it arrives (exit 1 on Block);
                                              every line is decided like the batch decision
                                              of the stream so far, over a bounded window
    redactify --fpr-monitor [--interval-secs N] [--max-iterations N]
                                              benign-canary false-positive monitor (default
                                              5 s interval, 3 iterations; exit 1 when the 5%
                                              FPR budget is exceeded)
    redactify selftest [FLAGS]                canonical probes (TCKN, IBAN, card, phone, e-mail,
                                              name, secret) under the loaded policy: pass/fail
                                              and latency, never values (exit 1 on a failure);
                                              `--selftest` is the same
    redactify --probe [FLAGS] [TEXT | -]      entity types, offsets, scores, rule ids and policy
                                              actions of TEXT, plus the decision; never values
    redactify --serve [ADDR] [ML FLAGS]       REST API server (default 127.0.0.1:8080)

    TEXT is read from stdin when it is `-` or absent (UTF-8). One TEXT at most
    (quote it); a TEXT that starts with `-` goes after `--`. An unknown flag, a
    second TEXT or a flag without its value exits 2.

FLAGS:
    --json, -j                 JSON output (detect, guard, sanitize, encode, vault, stream)
    --target, -t <kind>        user_prompt (default) | tool_response | model_output
                               (aliases: user, prompt, tool, tool-response, model,
                               model-output)
    --locale, -l <a,b>         locale packs for detect, guard, sanitize, stream and vault:
                               tr, en (the default set), fr, es, nl, uk, de, it, pl, ca,
                               au, sg, in, pt, br, cn, se, fi, no, dk, eu, kr, ng,
                               ph, za, th
    --policy <file.toml>       TOML policy for every mode (config feature; the
                               REDACTIFY_POLICY environment variable does the same);
                               its `locales` list applies when --locale is absent; a
                               malformed file refuses to run
    --interval-secs <N>        --fpr-monitor: seconds between iterations (default 5)
    --max-iterations <N>       --fpr-monitor: iterations to run, at least 1 (default 3)
    --serve [ADDR]             start the REST API (api feature); with the
                               REDACTIFY_API_TOKEN environment variable set, every
                               request except GET /health needs
                               `Authorization: Bearer <token>`; an invalid token
                               refuses to start
    --max-body <bytes>         --serve: request body limit, 1024 to 16777216 (default
                               1048576; the REDACTIFY_MAX_BODY environment variable does
                               the same). REDACTIFY_AUDIT_FILE (+ REDACTIFY_AUDIT_KEY)
                               records every decision in a hash-chained JSONL file; a
                               file that does not verify refuses to start
    --ml-security <onnx>       L2 model file (api,ml-onnx features)
    --ml-security-tokenizer <dir|file>
    --ml-safety <onnx>         L3 4-head stream model file
    --ml-safety-tokenizer <dir|file>
    --ml-ner <onnx>            L1 NER model file (free-prose names)
    --ml-ner-tokenizer <dir|file>
    --ml-ner-labels <json>     id2label array (written at export time; ML_SETUP.md)
    --ml-ner-router            L1 NER via the locale/script router (savasy for
                              tr + XLM-R multilingual, lazy-load + LRU) instead
                              of a single --ml-ner model
    --ml-ner-piiranha          add the PIIRanha ensemble secondary (implies
                              --ml-ner-router)
    --ml-threshold <0.0-1.0>   overrides measured defaults (L2 0.706 / L3 0.815 / NER 0.43)
    --help, -h                 this help
    --version, -V              print version",
        env!("CARGO_PKG_VERSION")
    );
}

/// Exits 2 (a usage error) with `message` on stderr.
fn usage_error(message: &str) -> ! {
    eprintln!("error: {message}");
    std::process::exit(2);
}

fn main() {
    // `std::env::args` panics on an argument that is not valid Unicode,
    // quoting the argument (possibly the text under test) on stderr
    let args: Vec<String> = std::env::args_os()
        .skip(1)
        .enumerate()
        .map(|(i, a)| {
            a.into_string().unwrap_or_else(|_| {
                usage_error(&format!("argument {} is not valid Unicode", i + 1))
            })
        })
        .collect();
    // `redactify selftest` (subcommand spelling) is `--selftest`; a TEXT that
    // is the word itself goes after `--`
    let mut args = args;
    if args.first().is_some_and(|a| a == "selftest") {
        args[0] = "--selftest".to_owned();
    }
    // POSIX utility syntax guideline 10: `--` ends the options
    let options = &args[..args.iter().position(|a| a == "--").unwrap_or(args.len())];

    // --help / --version come first so they work in any combination
    if options.iter().any(|a| a == "--help" || a == "-h") {
        print_usage();
        return;
    }
    if options.iter().any(|a| a == "--version" || a == "-V") {
        say!("redactify {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    // parse --target <kind> first, then the mode flag
    let mut target = redactify::policy::GuardTarget::UserPrompt;
    // --locale codes (empty = the policy's default locales, else tr+en)
    let mut locales: Vec<String> = Vec::new();
    // --fpr-monitor pacing
    let mut fpr_interval_secs: u64 = 5;
    let mut fpr_max_iterations: usize = 3;
    let mut remaining: Vec<&str> = Vec::new();
    let mut skip_next = false;
    #[cfg(feature = "api")]
    let mut serve_addr: Option<String> = None;
    // optional ML models for --serve (paths only here; construction is
    // feature-gated below)
    #[cfg(feature = "api")]
    let mut ml = MlFlags::default();
    // --max-body for --serve (bytes; validated when the server starts)
    #[cfg(feature = "api")]
    let mut max_body: Option<usize> = None;
    // optional TOML policy for EVERY mode (config feature; the
    // REDACTIFY_POLICY env var does the same without a flag)
    let mut policy_path: Option<String> = None;
    // the arguments after `--`: TEXT even when they start with `-`
    let mut operands: &[String] = &[];
    for (i, arg) in args.iter().enumerate() {
        if skip_next {
            skip_next = false;
            continue;
        }
        if arg == "--" {
            operands = &args[i + 1..];
            break;
        }
        if arg == "--serve" {
            #[cfg(feature = "api")]
            {
                // optional value: an address that is not another flag
                match args.get(i + 1) {
                    Some(a) if !a.starts_with('-') => {
                        serve_addr = Some(a.clone());
                        skip_next = true;
                    }
                    _ => serve_addr = Some("127.0.0.1:8080".to_owned()),
                }
            }
            #[cfg(not(feature = "api"))]
            {
                eprintln!(
                    "--serve needs the api feature:\n  cargo run --release --features api -- --serve 127.0.0.1:8080"
                );
                std::process::exit(2);
            }
        } else if arg == "--max-body" {
            let Some(v) = args.get(i + 1) else {
                usage_error("--max-body requires a byte count");
            };
            skip_next = true;
            #[cfg(feature = "api")]
            {
                match v.parse::<usize>() {
                    Ok(n) => max_body = Some(n),
                    Err(_) => usage_error(&format!(
                        "invalid --max-body value `{v}` (expected a whole number of bytes)"
                    )),
                }
            }
            #[cfg(not(feature = "api"))]
            {
                let _ = v;
                usage_error("--max-body needs the api feature");
            }
        } else if arg == "--policy" {
            // feature-agnostic parsing: guard/sanitize/stream are core
            // modes and take a policy too (loading is config-gated below)
            let Some(v) = args.get(i + 1).cloned() else {
                eprintln!("error: --policy requires a TOML file path");
                std::process::exit(2);
            };
            skip_next = true;
            policy_path = Some(v);
        } else if arg == "--ml-ner-router" || arg == "--ml-ner-piiranha" {
            #[cfg(feature = "api")]
            {
                if arg == "--ml-ner-piiranha" {
                    ml.ner_piiranha = true;
                } else {
                    ml.ner_router = true;
                }
            }
            #[cfg(not(feature = "api"))]
            {
                eprintln!("{arg} requires the api feature");
                std::process::exit(2);
            }
        } else if matches!(
            arg.as_str(),
            "--ml-security"
                | "--ml-security-tokenizer"
                | "--ml-safety"
                | "--ml-safety-tokenizer"
                | "--ml-ner"
                | "--ml-ner-tokenizer"
                | "--ml-ner-labels"
                | "--ml-threshold"
        ) {
            #[cfg(feature = "api")]
            {
                let value = args.get(i + 1).cloned();
                let Some(v) = value else {
                    eprintln!("error: {arg} requires a value");
                    std::process::exit(2);
                };
                skip_next = true;
                match arg.as_str() {
                    "--ml-security" => ml.security = Some(v),
                    "--ml-security-tokenizer" => ml.security_tok = Some(v),
                    "--ml-safety" => ml.safety = Some(v),
                    "--ml-safety-tokenizer" => ml.safety_tok = Some(v),
                    "--ml-ner" => ml.ner = Some(v),
                    "--ml-ner-tokenizer" => ml.ner_tok = Some(v),
                    "--ml-ner-labels" => ml.ner_labels = Some(v),
                    _ => match v.parse::<f32>() {
                        Ok(t) => ml.threshold = Some(t),
                        Err(_) => {
                            eprintln!(
                                "error: invalid --ml-threshold value `{v}` (expected 0.0-1.0)"
                            );
                            std::process::exit(2);
                        }
                    },
                }
            }
            #[cfg(not(feature = "api"))]
            {
                eprintln!("{arg} requires the api feature");
                std::process::exit(2);
            }
        } else if arg == "--target" || arg == "-t" {
            use std::str::FromStr;
            let Some(kind) = args.get(i + 1) else {
                usage_error(&format!("{arg} requires a target kind"));
            };
            target = match redactify::policy::GuardTarget::from_str(kind) {
                Ok(t) => t,
                Err(e) => usage_error(&e.to_string()),
            };
            skip_next = true;
        } else if arg == "--locale" || arg == "-l" {
            let Some(kind) = args.get(i + 1) else {
                usage_error(&format!("{arg} requires locale codes"));
            };
            // spaces around the commas belong to the list syntax; each
            // code is then matched exactly (an unknown or miscased code
            // would select no pack and switch detection off)
            locales = kind
                .split(',')
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(String::from)
                .collect();
            if let Some(code) = locales
                .iter()
                .find(|code| !redactify::SUPPORTED_LOCALES.contains(&code.as_str()))
            {
                usage_error(&format!(
                    "unknown locale `{code}` for {arg} (supported: {})",
                    redactify::SUPPORTED_LOCALES.join(", ")
                ));
            }
            skip_next = true;
        } else if arg == "--interval-secs" || arg == "--max-iterations" {
            let Some(v) = args.get(i + 1) else {
                eprintln!("error: {arg} requires a value");
                std::process::exit(2);
            };
            skip_next = true;
            match (arg.as_str(), v.parse::<u64>()) {
                ("--interval-secs", Ok(n)) => fpr_interval_secs = n,
                ("--max-iterations", Ok(n)) if n >= 1 => {
                    fpr_max_iterations = usize::try_from(n).unwrap_or(usize::MAX);
                }
                _ => {
                    let bound = if arg == "--max-iterations" {
                        " >= 1"
                    } else {
                        ""
                    };
                    eprintln!("error: invalid {arg} value `{v}` (expected a whole number{bound})");
                    std::process::exit(2);
                }
            }
        } else {
            remaining.push(arg);
        }
    }

    // the mode flag, --json and at most one TEXT, in any order; anything
    // else that looks like a flag is refused, so it is never scanned as the
    // text or takes the text's place (reporting "No PII found.")
    let mut json_format = false;
    let mut mode: Option<(Mode, &str)> = None;
    let mut texts: Vec<&str> = Vec::new();
    for &a in &remaining {
        let flag_mode = match a {
            "--json" | "-j" => {
                json_format = true;
                continue;
            }
            "--guard" | "-g" => Mode::Guard,
            "--sanitize" | "-s" => Mode::Sanitize,
            "--encode" | "-e" => Mode::Encode,
            "--vault" | "-v" => Mode::Vault,
            "--stream" => Mode::Stream,
            "--fpr-monitor" => Mode::FprMonitor,
            "--selftest" => Mode::Selftest,
            "--probe" | "-p" => Mode::Probe,
            // `-` names stdin explicitly
            "-" => {
                texts.push(a);
                continue;
            }
            flag if flag.starts_with('-') => usage_error(&format!(
                "unknown flag `{flag}`; see --help (a TEXT that starts with `-` goes after `--`)"
            )),
            _ => {
                texts.push(a);
                continue;
            }
        };
        match mode {
            Some((m, first)) if m != flag_mode => {
                usage_error(&format!("`{first}` and `{a}` are different modes"));
            }
            _ => mode = Some((flag_mode, a)),
        }
    }
    texts.extend(operands.iter().map(String::as_str));
    if texts.len() > 1 {
        usage_error(&format!(
            "expected at most one TEXT, got {} (quote a text that has spaces)",
            texts.len()
        ));
    }
    let (mode, mode_flag) = mode.unwrap_or((Mode::Detect, ""));
    // `-` names stdin explicitly (same as giving no text)
    let text = texts.pop().filter(|t| *t != "-").map(str::to_owned);
    if text.is_some() && matches!(mode, Mode::Stream | Mode::FprMonitor | Mode::Selftest) {
        let why = match mode {
            Mode::Stream => "it reads stdin",
            Mode::Selftest => "it scans its own probe texts",
            _ => "it scans its own canary texts",
        };
        usage_error(&format!("{mode_flag} takes no TEXT ({why})"));
    }
    #[cfg(feature = "api")]
    if serve_addr.is_some() && (text.is_some() || mode != Mode::Detect) {
        usage_error("--serve runs the REST API; it takes no TEXT and no mode flag");
    }
    let locale_refs: Vec<&str> = locales.iter().map(String::as_str).collect();

    // one policy load for every mode (flag wins over REDACTIFY_POLICY);
    // fail-closed on a malformed file, same posture as a model-load failure
    let policy = load_policy_or_exit(policy_path.as_deref());

    #[cfg(feature = "api")]
    if let Some(addr) = serve_addr {
        // server mode: never read stdin, run until killed
        let mut state = build_api_state(ml);
        if let Some(p) = &policy {
            state = state.with_policy(p.clone());
        }
        // --max-body wins over REDACTIFY_MAX_BODY; the server refuses a
        // limit outside its range
        let limit = match max_body {
            Some(n) => n,
            None => match redactify::api::body_limit_from_env() {
                Ok(n) => n.unwrap_or(redactify::api::MAX_BODY),
                Err(e) => {
                    eprintln!("cannot start: {e}");
                    std::process::exit(1);
                }
            },
        };
        state = state.with_max_body(limit);
        let ml = if state.ml_active() { " + ML" } else { "" };
        let pol = if state.policy.is_some() {
            " + policy"
        } else {
            ""
        };
        let audit = if std::env::var_os(redactify::api::AUDIT_FILE_ENV_VAR).is_some() {
            " + audit file"
        } else {
            ""
        };
        eprintln!(
            "redactify api listening on http://{addr}{ml}{pol}{audit} (4 workers, {limit} byte body cap)"
        );
        if policy.as_ref().is_some_and(|p| p.dry_run) {
            eprintln!(
                "redactify api: DRY RUN (shadow mode): decisions are audited and counted, never enforced"
            );
        }
        install_location_only_panic_hook();
        if let Err(e) = redactify::api::serve_with(&addr, state) {
            eprintln!("cannot start the REST API on {addr}: {e}");
            std::process::exit(1);
        }
        return;
    }

    // streaming mode reads stdin INCREMENTALLY (never the whole input) and
    // forwards masked lines as they complete; must run before the batch
    // stdin read below
    if let Mode::Stream = mode {
        run_stream(&target, json_format, policy.as_ref(), &locale_refs);
        return;
    }

    // FPR monitor runs its own loop (no stdin needed)
    if let Mode::FprMonitor = mode {
        run_fpr_monitor(fpr_interval_secs, fpr_max_iterations);
        return;
    }

    // selftest scans its own probe texts (no stdin needed)
    if let Mode::Selftest = mode {
        run_selftest(&target, policy.as_ref(), &locale_refs, json_format);
        return;
    }

    let text = match text {
        Some(t) => t,
        None => {
            let mut buf = String::new();
            if std::io::stdin().read_to_string(&mut buf).is_err() {
                eprintln!("failed to read input (UTF-8 expected)");
                std::process::exit(1);
            }
            buf
        }
    };

    // one guard per invocation: the policy, the target and the effective
    // locales (--locale, else the policy's default locales, else tr+en);
    // its detector serves detect and vault too
    let guard = redactify::Guard::new(target)
        .with_policy(policy.as_ref())
        .with_locales(&locale_refs);
    match mode {
        Mode::Guard => run_guard(&text, &guard, json_format),
        Mode::Sanitize => run_sanitize(&text, &guard, json_format),
        Mode::Encode => run_encode(&text, json_format),
        Mode::Vault => run_vault(&text, &guard.detector(), json_format),
        Mode::Detect => run_detect(&text, &guard.detector(), json_format),
        Mode::Probe => run_probe(&text, &guard, policy.as_ref(), json_format),
        Mode::Stream => unreachable!("streaming mode is dispatched before the stdin read"),
        Mode::FprMonitor => unreachable!("fpr-monitor is dispatched before the stdin read"),
        Mode::Selftest => unreachable!("selftest is dispatched before the stdin read"),
    }
}

/// Replaces the default panic hook before the REST server starts: the
/// default hook prints the panic message, which may quote request text
/// (PII), to stderr. This one logs the source location only (the MCP
/// binary does the same); the worker still answers the request with a 500.
#[cfg(feature = "api")]
fn install_location_only_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let location = info
            .location()
            .map_or_else(|| "unknown location".to_owned(), ToString::to_string);
        eprintln!("redactify api: a request handler panicked at {location}");
    }));
}

/// Loads `--policy <file>` (falling back to `REDACTIFY_POLICY`) once for
/// every mode. Fail-closed: a malformed file refuses to run, and so does a
/// `REDACTIFY_POLICY` value that is not valid Unicode (never read as unset).
fn load_policy_or_exit(path: Option<&str>) -> Option<redactify::policy::Policy> {
    #[cfg(feature = "config")]
    {
        let source = match path.map(String::from) {
            Some(p) => Some(p),
            None => match std::env::var(redactify::policy::POLICY_ENV_VAR) {
                Ok(p) => Some(p),
                Err(std::env::VarError::NotPresent) => None,
                Err(std::env::VarError::NotUnicode(_)) => {
                    eprintln!(
                        "cannot load policy: {} is set but its value is not valid Unicode",
                        redactify::policy::POLICY_ENV_VAR
                    );
                    std::process::exit(1);
                }
            },
        };
        match source {
            Some(p) => match redactify::policy::Policy::load_toml_file(&p) {
                Ok(policy) => Some(policy),
                Err(e) => {
                    eprintln!("cannot load policy {p}: {e}");
                    std::process::exit(1);
                }
            },
            None => None,
        }
    }
    #[cfg(not(feature = "config"))]
    {
        if path.is_some() || std::env::var_os("REDACTIFY_POLICY").is_some() {
            eprintln!(
                "--policy / REDACTIFY_POLICY need the config feature:\n  cargo run --release --features config -- --guard --policy packs/kvkk.tr.toml < input.txt"
            );
            std::process::exit(2);
        }
        None
    }
}

/// Parsed `--ml-*` flags: model paths plus the optional shared threshold.
#[cfg(feature = "api")]
#[derive(Default)]
struct MlFlags {
    security: Option<String>,
    security_tok: Option<String>,
    safety: Option<String>,
    safety_tok: Option<String>,
    ner: Option<String>,
    ner_tok: Option<String>,
    ner_labels: Option<String>,
    ner_router: bool,
    ner_piiranha: bool,
    threshold: Option<f32>,
}

#[cfg(feature = "api")]
fn build_api_state(ml: MlFlags) -> redactify::api::ApiState {
    #[allow(unused_mut)] // model attachment exists only with ml-onnx
    let mut state = redactify::api::ApiState::default();

    #[cfg(feature = "ml-onnx")]
    {
        use redactify::guard::ml::MlClassifier;
        use std::sync::Arc;
        // measured operating points: L2 best-F1 0.706 and L3 best-F1 @ 0.815
        const ML_SECURITY_THRESHOLD: f32 = 0.706;
        const ML_SAFETY_THRESHOLD: f32 = 0.815;
        let attach = |model: Option<String>,
                      tokenizer: Option<String>,
                      kind: &str,
                      default_threshold: f32|
         -> Option<Arc<dyn MlClassifier>> {
            let model = model?;
            let tokenizer = tokenizer.unwrap_or_else(|| {
                eprintln!("error: --ml-{kind}-tokenizer is required with --ml-{kind}");
                std::process::exit(2);
            });
            let threshold = ml.threshold.unwrap_or(default_threshold);
            match kind {
                "safety" => {
                    let cls =
                        redactify::guard::onnx::OnnxStreamGuardClassifier::new(&model, &tokenizer)
                            .map(|c| c.with_threshold(threshold))
                            .map_err(|e| format!("{e}"));
                    match cls {
                        Ok(c) => {
                            eprintln!("L3 safety model loaded: {model} (threshold {threshold})");
                            Some(Arc::new(c))
                        }
                        Err(e) => {
                            eprintln!("error: safety model load failed: {e}");
                            std::process::exit(1);
                        }
                    }
                }
                _ => {
                    let cls =
                        redactify::guard::onnx::OnnxSecurityClassifier::new(&model, &tokenizer)
                            .map(|c| c.with_threshold(threshold))
                            .map_err(|e| format!("{e}"));
                    match cls {
                        Ok(c) => {
                            eprintln!("L2 security model loaded: {model} (threshold {threshold})");
                            Some(Arc::new(c))
                        }
                        Err(e) => {
                            eprintln!("error: security model load failed: {e}");
                            std::process::exit(1);
                        }
                    }
                }
            }
        };
        state.security = attach(
            ml.security,
            ml.security_tok,
            "security",
            ML_SECURITY_THRESHOLD,
        );
        state.safety = attach(ml.safety, ml.safety_tok, "safety", ML_SAFETY_THRESHOLD);

        // L1 NER recognizer (free-prose names): best-F1 operating point 0.43
        // (span-level, data/ner_testset_tr.jsonl; F1 0.987), ~250 ms/call on
        // CPU (fp32 export).
        const ML_NER_THRESHOLD: f32 = 0.43;
        // L1 NER ROUTER (multilingual): locale/script-routed slots with
        // lazy-load + LRU (see src/guard/ner_router.rs), plus the optional
        // PIIRanha ensemble. Per-slot thresholds are calibrated, so the
        // shared --ml-threshold override deliberately does NOT apply here.
        // A slot whose model fails to load is marked dead and reported
        // through the router's health (a fail-open NER_DEGRADED signal,
        // `ml_health.ner` on GET /health) instead of aborting startup.
        if ml.ner_router || ml.ner_piiranha {
            if ml.ner.is_some() {
                eprintln!("error: --ml-ner-router and --ml-ner are mutually exclusive");
                std::process::exit(2);
            }
            let slots = redactify::guard::default_slots();
            let mut router = redactify::guard::NerRouter::with_defaults();
            if ml.ner_piiranha {
                router = router.with_piiranha();
            }
            eprintln!(
                "L1 NER router enabled: {} slot(s) ({}), lazy-load, models load on first use{}",
                slots.len(),
                slots
                    .iter()
                    .map(|s| format!("{}: {}", s.languages.join("+"), s.model_path.display()))
                    .collect::<Vec<_>>()
                    .join(", "),
                if ml.ner_piiranha {
                    " + PIIRanha ensemble"
                } else {
                    ""
                }
            );
            state.ner = Some(Arc::new(router));
        }
        if let Some(model) = ml.ner {
            let tokenizer = ml.ner_tok.unwrap_or_else(|| {
                eprintln!("error: --ml-ner-tokenizer is required with --ml-ner");
                std::process::exit(2);
            });
            let labels_path = ml.ner_labels.unwrap_or_else(|| {
                eprintln!("error: --ml-ner-labels is required with --ml-ner");
                std::process::exit(2);
            });
            let labels = match redactify::guard::onnx::load_labels_json(&labels_path) {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("error: cannot load {labels_path}: {e}");
                    std::process::exit(1);
                }
            };
            let threshold = ml.threshold.unwrap_or(ML_NER_THRESHOLD);
            match redactify::guard::onnx::OnnxNerRecognizer::new(&model, &tokenizer, labels) {
                Ok(r) => {
                    let r = r.with_threshold(threshold);
                    eprintln!("L1 NER model loaded: {model} (threshold {threshold})");
                    state.ner = Some(Arc::new(r));
                }
                Err(e) => {
                    eprintln!("error: NER model load failed: {e}");
                    std::process::exit(1);
                }
            }
        }
    }
    #[cfg(not(feature = "ml-onnx"))]
    {
        let any_ml_flag = ml.security.is_some()
            || ml.safety.is_some()
            || ml.security_tok.is_some()
            || ml.safety_tok.is_some()
            || ml.ner.is_some()
            || ml.ner_tok.is_some()
            || ml.ner_labels.is_some()
            || ml.ner_router
            || ml.ner_piiranha
            || ml.threshold.is_some();
        if any_ml_flag {
            eprintln!(
                "error: --ml-* needs the ml-onnx feature:
  cargo run --release --features \"api,ml-onnx\" -- --serve ..."
            );
            std::process::exit(2);
        }
    }
    state
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Detect,
    Guard,
    Sanitize,
    Encode,
    Vault,
    Stream,
    FprMonitor,
    Selftest,
    Probe,
}

fn run_detect(text: &str, detector: &redactify::Detector<'_>, json_format: bool) {
    let ents = detector.detect(text);
    if json_format {
        print_json_detect(text, &ents);
        return;
    }
    if ents.is_empty() {
        say!("No PII found.");
        return;
    }
    say!(
        "{:<13} {:>8} {:>8} {:>5}  TEXT",
        "TYPE",
        "BEGIN",
        "END",
        "SCORE"
    );
    for e in &ents {
        say!(
            "{:<13} {:>8} {:>8} {:>5.2}  {}",
            e.kind,
            e.start,
            e.end,
            e.score,
            e.text
        );
    }
    say!();
    // the same detector that produced the table above
    say!("{}", detector.redact(text));
}

fn run_guard(text: &str, guard: &redactify::Guard<'_>, json_format: bool) {
    use redactify::policy;

    let d = guard.decide(text);
    if json_format {
        print_json_guard(&d);
        return;
    }

    say!("{:<12} {:?}", "ACTION:", d.action);
    say!("{:<12} {}", "RATIONALE:", d.rationale);

    if !d.mask_summary.is_empty() {
        say!("{:<12} {}", "PII FOUND:", d.mask_summary.join(", "));
    }

    if !d.verdicts.is_empty() {
        say!();
        say!(
            "{:<16} {:>6} {:>8}  RATIONALE",
            "CATEGORY",
            "SCORE",
            "SEVERITY"
        );
        for v in &d.verdicts {
            say!(
                "{:<16} {:>6.2} {:>8}  {}",
                v.category.as_str(),
                v.score,
                v.severity.as_str(),
                v.rationale
            );
        }
    }

    // exit code: 0 for Allow/Mask/Log, 1 for Block
    if d.action == policy::GuardAction::Block {
        std::process::exit(1);
    }
}

/// Incremental stdin -> stdout guard: stdin is read in 8 KiB chunks (never
/// buffered whole), every completed line is forwarded immediately with its
/// PII masked, and a policy Block stops forwarding and exits 1 - the same
/// convention as `--guard`. A multibyte UTF-8 character split across two
/// reads is carried over (never rejected), because read boundaries are not
/// character boundaries.
fn run_stream(
    target: &redactify::policy::GuardTarget,
    json_format: bool,
    policy: Option<&redactify::policy::Policy>,
    locales: &[&str],
) {
    use redactify::policy::stream::{GuardEvent, StreamingGuard};
    use std::io::{Read, Write};

    fn forward(
        events: Vec<GuardEvent>,
        json_format: bool,
        out: &mut std::io::StdoutLock<'_>,
    ) -> bool {
        // returns false when a Block was emitted (stop the stream)
        for ev in events {
            match ev {
                GuardEvent::Segment { text, .. } => {
                    if json_format {
                        let line = serde_json::json!({ "type": "segment", "text": text });
                        let _ = writeln!(out, "{line}");
                    } else {
                        let _ = out.write_all(text.as_bytes());
                    }
                    let _ = out.flush();
                }
                GuardEvent::Block { rationale } => {
                    if json_format {
                        let line = serde_json::json!({ "type": "block", "rationale": rationale });
                        let _ = writeln!(out, "{line}");
                        let _ = out.flush();
                    } else {
                        eprintln!("blocked: {rationale}");
                    }
                    return false;
                }
                _ => {}
            }
        }
        true
    }

    // empty locales: the policy's default locales, else tr+en
    let mut sg = StreamingGuard::new(*target).with_locales(locales);
    if let Some(p) = policy {
        sg = sg.with_policy(p.clone());
    }
    let stdin = std::io::stdin();
    let mut handle = stdin.lock();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let mut pending: Vec<u8> = Vec::new();
    let mut buf = [0u8; 8192];
    let mut blocked = false;
    // dry run (policy shadow mode): echo the input, report a would-be
    // Block on stderr, exit 0
    let dry_run = policy.is_some_and(|p| p.dry_run);
    let mut shadow = true;

    'read: loop {
        let n = match handle.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            // `Read::read`: an interrupted read is not an error; retry
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                eprintln!("failed to read input: {e}");
                std::process::exit(1);
            }
        };
        pending.extend_from_slice(&buf[..n]);
        // decode as much as is certainly valid; keep a trailing partial
        // multibyte character as carry-over for the next read
        let valid_up_to = match std::str::from_utf8(&pending) {
            Ok(s) => s.len(),
            Err(e) => {
                let v = e.valid_up_to();
                if pending.len() - v >= 4 {
                    eprintln!("input is not valid UTF-8");
                    std::process::exit(1);
                }
                v
            }
        };
        let chunk = std::str::from_utf8(&pending[..valid_up_to])
            .expect("valid_up_to prefix is valid UTF-8 by construction");
        if dry_run {
            // shadow mode: the input passes unchanged, the guard decides
            // beside it until its first would-be Block
            if json_format {
                let line = serde_json::json!({ "type": "segment", "text": chunk, "dry_run": true });
                let _ = writeln!(out, "{line}");
            } else {
                let _ = out.write_all(chunk.as_bytes());
            }
            let _ = out.flush();
            if shadow {
                shadow = shadow_stream(sg.push(chunk));
            }
            pending.drain(..valid_up_to);
            continue;
        }
        if !forward(sg.push(chunk), json_format, &mut out) {
            blocked = true;
            break 'read;
        }
        pending.drain(..valid_up_to);
    }

    if !blocked {
        if !pending.is_empty() {
            eprintln!("input ended with a partial UTF-8 character");
            std::process::exit(1);
        }
        if dry_run {
            if shadow {
                shadow_stream(sg.finish());
            }
            return;
        }
        blocked = !forward(sg.finish(), json_format, &mut out);
    }
    if blocked {
        std::process::exit(1);
    }
}

/// The dry-run side of `--stream`: reports a would-be Block on stderr
/// (the rationale is content-free); `false` once one was seen.
fn shadow_stream(events: Vec<redactify::policy::GuardEvent>) -> bool {
    for ev in events {
        if let redactify::policy::GuardEvent::Block { rationale } = ev {
            eprintln!("dry run (not enforced): would block: {rationale}");
            return false;
        }
    }
    true
}

fn run_sanitize(text: &str, guard: &redactify::Guard<'_>, json_format: bool) {
    use redactify::policy;

    let r = guard.sanitize(text);
    // on Block the library keeps the PII raw (the caller decides); printed
    // output is loggable surface, so it gets the loggable re-mask instead
    // (secrets, then normalization-aware PII, then HTML encoding for
    // model_output), as the REST and MCP surfaces return
    let shown = if r.decision.action == policy::GuardAction::Block {
        guard.mask_all(text)
    } else {
        r.text
    };
    if json_format {
        let mut out = serde_json::json!({
            "action": r.decision.action.to_string(),
            "rationale": r.decision.rationale,
            "pii_found": r.decision.mask_summary,
            "text": shown,
        });
        add_policy_fields(&mut out, &r.decision);
        say!("{out}");
        if r.decision.action == policy::GuardAction::Block {
            std::process::exit(1);
        }
        return;
    }
    say!("{:<12} {:?}", "ACTION:", r.decision.action);
    say!("{:<12} {}", "RATIONALE:", r.decision.rationale);
    if !r.decision.mask_summary.is_empty() {
        say!(
            "{:<12} {}",
            "PII FOUND:",
            r.decision.mask_summary.join(", ")
        );
    }
    say!();
    say!("{shown}");

    if r.decision.action == policy::GuardAction::Block {
        std::process::exit(1);
    }
}

fn run_encode(text: &str, json_format: bool) {
    if json_format {
        say!(
            "{}",
            serde_json::json!({"encoded": redactify::guard::encode_html(text)})
        );
        return;
    }
    say!("{}", redactify::guard::encode_html(text));
}

fn print_json_detect(text: &str, ents: &[redactify::Entity]) {
    let entities: Vec<serde_json::Value> = ents
        .iter()
        .map(|e| {
            serde_json::json!({
                "type": e.kind.as_str(),
                "start": e.start,
                "end": e.end,
                "score": e.score,
                "text": e.text,
            })
        })
        .collect();
    let out = serde_json::json!({
        "input": text,
        "entities": entities,
    });
    say!("{out}");
}

/// The opt-in JSON fields of a decision: `entities` (per type, the action
/// and the count; no values) when an entity action other than mask applied
/// or in dry run, and `dry_run` / `dry_run_action` in dry run.
fn add_policy_fields(out: &mut serde_json::Value, d: &redactify::policy::Decision) {
    let opted_in = d.dry_run_action.is_some()
        || d.entity_counts
            .iter()
            .any(|c| c.action != redactify::policy::EntityAction::Mask);
    if opted_in {
        out["entities"] = d
            .entity_counts
            .iter()
            .map(|c| {
                serde_json::json!({
                    "type": c.kind.as_str(),
                    "action": c.action.as_str(),
                    "count": c.count,
                })
            })
            .collect();
    }
    if let Some(decided) = d.dry_run_action {
        out["dry_run"] = serde_json::Value::Bool(true);
        out["dry_run_action"] = serde_json::Value::String(decided.to_string());
    }
}

fn print_json_guard(d: &redactify::policy::Decision) {
    let verdicts: Vec<serde_json::Value> = d
        .verdicts
        .iter()
        .map(|v| {
            serde_json::json!({
                "category": v.category.as_str(),
                "score": v.score,
                "severity": v.severity.as_str(),
                "action": v.action.to_string(),
                "rationale": v.rationale,
            })
        })
        .collect();
    let relevance_downgraded: Vec<serde_json::Value> = d
        .relevance_downgraded
        .iter()
        .map(|s| {
            serde_json::json!({
                "type": s.kind.as_str(),
                "start": s.start,
                "end": s.end,
            })
        })
        .collect();
    let mut out = serde_json::json!({
        "action": d.action.to_string(),
        "top_signal": d.top_signal.as_ref().map(|s| serde_json::json!({
            "kind": s.kind.as_str().to_owned(),
            "score": s.score,
        })),
        "pii_found": d.mask_summary,
        "rationale": d.rationale,
        "verdicts": verdicts,
        "relevance_downgraded": relevance_downgraded,
    });
    add_policy_fields(&mut out, d);
    say!("{out}");
    if d.action == redactify::policy::GuardAction::Block {
        std::process::exit(1);
    }
}

fn run_vault(text: &str, detector: &redactify::Detector<'_>, json_format: bool) {
    let (anon, vault) = detector.pseudonymize(text);
    if json_format {
        print_vault_json(&anon, &vault);
        return;
    }
    say!("{:<16} {}", "PSEUDONYMIZED:", anon);
    say!("{:<16} {} unique PII entries", "VAULT:", vault.len());
    for (placeholder, original) in vault.entries_iter() {
        say!("  [{placeholder}] -> {original}");
    }

    // Demo the round-trip
    let restored = vault.restore(&anon);
    say!();
    say!("{:<16} {}", "RESTORED:", restored);
    say!();
    say!("Library API:");
    say!("  let (anon, vault) = Detector::new().pseudonymize(prompt);");
    say!("  let response = llm_call(&anon);");
    say!("  let natural = vault.restore(&response);");
}

fn print_vault_json(anon: &str, vault: &redactify::Vault) {
    let entries: Vec<serde_json::Value> = vault
        .entries_iter()
        .map(|(placeholder, original)| {
            serde_json::json!({"placeholder": placeholder, "original": original})
        })
        .collect();
    let restored = vault.restore(anon);
    say!(
        "{}",
        serde_json::json!({
            "pseudonymized": anon,
            "entries": entries,
            "restored": restored,
        })
    );
}

/// FPR monitoring mode: runs the benign
/// canary corpus in a loop and reports FPR drift. Each iteration:
/// 1. runs `guard_all` on every canary text
/// 2. counts non-Allow outcomes as false positives
/// 3. reports per-iteration and cumulative FPR
/// 4. exits non-zero if the budget is exceeded (CI/ops gate)
///
/// Usage: `redactify --fpr-monitor [--interval-secs N] [--max-iterations N]`
/// (defaults: 5 seconds, 3 iterations).
fn run_fpr_monitor(interval_secs: u64, max_iterations: usize) {
    use redactify::policy::{guard_all, GuardAction};

    const CANARY: &[&str] = &[
        "merhaba dunya bugun hava cok guzel",
        "The quick brown fox jumps over the lazy dog",
        "Sipariş numaranız 12000345671 olarak kaydedildi.",
        "please summarize this document in three bullet points",
        "version 2.4.1 release notes published",
        "team standup at 9 retro at 14",
        "toplam tutar 1.450,90 TL odendi",
        "sunucu 10.0.0.5 uzerinden yanit verdi",
        "fatura no A-2026-0042 odendi",
        "hava 23 derece ruzgar guneyden",
    ];
    const BUDGET: f64 = 0.05; // 5% max FPR

    eprintln!(
        "FPR monitor: {} canary texts, {}s interval, max {} iterations (budget {:.0}%)",
        CANARY.len(),
        interval_secs,
        max_iterations,
        BUDGET * 100.0
    );

    let mut total_checks = 0usize;
    let mut total_fp = 0usize;

    for iteration in 1..=max_iterations {
        let mut fp = 0;
        for text in CANARY {
            let d = guard_all(text);
            if d.action != GuardAction::Allow {
                fp += 1;
                eprintln!(
                    "  FP: {:?} -> {:?} ({})",
                    &text[..text.len().min(50)],
                    d.action,
                    d.rationale
                );
            }
        }
        total_checks += CANARY.len();
        total_fp += fp;
        let iter_fpr = fp as f64 / CANARY.len() as f64;
        let cum_fpr = total_fp as f64 / total_checks as f64;
        eprintln!(
            "  iter {}/{}: FP {}/{}, FPR {:.3} (cumulative {:.3})",
            iteration,
            max_iterations,
            fp,
            CANARY.len(),
            iter_fpr,
            cum_fpr
        );

        if cum_fpr > BUDGET {
            eprintln!(
                "FPR BUDGET EXCEEDED: cumulative {:.3} > {:.1}%",
                cum_fpr,
                BUDGET * 100.0
            );
            std::process::exit(1);
        }

        if iteration < max_iterations {
            std::thread::sleep(std::time::Duration::from_secs(interval_secs));
        }
    }

    eprintln!(
        "FPR monitor PASSED: {} checks, {} FPs, cumulative FPR {:.3} (budget {:.1}%)",
        total_checks,
        total_fp,
        total_fp as f64 / total_checks as f64,
        BUDGET * 100.0
    );
}

/// One canonical selftest probe: a synthetic text and the value in it
/// (the value is only compared, never printed).
struct Probe {
    /// The printed probe name (an entity label, or `SECRET`).
    name: &'static str,
    /// The entity type, `None` for the secret probe.
    kind: Option<redactify::EntityType>,
    text: &'static str,
    value: &'static str,
    /// The locale pack the probe needs (`None`: locale-independent).
    locale: Option<&'static str>,
}

/// The canonical probes: synthetic values only (check digits valid, no
/// real person or account).
fn selftest_probes() -> [Probe; 7] {
    use redactify::EntityType as T;
    [
        Probe {
            name: "TCKN",
            kind: Some(T::Tckn),
            text: "TCKN 12345678950",
            value: "12345678950",
            locale: Some("tr"),
        },
        Probe {
            name: "IBAN",
            kind: Some(T::Iban),
            text: "IBAN TR330006100519786457841326",
            value: "TR330006100519786457841326",
            locale: None,
        },
        Probe {
            name: "CREDIT_CARD",
            kind: Some(T::CreditCard),
            text: "kart 4111 1111 1111 1111",
            value: "4111 1111 1111 1111",
            locale: None,
        },
        Probe {
            name: "PHONE",
            kind: Some(T::Phone),
            text: "tel 0532 123 45 67",
            value: "0532 123 45 67",
            locale: Some("tr"),
        },
        Probe {
            name: "EMAIL",
            kind: Some(T::Email),
            text: "mail ali@example.com",
            value: "ali@example.com",
            locale: None,
        },
        Probe {
            name: "NAME",
            kind: Some(T::Name),
            text: "M\u{fc}\u{15f}teri: Ahmet Y\u{131}lmaz",
            value: "Ahmet Y\u{131}lmaz",
            locale: Some("tr"),
        },
        Probe {
            name: "SECRET",
            kind: None,
            text: "key AKIAIOSFODNN7EXAMPLE",
            value: "AKIAIOSFODNN7EXAMPLE",
            locale: None,
        },
    ]
}

/// The outcome of one probe: status (`PASS`/`FAIL`/`SKIP`), the policy
/// action label and a content-free reason.
fn judge_probe(
    probe: &Probe,
    r: &redactify::policy::SanitizeResult,
    policy: Option<&redactify::policy::Policy>,
    locales: &[&str],
) -> (&'static str, &'static str, &'static str) {
    use redactify::policy::{EntityAction, GuardAction, GuardCategory};
    if probe.locale.is_some_and(|l| !locales.contains(&l)) {
        return ("SKIP", "-", "its locale pack is not selected");
    }
    let dry_run = r.decision.dry_run_action.is_some();
    let leaked = !dry_run && r.text.contains(probe.value);
    let Some(kind) = probe.kind else {
        if policy.is_some_and(|p| p.disabled.contains(&GuardCategory::Secrets)) {
            return ("SKIP", "-", "SECRETS is disabled by the policy");
        }
        let found = r
            .decision
            .signals
            .iter()
            .any(|s| s.kind == redactify::guard::SignalKind::Secrets);
        return match (found, leaked) {
            (false, _) => ("FAIL", "MASK", "not detected"),
            (true, true) => ("FAIL", "MASK", "detected but not masked"),
            (true, false) => ("PASS", "MASK", ""),
        };
    };
    let action = policy.map_or(EntityAction::Mask, |p| p.entity_actions.action_for(kind));
    if action == EntityAction::Ignore {
        return ("SKIP", action.as_str(), "ignored by the policy");
    }
    if !r.decision.entity_counts.iter().any(|c| c.kind == kind) {
        return ("FAIL", action.as_str(), "not detected");
    }
    let verdict = match action {
        EntityAction::Block if r.decision.decided_action() != GuardAction::Block => {
            ("FAIL", "configured BLOCK but the decision does not block")
        }
        EntityAction::Log if !dry_run && !r.text.contains(probe.value) => {
            ("FAIL", "configured LOG but masked")
        }
        EntityAction::Mask if leaked => ("FAIL", "detected but not masked"),
        _ => ("PASS", ""),
    };
    (verdict.0, action.as_str(), verdict.1)
}

/// `redactify selftest`: the canonical probes through the guard under the
/// loaded policy and locales; prints status and latency per probe, never a
/// value; exits 1 when any probe fails.
fn run_selftest(
    target: &redactify::policy::GuardTarget,
    policy: Option<&redactify::policy::Policy>,
    locales: &[&str],
    json_format: bool,
) {
    let guard = redactify::Guard::new(*target)
        .with_policy(policy)
        .with_locales(locales);
    // the effective locale list (the guard's own rule)
    let effective: Vec<&str> = if !locales.is_empty() {
        locales.to_vec()
    } else if let Some(p) = policy.filter(|p| !p.default_locales.is_empty()) {
        p.default_locales.iter().map(String::as_str).collect()
    } else {
        vec!["tr", "en"]
    };
    let probes = selftest_probes();
    // warm-up: the first scan compiles the rule set; the timed pass below
    // measures steady-state latency
    for p in &probes {
        let _ = guard.sanitize(p.text);
    }
    let dry_run = policy.is_some_and(|p| p.dry_run);
    let mut rows = Vec::with_capacity(probes.len());
    for p in &probes {
        let started = std::time::Instant::now();
        let r = guard.sanitize(p.text);
        let micros = started.elapsed().as_micros();
        let (status, action, reason) = judge_probe(p, &r, policy, &effective);
        rows.push((p.name, status, action, micros, reason));
    }
    let count = |s: &str| rows.iter().filter(|r| r.1 == s).count();
    let (passed, failed, skipped) = (count("PASS"), count("FAIL"), count("SKIP"));
    if json_format {
        let probes: Vec<serde_json::Value> = rows
            .iter()
            .map(|(name, status, action, micros, reason)| {
                serde_json::json!({
                    "probe": name,
                    "status": status.to_ascii_lowercase(),
                    "action": action,
                    "micros": micros,
                    "reason": reason,
                })
            })
            .collect();
        say!(
            "{}",
            serde_json::json!({
                "passed": passed,
                "failed": failed,
                "skipped": skipped,
                "dry_run": dry_run,
                "policy": policy.is_some(),
                "locales": effective,
                "probes": probes,
            })
        );
    } else {
        say!(
            "redactify selftest (policy: {}; locales: {}; dry run: {})",
            if policy.is_some() {
                "loaded"
            } else {
                "built-in"
            },
            effective.join(","),
            if dry_run {
                "ON, nothing is enforced"
            } else {
                "off"
            }
        );
        for (name, status, action, micros, reason) in &rows {
            if *status == "SKIP" {
                say!("{status}  {name:<12} {action:<7} {:>8}  {reason}", "-");
            } else {
                say!("{status}  {name:<12} {action:<7} {micros:>5} us  {reason}");
            }
        }
        say!(
            "{} probes: {passed} passed, {failed} failed, {skipped} skipped",
            rows.len()
        );
    }
    if failed > 0 {
        std::process::exit(1);
    }
}

/// `--probe`: entity types, byte offsets, scores, the rule (or custom rule
/// or recognizer) that found each one and the policy action, then the
/// decision. Never prints a value.
fn run_probe(
    text: &str,
    guard: &redactify::Guard<'_>,
    policy: Option<&redactify::policy::Policy>,
    json_format: bool,
) {
    use redactify::DetectionSource;
    let explained = guard.detector().explain(text);
    let d = guard.decide(text);
    let action_of = |kind: redactify::EntityType| {
        policy.map_or(redactify::policy::EntityAction::Mask, |p| {
            p.entity_actions.action_for(kind)
        })
    };
    let source = |s: &DetectionSource| match s {
        DetectionSource::Rule { id } => format!("rule {id}"),
        DetectionSource::Custom { index } => format!("custom rule #{index}"),
        DetectionSource::Ner { name } => format!("ner {name}"),
        _ => "other".to_owned(),
    };
    if json_format {
        let entities: Vec<serde_json::Value> = explained
            .iter()
            .map(|(e, why)| {
                serde_json::json!({
                    "type": e.kind.as_str(),
                    "start": e.start,
                    "end": e.end,
                    "score": e.score,
                    "source": source(&why.source),
                    "view": why.view.as_str(),
                    "action": action_of(e.kind).as_str(),
                })
            })
            .collect();
        say!(
            "{}",
            serde_json::json!({
                "entities": entities,
                "action": d.action.to_string(),
                "dry_run_action": d.dry_run_action.map(|a| a.to_string()),
                "rationale": d.rationale,
            })
        );
        return;
    }
    if explained.is_empty() {
        say!("No PII found.");
    } else {
        say!(
            "{:<16} {:>7} {:>7} {:>5} {:<7} SOURCE",
            "TYPE",
            "BEGIN",
            "END",
            "SCORE",
            "ACTION"
        );
        for (e, why) in &explained {
            say!(
                "{:<16} {:>7} {:>7} {:>5.2} {:<7} {}",
                e.kind.as_str(),
                e.start,
                e.end,
                e.score,
                action_of(e.kind).as_str(),
                source(&why.source)
            );
        }
    }
    say!();
    say!("{:<12} {}", "ACTION:", d.action);
    say!("{:<12} {}", "RATIONALE:", d.rationale);
}
