# redactify - development & container workflow
#
# GNU Make 4.x (tab-indented recipes). Works in Git Bash on Windows and Linux.
# Common: make help | make test | make serve | make docker-up | make clean

SHELL := /bin/sh

CARGO     ?= cargo
FEATURES  ?= api          # features for build/serve targets
PORT      ?= 8080
ADDR      ?= 127.0.0.1:$(PORT)
IMAGE     ?= redactify:local
COMPOSE   ?= docker compose
PID_FILE  ?= .serve.pid
LOG_FILE  ?= .serve.log

.PHONY: help build release serve run stop status test test-api test-serde test-config test-ml \
        fmt clippy lint doc bench check-english fuzz clean distclean \
        docker-build docker-up docker-down docker-logs docker-smoke docker-clean

help: ## show this help
	@printf 'targets:\n'
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-16s %s\n",$$1,$$2}'

build: ## cargo build (debug)
	$(CARGO) build

release: ## cargo build --release
	$(CARGO) build --release

serve: ## run the REST API in the foreground (ADDR=127.0.0.1:8080)
	$(CARGO) run --release --features $(FEATURES) -- --serve $(ADDR)

run: ## start the REST API in the background (PID/LOG files)
	$(CARGO) build --release --features $(FEATURES)
	@$(CARGO) run --release --features $(FEATURES) -- --serve $(ADDR) >$(LOG_FILE) 2>&1 </dev/null & echo $$! > $(PID_FILE)
	@sleep 1 && curl -fsS http://$(ADDR)/health && echo

stop: ## stop the background server started by `make run`
	@if [ -f $(PID_FILE) ]; then 	kill $$(cat $(PID_FILE)) 2>/dev/null || true; 	rm -f $(PID_FILE); 	echo "stopped (pid file removed)"; 	fi
	@# the pid points at `cargo run`, whose server CHILD can outlive it on
	@# Unix - always finish with the pattern kill (harmless when idle)
	@if [ "$(OS)" = "Windows_NT" ]; then 	taskkill //IM redactify.exe //F 2>/dev/null || true; 	else 	pkill -f 'redactify.*--serve' 2>/dev/null || true; 	fi

status: ## health-check whatever runs on ADDR
	@curl -fsS http://$(ADDR)/health && echo || echo "not reachable on $(ADDR)"

test: ## full test suite (default features)
	$(CARGO) --locked test

check-english: ## fail on Turkish prose outside the functional allowlist
	$(CARGO) --locked test --test english_only

test-api: ## full test suite incl. REST API tests
	$(CARGO) --locked test --features api

test-serde: ## full test suite incl. serde round-trip tests
	$(CARGO) --locked test --features serde

test-config: ## full test suite incl. TOML policy tests (+ the api+config policy_config tests)
	$(CARGO) --locked test --features config
	$(CARGO) --locked test --features "api config" --test policy_config

test-ml: ## full test suite incl. ONNX tests (real-model tests skip without ml_models/)
	$(CARGO) --locked test --features ml-onnx

fmt: ## rustfmt
	$(CARGO) fmt

clippy: ## clippy, all feature configurations, warnings as errors (mirrors the CI lint job)
	$(CARGO) --locked clippy --all-targets -- -D warnings
	$(CARGO) --locked clippy --all-targets --features api -- -D warnings
	$(CARGO) --locked clippy --all-targets --features "api ml-onnx" -- -D warnings
	$(CARGO) --locked clippy --all-targets --features "api serde" -- -D warnings
	$(CARGO) --locked clippy --all-targets --features "api config" -- -D warnings

doc: ## rustdoc with warnings denied (mirrors the CI doc job)
	RUSTDOCFLAGS="-D warnings" $(CARGO) --locked doc --no-deps --features "api ml-onnx serde config"

lint: fmt clippy ## fmt + clippy

clean: ## cargo clean + local server artifacts
	$(CARGO) clean
	rm -f $(PID_FILE) $(LOG_FILE)

distclean: clean ## also remove the local docker image
	docker rmi -f $(IMAGE) 2>/dev/null || true

bench: ## run the criterion benchmarks (detect/redact/guard chain)
	$(CARGO) bench --bench pii

FUZZ_TIME ?= 60

fuzz: ## coverage-guided fuzzing smoke run (needs nightly: rustup toolchain install nightly)
	cargo +nightly fuzz run detect -- -max_total_time=$(FUZZ_TIME)
	cargo +nightly fuzz run normalize -- -max_total_time=$(FUZZ_TIME)

docker-build: ## build the container image
	docker build -t $(IMAGE) .

docker-up: ## build + start the stack via docker compose
	$(COMPOSE) up -d --build

docker-down: ## stop the compose stack
	$(COMPOSE) down

docker-logs: ## follow compose logs
	$(COMPOSE) logs -f

docker-smoke: ## curl the compose-served API
	@curl -fsS http://127.0.0.1:$(PORT)/health && echo
	@curl -fsS -X POST http://127.0.0.1:$(PORT)/v1/guard \
	-H 'Content-Type: application/json' \
	-d '{"text":"TCKN 12345678950 and see http://169.254.169.254/meta"}' && echo

docker-clean: docker-down ## stop the stack and remove the image
	docker rmi -f $(IMAGE) 2>/dev/null || true
