# RSI — raccourcis. La cible la plus simple : `make install`.

.PHONY: install build test demo connect clean ci

## install : compile et connecte RSI à ton agent IA (openclaw, hermes-agent…)
install:
	@./install.sh

## build : compile tous les binaires en release
build:
	cargo build --release --bins

## test : lance toute la suite de tests
test:
	cargo test

## demo : lance la simulation de démonstration
demo:
	cargo run --release --bin rsi-demo

## connect : (re)connecte le serveur MCP aux agents (sans recompiler)
connect:
	cargo run --release --bin rsi-connect

## ci : reproduit en local exactement les checks de la CI (clippy 0 warning +
## tests, en défaut puis avec les features publiques). À lancer avant de pousser.
ci:
	cargo clippy --all-targets --locked -- -D warnings
	cargo test --locked
	cargo clippy --all-targets --locked --features "wasm observability simd llm-ollama llm-claude-ureq" -- -D warnings
	cargo test --locked --features "wasm observability simd llm-ollama llm-claude-ureq"

## clean : nettoie les artefacts de build
clean:
	cargo clean
	rm -f forge_checkpoint.json
