# fallback-lint

`fallback-lint` is a deterministic Rust CLI for auditing ordered AI-model and backend fallback ladders before an outage turns a safe primary route into an unsafe degraded route.

It checks every declared fallback against data-class, region, external-processing, quality, cost, latency, and capability constraints. It then simulates declared outages plus optional single-provider and single-region failures, reporting any workload left without an available route.

## Why

Adaptive routers usually prove that the selected primary is acceptable. Operations often maintain a separate ordered fallback list, where dormant entries can drift past residency, privacy, quality, or budget boundaries. `fallback-lint` makes those degraded-mode paths reviewable in CI.

## Install

```bash
cargo install --path .
```

Stable Rust is supported; the minimum supported version is Rust 1.85.

## Use

Audit the included healthy policy:

```bash
cargo run --release -- \
  --config examples/fallbacks.toml \
  --scenarios examples/outages.jsonl
```

Inspect machine-readable findings from an intentionally unsafe ladder:

```bash
cargo run --release -- \
  --config examples/unsafe-fallbacks.toml \
  --format json
```

Exit codes are `0` for a clean audit, `2` for policy or availability findings, and `1` for malformed input or runtime errors. Use `--output report.json` to write the selected report format to a file.

## Input model

The strict TOML configuration declares:

- targets with provider, region, external-processing status, quality in basis points, cost in integer microunits, p95 latency, capabilities, and admitted data classes;
- workloads with hard constraints and an ordered target ladder;
- whether to generate every single-provider and single-region outage.

Optional strict JSONL scenarios declare unavailable target, provider, or region sets. Blank records, unknown fields, duplicate IDs, unknown targets, and unsupported schema versions fail closed as errors or findings. Reports include SHA-256 identifiers for both input byte streams.

## Verification

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo build --release --all-features
cargo package --allow-dirty
cargo audit
```

CI repeats formatting, Clippy, tests, and release builds on stable Rust and Rust 1.85.

## Scope and limitations

`fallback-lint` is an offline configuration auditor. Metrics and outage sets are caller-declared; it does not measure providers, execute traffic, prove scenario completeness, infer correlated failures, or enforce runtime routing. Quality basis points and cost microunits are domain-defined integers. Generated failures are single-provider or single-region only; declare compound scenarios explicitly. Input digests identify bytes but are not signatures.

## License

MIT
