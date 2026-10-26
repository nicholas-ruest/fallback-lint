use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;

const CLEAN: &str = r#"
schema_version = 1

[settings]
generate_single_provider_outages = false
generate_single_region_outages = false
max_routes_per_workload = 4

[[targets]]
id = "primary"
provider = "one"
region = "ca"
quality_bps = 9000
cost_microunits = 20
p95_latency_ms = 100
capabilities = ["json"]
data_classes = ["internal"]

[[workloads]]
id = "summarize"
data_class = "internal"
allowed_regions = ["ca"]
min_quality_bps = 8500
max_cost_microunits = 30
max_p95_latency_ms = 120
required_capabilities = ["json"]
routes = ["primary"]
"#;

#[test]
fn clean_policy_exits_zero() {
    let directory = tempfile::tempdir().expect("tempdir");
    let config = directory.path().join("config.toml");
    fs::write(&config, CLEAN).expect("write config");

    Command::cargo_bin("fallback-lint")
        .expect("binary")
        .args(["--config", config.to_str().expect("path")])
        .assert()
        .success()
        .stdout(predicate::str::contains("fallback-lint: PASS"));
}

#[test]
fn outage_dead_end_exits_two_with_json_report() {
    let directory = tempfile::tempdir().expect("tempdir");
    let config = directory.path().join("config.toml");
    let scenarios = directory.path().join("scenarios.jsonl");
    fs::write(&config, CLEAN).expect("write config");
    fs::write(
        &scenarios,
        "{\"id\":\"primary-down\",\"unavailable_targets\":[\"primary\"]}\n",
    )
    .expect("write scenarios");

    Command::cargo_bin("fallback-lint")
        .expect("binary")
        .args([
            "--config",
            config.to_str().expect("path"),
            "--scenarios",
            scenarios.to_str().expect("path"),
            "--format",
            "json",
        ])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("SCENARIO_NO_ROUTE"));
}

#[test]
fn malformed_config_exits_one() {
    let directory = tempfile::tempdir().expect("tempdir");
    let config = directory.path().join("config.toml");
    fs::write(&config, "schema_version = nope").expect("write config");

    Command::cargo_bin("fallback-lint")
        .expect("binary")
        .args(["--config", config.to_str().expect("path")])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("invalid config TOML"));
}
