use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const SUPPORTED_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema_version: u32,
    #[serde(default)]
    pub settings: Settings,
    pub targets: Vec<Target>,
    pub workloads: Vec<Workload>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub generate_single_provider_outages: bool,
    pub generate_single_region_outages: bool,
    pub max_routes_per_workload: usize,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            generate_single_provider_outages: true,
            generate_single_region_outages: false,
            max_routes_per_workload: 16,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub id: String,
    pub provider: String,
    pub region: String,
    #[serde(default)]
    pub external: bool,
    pub quality_bps: u16,
    pub cost_microunits: u64,
    pub p95_latency_ms: u64,
    #[serde(default)]
    pub capabilities: BTreeSet<String>,
    #[serde(default)]
    pub data_classes: BTreeSet<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Workload {
    pub id: String,
    pub data_class: String,
    #[serde(default)]
    pub allowed_regions: BTreeSet<String>,
    #[serde(default)]
    pub allow_external: bool,
    pub min_quality_bps: u16,
    pub max_cost_microunits: u64,
    pub max_p95_latency_ms: u64,
    #[serde(default)]
    pub required_capabilities: BTreeSet<String>,
    pub routes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    pub id: String,
    #[serde(default)]
    pub unavailable_targets: BTreeSet<String>,
    #[serde(default)]
    pub unavailable_providers: BTreeSet<String>,
    #[serde(default)]
    pub unavailable_regions: BTreeSet<String>,
}

impl Scenario {
    fn baseline() -> Self {
        Self {
            id: "baseline".to_owned(),
            unavailable_targets: BTreeSet::new(),
            unavailable_providers: BTreeSet::new(),
            unavailable_regions: BTreeSet::new(),
        }
    }

    fn target_is_available(&self, target: &Target) -> bool {
        !self.unavailable_targets.contains(&target.id)
            && !self.unavailable_providers.contains(&target.provider)
            && !self.unavailable_regions.contains(&target.region)
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Finding {
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workload: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scenario: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Decision {
    pub workload: String,
    pub scenario: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_target: Option<String>,
    pub skipped_targets: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct Summary {
    pub targets: usize,
    pub workloads: usize,
    pub scenarios: usize,
    pub decisions: usize,
    pub findings: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct InputDigests {
    pub config_sha256: String,
    pub scenarios_sha256: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub clean: bool,
    pub input_digests: InputDigests,
    pub summary: Summary,
    pub decisions: Vec<Decision>,
    pub findings: Vec<Finding>,
}

pub fn parse_config(input: &str) -> anyhow::Result<Config> {
    toml::from_str(input).map_err(|error| anyhow::anyhow!("invalid config TOML: {error}"))
}

pub fn parse_scenarios(input: &str) -> anyhow::Result<Vec<Scenario>> {
    if input.is_empty() {
        return Ok(Vec::new());
    }

    let mut scenarios = Vec::new();
    for (index, line) in input.lines().enumerate() {
        if line.trim().is_empty() {
            anyhow::bail!(
                "invalid scenarios JSONL: blank record at line {}",
                index + 1
            );
        }
        let scenario = serde_json::from_str(line).map_err(|error| {
            anyhow::anyhow!("invalid scenarios JSONL at line {}: {error}", index + 1)
        })?;
        scenarios.push(scenario);
    }
    Ok(scenarios)
}

pub fn audit(
    config: &Config,
    declared_scenarios: &[Scenario],
    config_bytes: &[u8],
    scenario_bytes: &[u8],
) -> Report {
    let mut findings = Vec::new();
    let targets = index_targets(config, &mut findings);
    validate_workloads(config, &targets, &mut findings);

    let scenarios = build_scenarios(config, declared_scenarios, &targets, &mut findings);
    let mut decisions = simulate(config, &targets, &scenarios, &mut findings);

    findings.sort();
    findings.dedup();
    decisions.sort();

    Report {
        schema_version: SUPPORTED_SCHEMA_VERSION,
        clean: findings.is_empty(),
        input_digests: InputDigests {
            config_sha256: sha256(config_bytes),
            scenarios_sha256: sha256(scenario_bytes),
        },
        summary: Summary {
            targets: config.targets.len(),
            workloads: config.workloads.len(),
            scenarios: scenarios.len(),
            decisions: decisions.len(),
            findings: findings.len(),
        },
        decisions,
        findings,
    }
}

fn index_targets<'a>(
    config: &'a Config,
    findings: &mut Vec<Finding>,
) -> BTreeMap<&'a str, &'a Target> {
    if config.schema_version != SUPPORTED_SCHEMA_VERSION {
        findings.push(global_finding(
            "CFG_SCHEMA_VERSION",
            format!(
                "schema_version {} is unsupported; expected {}",
                config.schema_version, SUPPORTED_SCHEMA_VERSION
            ),
        ));
    }
    if config.settings.max_routes_per_workload == 0 {
        findings.push(global_finding(
            "CFG_MAX_ROUTES_ZERO",
            "max_routes_per_workload must be greater than zero",
        ));
    }

    let mut targets = BTreeMap::new();
    for target in &config.targets {
        if target.id.trim().is_empty() {
            findings.push(global_finding(
                "CFG_EMPTY_TARGET_ID",
                "target id must not be empty",
            ));
            continue;
        }
        if target.provider.trim().is_empty() || target.region.trim().is_empty() {
            findings.push(Finding {
                code: "CFG_TARGET_IDENTITY".to_owned(),
                workload: None,
                scenario: None,
                target: Some(target.id.clone()),
                message: "target provider and region must not be empty".to_owned(),
            });
        }
        if target.quality_bps > 10_000 {
            findings.push(Finding {
                code: "CFG_TARGET_QUALITY".to_owned(),
                workload: None,
                scenario: None,
                target: Some(target.id.clone()),
                message: format!("quality_bps {} exceeds 10000", target.quality_bps),
            });
        }
        if targets.insert(target.id.as_str(), target).is_some() {
            findings.push(Finding {
                code: "CFG_DUPLICATE_TARGET".to_owned(),
                workload: None,
                scenario: None,
                target: Some(target.id.clone()),
                message: "target id is duplicated".to_owned(),
            });
        }
    }
    targets
}

fn validate_workloads(
    config: &Config,
    targets: &BTreeMap<&str, &Target>,
    findings: &mut Vec<Finding>,
) {
    let mut workload_ids = BTreeSet::new();
    for workload in &config.workloads {
        if !workload_ids.insert(workload.id.as_str()) {
            findings.push(workload_finding(
                "CFG_DUPLICATE_WORKLOAD",
                workload,
                None,
                "workload id is duplicated",
            ));
        }
        if workload.id.trim().is_empty() || workload.data_class.trim().is_empty() {
            findings.push(workload_finding(
                "CFG_WORKLOAD_IDENTITY",
                workload,
                None,
                "workload id and data_class must not be empty",
            ));
        }
        if workload.min_quality_bps > 10_000 {
            findings.push(workload_finding(
                "CFG_WORKLOAD_QUALITY",
                workload,
                None,
                format!("min_quality_bps {} exceeds 10000", workload.min_quality_bps),
            ));
        }
        if workload.routes.is_empty() {
            findings.push(workload_finding(
                "CFG_EMPTY_ROUTES",
                workload,
                None,
                "workload must declare at least one route",
            ));
        }
        if workload.routes.len() > config.settings.max_routes_per_workload {
            findings.push(workload_finding(
                "CFG_TOO_MANY_ROUTES",
                workload,
                None,
                format!(
                    "{} routes exceed configured maximum {}",
                    workload.routes.len(),
                    config.settings.max_routes_per_workload
                ),
            ));
        }

        let mut route_ids = BTreeSet::new();
        for route in &workload.routes {
            if !route_ids.insert(route.as_str()) {
                findings.push(workload_finding(
                    "CFG_DUPLICATE_ROUTE",
                    workload,
                    Some(route),
                    "route target is repeated",
                ));
            }
            let Some(target) = targets.get(route.as_str()).copied() else {
                findings.push(workload_finding(
                    "CFG_UNKNOWN_ROUTE",
                    workload,
                    Some(route),
                    "route references an unknown target",
                ));
                continue;
            };
            validate_route(workload, target, findings);
        }
    }
}

fn validate_route(workload: &Workload, target: &Target, findings: &mut Vec<Finding>) {
    if !target.data_classes.contains(&workload.data_class) {
        findings.push(workload_finding(
            "ROUTE_DATA_CLASS",
            workload,
            Some(&target.id),
            format!("target does not admit data class {}", workload.data_class),
        ));
    }
    if !workload.allowed_regions.is_empty() && !workload.allowed_regions.contains(&target.region) {
        findings.push(workload_finding(
            "ROUTE_REGION",
            workload,
            Some(&target.id),
            format!("target region {} is not allowed", target.region),
        ));
    }
    if target.external && !workload.allow_external {
        findings.push(workload_finding(
            "ROUTE_EXTERNAL",
            workload,
            Some(&target.id),
            "external target is forbidden for this workload",
        ));
    }
    if target.quality_bps < workload.min_quality_bps {
        findings.push(workload_finding(
            "ROUTE_QUALITY",
            workload,
            Some(&target.id),
            format!(
                "quality {} is below minimum {} basis points",
                target.quality_bps, workload.min_quality_bps
            ),
        ));
    }
    if target.cost_microunits > workload.max_cost_microunits {
        findings.push(workload_finding(
            "ROUTE_COST",
            workload,
            Some(&target.id),
            format!(
                "cost {} exceeds maximum {} microunits",
                target.cost_microunits, workload.max_cost_microunits
            ),
        ));
    }
    if target.p95_latency_ms > workload.max_p95_latency_ms {
        findings.push(workload_finding(
            "ROUTE_LATENCY",
            workload,
            Some(&target.id),
            format!(
                "p95 latency {} exceeds maximum {} ms",
                target.p95_latency_ms, workload.max_p95_latency_ms
            ),
        ));
    }
    let missing: Vec<_> = workload
        .required_capabilities
        .difference(&target.capabilities)
        .cloned()
        .collect();
    if !missing.is_empty() {
        findings.push(workload_finding(
            "ROUTE_CAPABILITY",
            workload,
            Some(&target.id),
            format!("target lacks required capabilities: {}", missing.join(", ")),
        ));
    }
}

fn build_scenarios(
    config: &Config,
    declared: &[Scenario],
    targets: &BTreeMap<&str, &Target>,
    findings: &mut Vec<Finding>,
) -> Vec<Scenario> {
    let mut scenarios = vec![Scenario::baseline()];
    let mut ids = BTreeSet::from(["baseline".to_owned()]);

    for scenario in declared {
        if scenario.id.trim().is_empty() {
            findings.push(global_finding(
                "CFG_EMPTY_SCENARIO_ID",
                "scenario id must not be empty",
            ));
            continue;
        }
        if !ids.insert(scenario.id.clone()) {
            findings.push(Finding {
                code: "CFG_DUPLICATE_SCENARIO".to_owned(),
                workload: None,
                scenario: Some(scenario.id.clone()),
                target: None,
                message: "scenario id is duplicated or reserved".to_owned(),
            });
            continue;
        }
        for unavailable in &scenario.unavailable_targets {
            if !targets.contains_key(unavailable.as_str()) {
                findings.push(Finding {
                    code: "CFG_UNKNOWN_UNAVAILABLE_TARGET".to_owned(),
                    workload: None,
                    scenario: Some(scenario.id.clone()),
                    target: Some(unavailable.clone()),
                    message: "scenario references an unknown unavailable target".to_owned(),
                });
            }
        }
        scenarios.push(scenario.clone());
    }

    if config.settings.generate_single_provider_outages {
        let providers: BTreeSet<_> = targets.values().map(|target| &target.provider).collect();
        for provider in providers {
            let id = format!("generated:provider:{provider}");
            if ids.insert(id.clone()) {
                scenarios.push(Scenario {
                    id,
                    unavailable_targets: BTreeSet::new(),
                    unavailable_providers: BTreeSet::from([provider.clone()]),
                    unavailable_regions: BTreeSet::new(),
                });
            }
        }
    }

    if config.settings.generate_single_region_outages {
        let regions: BTreeSet<_> = targets.values().map(|target| &target.region).collect();
        for region in regions {
            let id = format!("generated:region:{region}");
            if ids.insert(id.clone()) {
                scenarios.push(Scenario {
                    id,
                    unavailable_targets: BTreeSet::new(),
                    unavailable_providers: BTreeSet::new(),
                    unavailable_regions: BTreeSet::from([region.clone()]),
                });
            }
        }
    }
    scenarios.sort_by(|left, right| left.id.cmp(&right.id));
    scenarios
}

fn simulate(
    config: &Config,
    targets: &BTreeMap<&str, &Target>,
    scenarios: &[Scenario],
    findings: &mut Vec<Finding>,
) -> Vec<Decision> {
    let mut decisions = Vec::new();
    for workload in &config.workloads {
        for scenario in scenarios {
            let selected = workload
                .routes
                .iter()
                .enumerate()
                .find_map(|(index, route)| {
                    targets
                        .get(route.as_str())
                        .copied()
                        .filter(|target| scenario.target_is_available(target))
                        .map(|target| (index, target))
                });
            match selected {
                Some((index, target)) => decisions.push(Decision {
                    workload: workload.id.clone(),
                    scenario: scenario.id.clone(),
                    selected_target: Some(target.id.clone()),
                    skipped_targets: index,
                }),
                None => {
                    findings.push(Finding {
                        code: "SCENARIO_NO_ROUTE".to_owned(),
                        workload: Some(workload.id.clone()),
                        scenario: Some(scenario.id.clone()),
                        target: None,
                        message: "no declared route remains available".to_owned(),
                    });
                    decisions.push(Decision {
                        workload: workload.id.clone(),
                        scenario: scenario.id.clone(),
                        selected_target: None,
                        skipped_targets: workload.routes.len(),
                    });
                }
            }
        }
    }
    decisions
}

fn workload_finding(
    code: &str,
    workload: &Workload,
    target: Option<&str>,
    message: impl Into<String>,
) -> Finding {
    Finding {
        code: code.to_owned(),
        workload: Some(workload.id.clone()),
        scenario: None,
        target: target.map(ToOwned::to_owned),
        message: message.into(),
    }
}

fn global_finding(code: &str, message: impl Into<String>) -> Finding {
    Finding {
        code: code.to_owned(),
        workload: None,
        scenario: None,
        target: None,
        message: message.into(),
    }
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn render_text(report: &Report) -> String {
    let mut output = String::new();
    output.push_str(if report.clean {
        "fallback-lint: PASS\n"
    } else {
        "fallback-lint: FAIL\n"
    });
    output.push_str(&format!(
        "targets={} workloads={} scenarios={} decisions={} findings={}\n",
        report.summary.targets,
        report.summary.workloads,
        report.summary.scenarios,
        report.summary.decisions,
        report.summary.findings
    ));
    output.push_str(&format!(
        "config_sha256={} scenarios_sha256={}\n",
        report.input_digests.config_sha256, report.input_digests.scenarios_sha256
    ));
    for finding in &report.findings {
        let mut context = Vec::new();
        if let Some(workload) = &finding.workload {
            context.push(format!("workload={workload}"));
        }
        if let Some(scenario) = &finding.scenario {
            context.push(format!("scenario={scenario}"));
        }
        if let Some(target) = &finding.target {
            context.push(format!("target={target}"));
        }
        let suffix = if context.is_empty() {
            String::new()
        } else {
            format!(" [{}]", context.join(" "))
        };
        output.push_str(&format!(
            "{}{}: {}\n",
            finding.code, suffix, finding.message
        ));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clean_config() -> Config {
        parse_config(
            r#"
schema_version = 1

[settings]
generate_single_provider_outages = true
generate_single_region_outages = false
max_routes_per_workload = 4

[[targets]]
id = "local-a"
provider = "local"
region = "ca-central"
quality_bps = 9200
cost_microunits = 10
p95_latency_ms = 80
capabilities = ["tools"]
data_classes = ["restricted"]

[[targets]]
id = "local-b"
provider = "backup"
region = "ca-central"
quality_bps = 9100
cost_microunits = 15
p95_latency_ms = 100
capabilities = ["tools"]
data_classes = ["restricted"]

[[workloads]]
id = "support"
data_class = "restricted"
allowed_regions = ["ca-central"]
allow_external = false
min_quality_bps = 9000
max_cost_microunits = 20
max_p95_latency_ms = 120
required_capabilities = ["tools"]
routes = ["local-a", "local-b"]
"#,
        )
        .expect("valid config")
    }

    #[test]
    fn clean_cross_provider_ladder_survives_provider_outages() {
        let config = clean_config();
        let report = audit(&config, &[], b"config", b"");
        assert!(report.clean);
        assert_eq!(report.summary.scenarios, 3);
        assert_eq!(report.summary.decisions, 3);
    }

    #[test]
    fn catches_policy_drift_in_dormant_fallback() {
        let mut config = clean_config();
        config.targets[1].region = "us-east".to_owned();
        config.targets[1].external = true;
        let report = audit(&config, &[], b"config", b"");
        let codes: BTreeSet<_> = report
            .findings
            .iter()
            .map(|finding| finding.code.as_str())
            .collect();
        assert!(codes.contains("ROUTE_REGION"));
        assert!(codes.contains("ROUTE_EXTERNAL"));
    }

    #[test]
    fn reports_no_route_when_scenario_exhausts_ladder() {
        let config = clean_config();
        let scenarios = vec![Scenario {
            id: "total".to_owned(),
            unavailable_targets: BTreeSet::from(["local-a".to_owned(), "local-b".to_owned()]),
            unavailable_providers: BTreeSet::new(),
            unavailable_regions: BTreeSet::new(),
        }];
        let report = audit(&config, &scenarios, b"config", b"scenario");
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.code == "SCENARIO_NO_ROUTE"
                && finding.scenario.as_deref() == Some("total")));
    }

    #[test]
    fn rejects_blank_jsonl_records() {
        let error = parse_scenarios("{\"id\":\"one\"}\n\n{\"id\":\"two\"}")
            .expect_err("blank record must fail");
        assert!(error.to_string().contains("blank record at line 2"));
    }
}
