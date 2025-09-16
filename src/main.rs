// src/main.rs
use anyhow::Result;
use clap::{ArgAction, Parser, ValueEnum};
use ignore::WalkBuilder;
use rayon::prelude::*;
use regex::Regex;
use serde::Serialize;
use serde_json::Value as Json;
use serde_yaml::Value as Yaml;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs,
    path::{Path, PathBuf},
};
use thiserror::Error;

#[derive(Parser, Debug)]
#[command(name="npminspect", version, about="Traverse directories to aggregate npm packages and versions from package.json and lockfiles")]
struct Cli {
    /// Root path to scan (defaults to current directory)
    #[arg(default_value = ".")]
    path: PathBuf,

    /// Output format
    #[arg(long, value_enum, default_value_t=Format::Table)]
    format: Format,

    /// Include dev/peer/optional deps from package.json in the output
    #[arg(long, default_value_t=true, action=ArgAction::Set)]
    include_non_runtime: bool,

    /// Do not respect .gitignore files
    #[arg(long)]
    no_gitignore: bool,

    /// Follow symlinks
    #[arg(long)]
    follow_symlinks: bool,

    /// Write output to a file (use '-' for stdout)
    #[arg(short, long, value_name="FILE")]
    output: Option<PathBuf>,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum Format {
    Table,
    Json,
}

#[derive(Debug, Clone, Serialize)]
struct Occurrence {
    source_file: String,
    source_kind: SourceKind,
    /// For package.json: requested range (e.g., ^1.2.3); for lockfiles: resolved version
    spec: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
enum SourceKind {
    PackageJson,
    PackageLock,
    NpmShrinkwrap,
    YarnLock,
    PnpmLock,
}

#[derive(Debug, Default, Serialize)]
struct PackageAggregate {
    /// Unique set of resolved versions seen in lockfiles (if any)
    resolved_versions: BTreeSet<String>,
    /// Unique set of version ranges requested by manifests (if any)
    requested_ranges: BTreeSet<String>,
    occurrences: Vec<Occurrence>,
}

#[derive(Debug, Default, Serialize)]
struct Inventory {
    /// name -> aggregate data
    packages: BTreeMap<String, PackageAggregate>,
    /// files that failed to parse (non-fatal)
    errors: Vec<ScanError>,
}

#[derive(Debug, Serialize)]
struct ScanError {
    file: String,
    message: String,
}

#[derive(Error, Debug)]
enum ParseErr {
    #[error("io error: {0}")]
    Io(String),
    #[error("json parse error: {0}")]
    Json(String),
    #[error("yaml parse error: {0}")]
    Yaml(String),
    #[error("format not recognized")]
    Unknown,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let walker = {
        let mut w = WalkBuilder::new(&cli.path);
        w.hidden(false)
            .git_ignore(!cli.no_gitignore)
            .git_global(!cli.no_gitignore)
            .git_exclude(!cli.no_gitignore)
            .parents(true)
            .follow_links(cli.follow_symlinks);
        // ignore::WalkBuilder does not expose max_open; rely on its defaults
        w.build()
    };

    // Collect interesting files first to enable parallel parsing
    let mut interesting: Vec<PathBuf> = Vec::new();
    for dent in walker {
        let dent = match dent {
            Ok(d) => d,
            Err(_) => continue,
        };
        if !dent.file_type().map(|ft| ft.is_file()).unwrap_or(false) {
            continue;
        }
        let name = dent.file_name().to_string_lossy();
        if matches!(
            &*name,
            "package.json"
                | "package-lock.json"
                | "npm-shrinkwrap.json"
                | "yarn.lock"
                | "pnpm-lock.yaml"
                | "pnpm-lock.yml"
        ) {
            interesting.push(dent.into_path());
        }
    }

    // Parse in parallel
    let mut inventory = Inventory::default();
    let results: Vec<(Option<(String, ParsedArtifact)>, Option<ScanError>)> = interesting
        .par_iter()
        .map(|path| {
            let path_str = path.to_string_lossy().to_string();
            match parse_file(path) {
                Ok(parsed) => (Some((path_str, parsed)), None),
                Err(e) => (
                    None,
                    Some(ScanError {
                        file: path_str,
                        message: format!("{e}"),
                    }),
                ),
            }
        })
        .collect();

    for (ok, err) in results {
        if let Some(err) = err {
            inventory.errors.push(err);
            continue;
        }
        if let Some((path, parsed)) = ok {
            merge_parsed(&mut inventory, &path, parsed);
        }
    }

    // Print or write to file
    if let Some(path) = &cli.output {
        let buf = match cli.format {
            Format::Json => serde_json::to_string_pretty(&inventory)?,
            Format::Table => render_table(&inventory),
        };
        if path.as_os_str() == "-" {
            println!("{}", buf);
        } else {
            fs::write(path, buf)?;
        }
    } else {
        match cli.format {
            Format::Json => println!("{}", serde_json::to_string_pretty(&inventory)?),
            Format::Table => print_table(&inventory),
        }
    }
    Ok(())
}

fn print_table(inv: &Inventory) {
    println!("{}", render_table(inv));
}

fn render_table(inv: &Inventory) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let mut names: Vec<_> = inv.packages.keys().cloned().collect();
    names.sort_unstable();

    out.push_str("Packages found:\n");
    out.push_str("──────────────────────────────────────────────────────────────────────────────\n");
    for name in names {
        if let Some(agg) = inv.packages.get(&name) {
            let requested = if agg.requested_ranges.is_empty() {
                "-".to_string()
            } else {
                agg.requested_ranges.iter().cloned().collect::<Vec<_>>().join(", ")
            };
            let resolved = if agg.resolved_versions.is_empty() {
                "-".to_string()
            } else {
                agg.resolved_versions
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            let _ = writeln!(
                out,
                "{:<40} requested: {:<25} resolved: {}",
                truncate(&name, 40),
                truncate(&requested, 25),
                resolved
            );
        }
    }
    if !inv.errors.is_empty() {
        out.push_str("\nNon-fatal parse errors:\n");
        out.push_str("───────────────────────\n");
        for e in &inv.errors {
            let _ = writeln!(
                out,
                "• {} — {}",
                truncate(&e.file, 60),
                truncate(&e.message, 80)
            );
        }
    }
    out
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let mut out = s.chars().take(max.saturating_sub(1)).collect::<String>();
        out.push('…');
        out
    }
}

#[derive(Debug)]
enum ParsedArtifact {
    PackageJson(HashMap<String, String>), // name -> range
    PackageLock(HashMap<String, String>), // name -> resolved version
    YarnLock(HashMap<String, String>),    // name -> resolved version
    PnpmLock(HashMap<String, String>),    // name -> resolved version
    NpmShrinkwrap(HashMap<String, String>),
}

fn parse_file(path: &Path) -> Result<ParsedArtifact, ParseErr> {
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    let data = fs::read(path).map_err(|e| ParseErr::Io(e.to_string()))?;
    match name {
        "package.json" => parse_package_json(&data),
        "package-lock.json" => parse_package_lock(&data),
        "npm-shrinkwrap.json" => parse_package_lock(&data).and_then(|p| match p {
            ParsedArtifact::PackageLock(map) => Ok(ParsedArtifact::NpmShrinkwrap(map)),
            other => Ok(other),
        }),
        "yarn.lock" => parse_yarn_lock(&data),
        "pnpm-lock.yaml" | "pnpm-lock.yml" => parse_pnpm_lock(&data),
        _ => Err(ParseErr::Unknown),
    }
}

fn merge_parsed(inv: &mut Inventory, path: &str, parsed: ParsedArtifact) {
    match parsed {
        ParsedArtifact::PackageJson(map) => {
            for (name, rng) in map {
                let entry = inv.packages.entry(name.clone()).or_default();
                entry.requested_ranges.insert(rng.clone());
                entry.occurrences.push(Occurrence {
                    source_file: path.to_string(),
                    source_kind: SourceKind::PackageJson,
                    spec: rng,
                });
            }
        }
        ParsedArtifact::PackageLock(map) => merge_lock(inv, path, map, SourceKind::PackageLock),
        ParsedArtifact::NpmShrinkwrap(map) => {
            merge_lock(inv, path, map, SourceKind::NpmShrinkwrap)
        }
        ParsedArtifact::YarnLock(map) => merge_lock(inv, path, map, SourceKind::YarnLock),
        ParsedArtifact::PnpmLock(map) => merge_lock(inv, path, map, SourceKind::PnpmLock),
    }
}

fn merge_lock(
    inv: &mut Inventory,
    path: &str,
    map: HashMap<String, String>,
    kind: SourceKind,
) {
    for (name, ver) in map {
        let entry = inv.packages.entry(name.clone()).or_default();
        entry.resolved_versions.insert(ver.clone());
        entry.occurrences.push(Occurrence {
            source_file: path.to_string(),
            source_kind: kind.clone(),
            spec: ver,
        });
    }
}

// ---------- Parsers ----------

fn parse_package_json(bytes: &[u8]) -> Result<ParsedArtifact, ParseErr> {
    let v: Json = serde_json::from_slice(bytes)
        .map_err(|e| ParseErr::Json(format!("package.json: {e}")))?;
    let mut map = HashMap::new();
    for key in ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"] {
        if let Some(obj) = v.get(key).and_then(|j| j.as_object()) {
            for (name, spec) in obj {
                if let Some(spec_str) = spec.as_str() {
                    map.insert(name.to_string(), spec_str.to_string());
                }
            }
        }
    }
    Ok(ParsedArtifact::PackageJson(map))
}

/// Parses npm package-lock.json (v1 and v2+)
fn parse_package_lock(bytes: &[u8]) -> Result<ParsedArtifact, ParseErr> {
    let v: Json = serde_json::from_slice(bytes)
        .map_err(|e| ParseErr::Json(format!("package-lock.json: {e}")))?;

    let mut map = HashMap::new();

    // v2+ format: "packages": { "node_modules/foo": { "version": "1.2.3", "name": "foo" }, ... }
    if let Some(packages) = v.get("packages").and_then(|p| p.as_object()) {
        for (_path, pkg) in packages {
            let version = pkg
                .get("version")
                .and_then(|s| s.as_str())
                .unwrap_or_default()
                .to_string();
            let name = pkg
                .get("name")
                .and_then(|s| s.as_str())
                .map(|s| s.to_string());
            if let Some(name) = name {
                if !version.is_empty() {
                    map.entry(name).or_insert(version);
                }
            }
        }
    }

    // v1 format: "dependencies": { "foo": { "version": "1.2.3", "requires": {..}, "dependencies": {...}}}
    if map.is_empty() {
        if let Some(deps) = v.get("dependencies").and_then(|d| d.as_object()) {
            fn walk_v1(acc: &mut HashMap<String, String>, obj: &serde_json::Map<String, Json>) {
                for (name, val) in obj {
                    if let Some(version) = val.get("version").and_then(|s| s.as_str()) {
                        acc.entry(name.clone()).or_insert(version.to_string());
                    }
                    if let Some(child) = val.get("dependencies").and_then(|d| d.as_object()) {
                        walk_v1(acc, child);
                    }
                }
            }
            walk_v1(&mut map, deps);
        }
    }

    Ok(ParsedArtifact::PackageLock(map))
}

/// Best-effort yarn.lock (v1/classic) parser. It scans for top-level entries and extracts the "version" field.
fn parse_yarn_lock(bytes: &[u8]) -> Result<ParsedArtifact, ParseErr> {
    let text = String::from_utf8_lossy(bytes);
    let mut map = HashMap::new();

    // Top-level entry line (no leading spaces) ending with ':'
    let re_key = Regex::new(r#"^([^\s].*?):\s*$"#).unwrap();
    // version "1.2.3"
    let re_version = Regex::new(r#"^\s*version\s+\"([^\"]+)\""#).unwrap();

    let mut current_keys: Vec<String> = Vec::new();
    let mut current_version: Option<String> = None;

    for line in text.lines() {
        if let Some(cap) = re_key.captures(line) {
            // Commit previous block
            if let Some(ver) = current_version.take() {
                for k in current_keys.drain(..) {
                    if let Some(name) = extract_pkg_name_from_yarn_spec(&k) {
                        map.entry(name).or_insert(ver.clone());
                    }
                }
            }
            // Start new block: can be multiple specs separated by ", "
            let raw = cap[1].trim().trim_matches('"');
            current_keys = raw.split(", ").map(|s| s.trim().to_string()).collect();
            current_version = None;
        } else if let Some(cap) = re_version.captures(line) {
            current_version = Some(cap[1].to_string());
        }
    }
    // Final block
    if let Some(ver) = current_version {
        for k in current_keys.drain(..) {
            if let Some(name) = extract_pkg_name_from_yarn_spec(&k) {
                map.entry(name).or_insert(ver.clone());
            }
        }
    }

    Ok(ParsedArtifact::YarnLock(map))
}

/// Extracts package name from a yarn spec line like:
///  - lodash@^4.17.21
///  - "@scope/name@^1.2.3"
///  - lodash@npm:4.17.21
///  - "@scope/name@npm:^1.2.3"
fn extract_pkg_name_from_yarn_spec(spec: &str) -> Option<String> {
    let s = spec.trim().trim_matches('"');
    if s.starts_with('@') {
        // scoped: find the second '@'
        let mut parts = s.splitn(3, '@');
        let _empty = parts.next(); // leading empty before scope due to starting '@'
        let scope = parts.next()?;
        let rest = parts.next()?;
        let name_rest = format!("@{scope}@{rest}");
        // Now "@scope/name@something"
        // Extract until the last '/' before the following '@'
        if let Some(idx) = name_rest.find('@') {
            let name_part = &name_rest[..idx];
            return Some(name_part.to_string());
        }
        None
    } else {
        // unscoped: take up to first '@'
        s.split('@').next().map(|x| x.to_string())
    }
}

/// Parses pnpm-lock.yaml: keys under "packages" are like "/name@1.2.3" or "/@scope/name@1.2.3"
fn parse_pnpm_lock(bytes: &[u8]) -> Result<ParsedArtifact, ParseErr> {
    let y: Yaml =
        serde_yaml::from_slice(bytes).map_err(|e| ParseErr::Yaml(format!("pnpm-lock.yaml: {e}")))?;
    let mut map = HashMap::new();

    if let Some(pkgs) = y.get("packages").and_then(|v| v.as_mapping()) {
        for (k, _v) in pkgs {
            if let Some(key) = k.as_str() {
                // Key example: "/lodash@4.17.21" or "/@scope/name@1.2.3"
                if let Some((name, ver)) = split_pnpm_key(key) {
                    map.entry(name.to_string()).or_insert(ver.to_string());
                }
            }
        }
    }

    Ok(ParsedArtifact::PnpmLock(map))
}

fn split_pnpm_key(key: &str) -> Option<(&str, &str)> {
    // strip leading slash(es)
    let k = key.trim_start_matches('/');
    // find last '@' which precedes the version
    let last_at = k.rfind('@')?;
    let (name, ver) = k.split_at(last_at);
    let ver = &ver[1..]; // skip '@'
    Some((name, ver))
}
