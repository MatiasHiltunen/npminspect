// src/tree.rs
//! Dependency tree rendering with colored output and vulnerability highlighting.

use crate::audit::AuditResult;
use colored::Colorize;
use regex::Regex;
use serde_json::Value as Json;
use serde_yaml::Value as Yaml;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// The type of lockfile that was parsed.
#[derive(Debug, Clone, Default)]
pub enum LockfileType {
    #[default]
    PackageLock,
    YarnLock,
    PnpmLock,
}

/// Represents the dependency graph extracted from a lockfile.
#[derive(Debug, Default, Clone)]
pub struct DependencyGraph {
    /// Package name -> version
    pub packages: BTreeMap<String, String>,
    /// Package name -> lockfile path (e.g., "node_modules/@eslint/eslintrc")
    pub package_paths: BTreeMap<String, String>,
    /// Package name -> set of packages it depends on
    pub dependencies: BTreeMap<String, BTreeSet<String>>,
    /// Package name -> set of packages that depend on it (reverse lookup)
    pub dependents: BTreeMap<String, BTreeSet<String>>,
    /// Direct dependencies of the root project
    pub root_deps: BTreeSet<String>,
    /// Root project name (if found)
    pub root_name: Option<String>,
    /// Base path where the lockfile was found
    pub base_path: Option<String>,
    /// Type of lockfile this was parsed from
    pub lockfile_type: LockfileType,
}

impl DependencyGraph {
    /// Get the version of a package.
    pub fn get_version(&self, name: &str) -> Option<&String> {
        self.packages.get(name)
    }

    /// Get the file system path for a package.
    pub fn get_path(&self, name: &str) -> Option<&String> {
        self.package_paths.get(name)
    }
}

/// Parses a package-lock.json (v2+) and extracts the full dependency graph.
pub fn parse_dependency_graph(bytes: &[u8], base_path: Option<&str>) -> Option<DependencyGraph> {
    let v: Json = serde_json::from_slice(bytes).ok()?;
    let mut graph = DependencyGraph::default();
    graph.base_path = base_path.map(|s| s.to_string());

    // Get root package info
    if let Some(root) = v.get("packages").and_then(|p| p.get("")) {
        graph.root_name = root.get("name").and_then(|n| n.as_str()).map(|s| s.to_string());

        // Direct dependencies from root
        if let Some(deps) = root.get("dependencies").and_then(|d| d.as_object()) {
            for name in deps.keys() {
                graph.root_deps.insert(name.clone());
            }
        }
        if let Some(deps) = root.get("devDependencies").and_then(|d| d.as_object()) {
            for name in deps.keys() {
                graph.root_deps.insert(name.clone());
            }
        }
    }

    // Parse all packages
    if let Some(packages) = v.get("packages").and_then(|p| p.as_object()) {
        for (path, pkg) in packages {
            if path.is_empty() {
                continue; // Skip root
            }

            let version = pkg
                .get("version")
                .and_then(|s| s.as_str())
                .unwrap_or_default()
                .to_string();

            if version.is_empty() {
                continue;
            }

            // Extract package name from path - skip if pattern doesn't match
            let name = match extract_package_name(path) {
                Some(n) => n,
                None => continue, // Skip packages with non-standard paths
            };
            graph.packages.insert(name.clone(), version);
            graph.package_paths.insert(name.clone(), path.clone());

            // Extract this package's dependencies
            let mut deps = BTreeSet::new();
            for dep_key in ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"] {
                if let Some(dep_obj) = pkg.get(dep_key).and_then(|d| d.as_object()) {
                    for dep_name in dep_obj.keys() {
                        deps.insert(dep_name.clone());
                    }
                }
            }

            // Build forward and reverse lookups
            for dep in &deps {
                graph
                    .dependents
                    .entry(dep.clone())
                    .or_default()
                    .insert(name.clone());
            }
            if !deps.is_empty() {
                graph.dependencies.insert(name, deps);
            }
        }
    }

    Some(graph)
}

/// Parses a pnpm-lock.yaml and extracts the dependency graph.
pub fn parse_pnpm_dependency_graph(bytes: &[u8], base_path: Option<&str>) -> Option<DependencyGraph> {
    let y: Yaml = serde_yaml::from_slice(bytes).ok()?;
    let mut graph = DependencyGraph::default();
    graph.base_path = base_path.map(|s| s.to_string());
    graph.lockfile_type = LockfileType::PnpmLock;

    // Get root package info from importers or root
    if let Some(importers) = y.get("importers").and_then(|i| i.as_mapping()) {
        if let Some(root) = importers.get(&Yaml::String(".".to_string())) {
            // Direct dependencies
            for dep_key in ["dependencies", "devDependencies", "optionalDependencies"] {
                if let Some(deps) = root.get(dep_key).and_then(|d| d.as_mapping()) {
                    for (name, _) in deps {
                        if let Some(name_str) = name.as_str() {
                            graph.root_deps.insert(name_str.to_string());
                        }
                    }
                }
            }
        }
    }

    // Parse all packages
    if let Some(packages) = y.get("packages").and_then(|p| p.as_mapping()) {
        for (key, pkg) in packages {
            let key_str = match key.as_str() {
                Some(k) => k,
                None => continue,
            };

            // Parse key like "/lodash@4.17.21" or "/@scope/name@1.2.3"
            let (name, version) = match split_pnpm_key(key_str) {
                Some((n, v)) => (n.to_string(), v.to_string()),
                None => continue,
            };

            graph.packages.insert(name.clone(), version);
            graph.package_paths.insert(name.clone(), format!("node_modules/{}", name));

            // Extract dependencies
            let mut deps = BTreeSet::new();
            for dep_key in ["dependencies", "optionalDependencies", "peerDependencies"] {
                if let Some(dep_obj) = pkg.get(dep_key).and_then(|d| d.as_mapping()) {
                    for (dep_name, _) in dep_obj {
                        if let Some(dep_name_str) = dep_name.as_str() {
                            deps.insert(dep_name_str.to_string());
                        }
                    }
                }
            }

            // Build forward and reverse lookups
            for dep in &deps {
                graph.dependents.entry(dep.clone()).or_default().insert(name.clone());
            }
            if !deps.is_empty() {
                graph.dependencies.insert(name, deps);
            }
        }
    }

    Some(graph)
}

fn split_pnpm_key(key: &str) -> Option<(&str, &str)> {
    let k = key.trim_start_matches('/');
    let last_at = k.rfind('@')?;
    if last_at == 0 {
        return None; // Scoped package needs more parsing
    }
    let (name, ver) = k.split_at(last_at);
    let ver = &ver[1..]; // skip '@'
    // Handle version suffixes like "4.17.21(patch_hash=...)"
    let ver = ver.split('(').next().unwrap_or(ver);
    Some((name, ver))
}

/// Parses a yarn.lock (v1/classic) and extracts the dependency graph.
pub fn parse_yarn_dependency_graph(bytes: &[u8], base_path: Option<&str>) -> Option<DependencyGraph> {
    let text = String::from_utf8_lossy(bytes);
    let mut graph = DependencyGraph::default();
    graph.base_path = base_path.map(|s| s.to_string());
    graph.lockfile_type = LockfileType::YarnLock;

    // Regex patterns for yarn.lock parsing
    let re_key = Regex::new(r#"^([^\s].*?):\s*$"#).ok()?;
    let re_version = Regex::new(r#"^\s+version\s+"([^"]+)""#).ok()?;
    let re_deps_start = Regex::new(r#"^\s+dependencies:\s*$"#).ok()?;
    let re_dep_entry = Regex::new(r#"^\s{4}"?([^"\s]+)"?\s+"#).ok()?;

    let mut current_names: Vec<String> = Vec::new();
    let mut current_version: Option<String> = None;
    let mut current_deps: BTreeSet<String> = BTreeSet::new();
    let mut in_deps_block = false;

    for line in text.lines() {
        // New package block
        if let Some(cap) = re_key.captures(line) {
            // Commit previous block
            if let Some(ver) = current_version.take() {
                for spec in current_names.drain(..) {
                    if let Some(name) = extract_yarn_package_name(&spec) {
                        graph.packages.entry(name.clone()).or_insert_with(|| ver.clone());
                        graph.package_paths.entry(name.clone()).or_insert_with(|| format!("node_modules/{}", name));
                        
                        if !current_deps.is_empty() {
                            for dep in &current_deps {
                                graph.dependents.entry(dep.clone()).or_default().insert(name.clone());
                            }
                            graph.dependencies.entry(name).or_insert_with(|| current_deps.clone());
                        }
                    }
                }
            }
            current_deps.clear();
            in_deps_block = false;

            // Start new block
            let raw = cap[1].trim().trim_matches('"');
            current_names = raw.split(", ").map(|s| s.trim().to_string()).collect();
            current_version = None;
        } else if let Some(cap) = re_version.captures(line) {
            current_version = Some(cap[1].to_string());
            in_deps_block = false;
        } else if re_deps_start.is_match(line) {
            in_deps_block = true;
        } else if in_deps_block {
            if let Some(cap) = re_dep_entry.captures(line) {
                current_deps.insert(cap[1].to_string());
            } else if !line.starts_with("    ") && !line.trim().is_empty() {
                in_deps_block = false;
            }
        }
    }

    // Final block
    if let Some(ver) = current_version {
        for spec in current_names {
            if let Some(name) = extract_yarn_package_name(&spec) {
                graph.packages.entry(name.clone()).or_insert(ver.clone());
                graph.package_paths.entry(name.clone()).or_insert_with(|| format!("node_modules/{}", name));
                
                if !current_deps.is_empty() {
                    for dep in &current_deps {
                        graph.dependents.entry(dep.clone()).or_default().insert(name.clone());
                    }
                    graph.dependencies.entry(name).or_insert_with(|| current_deps.clone());
                }
            }
        }
    }

    Some(graph)
}

fn extract_yarn_package_name(spec: &str) -> Option<String> {
    let s = spec.trim().trim_matches('"');
    if s.starts_with('@') {
        // Scoped: @scope/name@version
        let mut parts = s.splitn(3, '@');
        let _empty = parts.next();
        let scope = parts.next()?;
        let _rest = parts.next()?;
        Some(format!("@{}", scope.split('@').next().unwrap_or(scope)))
    } else {
        // Unscoped: name@version
        s.split('@').next().map(|x| x.to_string())
    }
}

/// Extracts package name from lockfile path.
fn extract_package_name(path: &str) -> Option<String> {
    let prefix = "node_modules/";
    let last_nm_idx = path.rfind(prefix)?;
    let after_nm = &path[last_nm_idx + prefix.len()..];

    if after_nm.is_empty() {
        return None;
    }

    if after_nm.starts_with('@') {
        if after_nm.contains('/') {
            Some(after_nm.to_string())
        } else {
            None
        }
    } else {
        after_nm.split('/').next().map(|s| s.to_string())
    }
}

/// Renders the dependency tree with colored output (returns String for file output).
#[allow(dead_code)]
pub fn render_dependency_tree(
    graph: &DependencyGraph,
    audit: Option<&AuditResult>,
    max_depth: usize,
) -> String {
    let mut output = String::new();
    let vulnerable_packages = get_vulnerable_packages(audit);

    // Header
    let root_name = graph.root_name.as_deref().unwrap_or("(project)");
    output.push_str(&format!("{}\n", root_name.bold().white()));

    // Sort root deps for consistent output
    let mut root_deps: Vec<_> = graph.root_deps.iter().collect();
    root_deps.sort();

    let total = root_deps.len();
    for (i, dep) in root_deps.iter().enumerate() {
        let is_last = i == total - 1;
        render_node(
            &mut output,
            graph,
            dep,
            &vulnerable_packages,
            "",
            is_last,
            0,
            max_depth,
            &mut HashSet::new(),
        );
    }

    // Vulnerability legend if there are any
    if !vulnerable_packages.is_empty() {
        output.push('\n');
        output.push_str(&"Vulnerability Legend:\n".bold().to_string());
        output.push_str(&format!("  {} = critical\n", "●".bright_red()));
        output.push_str(&format!("  {} = high\n", "●".red()));
        output.push_str(&format!("  {} = moderate\n", "●".yellow()));
        output.push_str(&format!("  {} = low\n", "●".blue()));
    }

    output
}

/// Renders the tree showing only paths to vulnerable packages (returns String for file output).
#[allow(dead_code)]
pub fn render_vulnerable_paths(
    graph: &DependencyGraph,
    audit: Option<&AuditResult>,
) -> String {
    let mut output = String::new();
    let vulnerable_packages = get_vulnerable_packages(audit);

    if vulnerable_packages.is_empty() {
        output.push_str(&"✓ No vulnerabilities to trace.\n".green().to_string());
        return output;
    }

    output.push_str(&format!(
        "{}\n\n",
        "Dependency paths to vulnerable packages:".bold()
    ));

    // For each vulnerable package, find all paths from root
    let mut shown_paths: HashSet<String> = HashSet::new();

    for (vuln_pkg, severity) in &vulnerable_packages {
        let paths = find_paths_to_package(graph, vuln_pkg);

        for path in paths {
            let path_key = path.join(" → ");
            if shown_paths.contains(&path_key) {
                continue;
            }
            shown_paths.insert(path_key);

            // Render this path
            render_vulnerability_path(&mut output, &path, vuln_pkg, severity, graph);
            output.push('\n');
        }
    }

    output
}

/// Gets vulnerable packages mapped to their highest severity.
fn get_vulnerable_packages(audit: Option<&AuditResult>) -> HashMap<String, String> {
    let mut result = HashMap::new();

    if let Some(audit) = audit {
        for (pkg, advisories) in &audit.advisories {
            // Get highest severity for this package
            let severity = advisories
                .iter()
                .map(|a| severity_rank(&a.severity))
                .max()
                .map(|rank| rank_to_severity(rank))
                .unwrap_or("unknown");

            result.insert(pkg.clone(), severity.to_string());
        }
    }

    result
}

fn severity_rank(severity: &str) -> u8 {
    match severity.to_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "moderate" => 2,
        "low" => 1,
        "info" => 0,
        _ => 0,
    }
}

fn rank_to_severity(rank: u8) -> &'static str {
    match rank {
        4 => "critical",
        3 => "high",
        2 => "moderate",
        1 => "low",
        _ => "info",
    }
}

/// Renders a single node in the tree (returns String).
#[allow(dead_code)]
fn render_node(
    output: &mut String,
    graph: &DependencyGraph,
    name: &str,
    vulnerable: &HashMap<String, String>,
    prefix: &str,
    is_last: bool,
    depth: usize,
    max_depth: usize,
    visited: &mut HashSet<String>,
) {
    let connector = if is_last { "└── " } else { "├── " };
    let version = graph.get_version(name).map(|v| v.as_str()).unwrap_or("?");

    // Format package name with vulnerability indicator
    let pkg_display = if let Some(severity) = vulnerable.get(name) {
        let indicator = get_severity_indicator(severity);
        let colored_name = colorize_by_severity(name, severity);
        format!("{} {}@{}", indicator, colored_name, version.dimmed())
    } else {
        format!("{}@{}", name, version.dimmed())
    };

    output.push_str(&format!("{}{}{}\n", prefix, connector, pkg_display));

    // Check for cycles
    if visited.contains(name) {
        let child_prefix = format!("{}{}", prefix, if is_last { "    " } else { "│   " });
        output.push_str(&format!("{}└── {}\n", child_prefix, "(circular)".dimmed()));
        return;
    }

    if depth >= max_depth {
        return;
    }

    visited.insert(name.to_string());

    // Render children
    if let Some(deps) = graph.dependencies.get(name) {
        let child_prefix = format!("{}{}", prefix, if is_last { "    " } else { "│   " });
        let mut deps_vec: Vec<_> = deps.iter().collect();
        deps_vec.sort();

        // Limit children shown to avoid huge output
        let show_count = deps_vec.len().min(10);
        let hidden = deps_vec.len().saturating_sub(10);

        for (i, dep) in deps_vec.iter().take(show_count).enumerate() {
            let is_child_last = i == show_count - 1 && hidden == 0;
            render_node(
                output,
                graph,
                dep,
                vulnerable,
                &child_prefix,
                is_child_last,
                depth + 1,
                max_depth,
                visited,
            );
        }

        if hidden > 0 {
            output.push_str(&format!(
                "{}└── {}\n",
                child_prefix,
                format!("... and {} more", hidden).dimmed()
            ));
        }
    }

    visited.remove(name);
}

/// Gets the colored indicator for a severity level.
fn get_severity_indicator(severity: &str) -> String {
    match severity.to_lowercase().as_str() {
        "critical" => "●".bright_red().to_string(),
        "high" => "●".red().to_string(),
        "moderate" => "●".yellow().to_string(),
        "low" => "●".blue().to_string(),
        _ => "●".white().to_string(),
    }
}

/// Colorizes a package name by severity.
fn colorize_by_severity(name: &str, severity: &str) -> String {
    match severity.to_lowercase().as_str() {
        "critical" => name.bright_red().bold().to_string(),
        "high" => name.red().bold().to_string(),
        "moderate" => name.yellow().to_string(),
        "low" => name.blue().to_string(),
        _ => name.white().to_string(),
    }
}

/// Finds the shortest path from each root dependency to a target package.
/// Returns one path per direct dependency that leads to the target.
fn find_paths_to_package(graph: &DependencyGraph, target: &str) -> Vec<Vec<String>> {
    let mut paths_by_root: HashMap<String, Vec<String>> = HashMap::new();

    // For each root dependency, find the shortest path to target using BFS
    for root_dep in &graph.root_deps {
        if let Some(path) = find_shortest_path_bfs(graph, root_dep, target) {
            // Only keep the shortest path for each root dependency
            let existing = paths_by_root.get(root_dep);
            if existing.is_none() || existing.unwrap().len() > path.len() {
                paths_by_root.insert(root_dep.clone(), path);
            }
        }
    }

    // Return paths sorted by length (shortest first)
    let mut result: Vec<Vec<String>> = paths_by_root.into_values().collect();
    result.sort_by_key(|p| p.len());
    result
}

/// BFS to find the shortest path from start to target.
fn find_shortest_path_bfs(
    graph: &DependencyGraph,
    start: &str,
    target: &str,
) -> Option<Vec<String>> {
    use std::collections::VecDeque;

    if start == target {
        return Some(vec![start.to_string()]);
    }

    let mut queue: VecDeque<Vec<String>> = VecDeque::new();
    let mut visited: HashSet<String> = HashSet::new();

    queue.push_back(vec![start.to_string()]);
    visited.insert(start.to_string());

    while let Some(path) = queue.pop_front() {
        let current = path.last().unwrap();

        if let Some(deps) = graph.dependencies.get(current) {
            for dep in deps {
                if dep == target {
                    // Found the target - return this path + target
                    let mut result = path.clone();
                    result.push(dep.clone());
                    return Some(result);
                }

                if !visited.contains(dep) {
                    visited.insert(dep.clone());
                    let mut new_path = path.clone();
                    new_path.push(dep.clone());
                    queue.push_back(new_path);
                }
            }
        }
    }

    None // No path found
}

/// Renders a single vulnerability path (returns String).
#[allow(dead_code)]
fn render_vulnerability_path(
    output: &mut String,
    path: &[String],
    vuln_pkg: &str,
    severity: &str,
    graph: &DependencyGraph,
) {
    let indicator = get_severity_indicator(severity);
    let severity_label = match severity.to_lowercase().as_str() {
        "critical" => "CRITICAL".bright_red().bold(),
        "high" => "HIGH".red().bold(),
        "moderate" => "MODERATE".yellow(),
        "low" => "LOW".blue(),
        _ => "UNKNOWN".white(),
    };

    output.push_str(&format!("{} {} [{}]\n", indicator, vuln_pkg.bold(), severity_label));

    // Show the path
    for (i, pkg) in path.iter().enumerate() {
        let version = graph.get_version(pkg).map(|v| v.as_str()).unwrap_or("?");
        let is_vulnerable = pkg == vuln_pkg;

        let pkg_display = if is_vulnerable {
            colorize_by_severity(&format!("{}@{}", pkg, version), severity)
        } else {
            format!("{}@{}", pkg, version.dimmed())
        };

        if i == 0 {
            output.push_str(&format!("   {} {}\n", "→".dimmed(), pkg_display));
        } else {
            let indent = "   ".repeat(i);
            output.push_str(&format!("{}└─ {}\n", indent, pkg_display));
        }
    }
}

/// Prints the tree directly to stdout with colors.
pub fn print_dependency_tree(graph: &DependencyGraph, audit: Option<&AuditResult>, max_depth: usize) {
    let vulnerable_packages = get_vulnerable_packages(audit);

    // Header
    let root_name = graph.root_name.as_deref().unwrap_or("(project)");
    println!("{}", root_name.bold().white());

    let mut root_deps: Vec<_> = graph.root_deps.iter().collect();
    root_deps.sort();

    let total = root_deps.len();
    for (i, dep) in root_deps.iter().enumerate() {
        let is_last = i == total - 1;
        print_node(
            graph,
            dep,
            &vulnerable_packages,
            "",
            is_last,
            0,
            max_depth,
            &mut HashSet::new(),
        );
    }

    // Vulnerability legend
    if !vulnerable_packages.is_empty() {
        println!();
        println!("{}", "Vulnerability Legend:".bold());
        println!("  {} = critical", "●".bright_red());
        println!("  {} = high", "●".red());
        println!("  {} = moderate", "●".yellow());
        println!("  {} = low", "●".blue());
    }
}

fn print_node(
    graph: &DependencyGraph,
    name: &str,
    vulnerable: &HashMap<String, String>,
    prefix: &str,
    is_last: bool,
    depth: usize,
    max_depth: usize,
    visited: &mut HashSet<String>,
) {
    let connector = if is_last { "└── " } else { "├── " };
    let version = graph.get_version(name).map(|v| v.as_str()).unwrap_or("?");

    // Format package name with vulnerability indicator
    if let Some(severity) = vulnerable.get(name) {
        let indicator = get_severity_indicator(severity);
        let colored_name = colorize_by_severity(name, severity);
        println!("{}{}{}@{}", prefix, connector, format!("{} {}", indicator, colored_name), version.dimmed());
    } else {
        println!("{}{}{}@{}", prefix, connector, name, version.dimmed());
    }

    if visited.contains(name) {
        let child_prefix = format!("{}{}", prefix, if is_last { "    " } else { "│   " });
        println!("{}└── {}", child_prefix, "(circular)".dimmed());
        return;
    }

    if depth >= max_depth {
        return;
    }

    visited.insert(name.to_string());

    if let Some(deps) = graph.dependencies.get(name) {
        let child_prefix = format!("{}{}", prefix, if is_last { "    " } else { "│   " });
        let mut deps_vec: Vec<_> = deps.iter().collect();
        deps_vec.sort();

        let show_count = deps_vec.len().min(10);
        let hidden = deps_vec.len().saturating_sub(10);

        for (i, dep) in deps_vec.iter().take(show_count).enumerate() {
            let is_child_last = i == show_count - 1 && hidden == 0;
            print_node(
                graph,
                dep,
                vulnerable,
                &child_prefix,
                is_child_last,
                depth + 1,
                max_depth,
                visited,
            );
        }

        if hidden > 0 {
            println!("{}└── {}", child_prefix, format!("... and {} more", hidden).dimmed());
        }
    }

    visited.remove(name);
}

/// Prints only the paths to vulnerable packages.
pub fn print_vulnerable_paths(graph: &DependencyGraph, audit: Option<&AuditResult>) {
    let vulnerable_packages = get_vulnerable_packages(audit);

    if vulnerable_packages.is_empty() {
        println!("{}", "✓ No vulnerabilities to trace.".green());
        return;
    }

    println!("{}\n", "Dependency paths to vulnerable packages:".bold());

    let mut shown_vuln: HashSet<String> = HashSet::new();
    let mut untraced: Vec<(String, String)> = Vec::new();

    for (vuln_pkg, severity) in &vulnerable_packages {
        if shown_vuln.contains(vuln_pkg) {
            continue;
        }
        shown_vuln.insert(vuln_pkg.clone());

        let paths = find_paths_to_package(graph, vuln_pkg);

        if paths.is_empty() {
            // Check if the package exists in the graph at all
            if graph.packages.contains_key(vuln_pkg) {
                // Package exists but no path from root deps
                print_vulnerability_no_path(vuln_pkg, severity, graph);
                println!();
            } else {
                // Package not in graph - collect for summary at end
                untraced.push((vuln_pkg.clone(), severity.clone()));
            }
        } else {
            // Show header for this vulnerability
            print_vulnerability_header(vuln_pkg, severity, graph, paths.len());
            
            // Show each path (one per direct dependency, shortest path)
            for path in paths {
                print_compact_path(&path, vuln_pkg, severity, graph);
            }
            println!();
        }
    }

    // Show untraced vulnerabilities at the end with explanation (only if they have a path on disk)
    if !untraced.is_empty() {
        // Filter to only packages that actually have a path (exist somewhere)
        let real_untraced: Vec<_> = untraced
            .into_iter()
            .filter(|(pkg, _)| graph.package_paths.contains_key(pkg))
            .collect();
        
        if !real_untraced.is_empty() {
            println!("{}", "Vulnerabilities found but dependency path unclear:".yellow().bold());
            println!("{}", "These packages exist but the dependency chain couldn't be traced.".dimmed());
            println!();
            for (vuln_pkg, severity) in real_untraced {
                let indicator = get_severity_indicator(&severity);
                let severity_label = match severity.to_lowercase().as_str() {
                    "critical" => "CRITICAL".bright_red().bold(),
                    "high" => "HIGH".red().bold(),
                    "moderate" => "MODERATE".yellow(),
                    "low" => "LOW".blue(),
                    _ => "UNKNOWN".white(),
                };
                let pkg_colored = colorize_by_severity(&vuln_pkg, &severity);
                
                // Show path if available
                if let Some(rel_path) = graph.get_path(&vuln_pkg) {
                    let full_path = if let Some(base) = &graph.base_path {
                        format!("{}/{}", base, rel_path).replace('/', std::path::MAIN_SEPARATOR_STR)
                    } else {
                        rel_path.replace('/', std::path::MAIN_SEPARATOR_STR)
                    };
                    let version = graph.get_version(&vuln_pkg).map(|v| v.as_str()).unwrap_or("?");
                    println!("   {} {}@{} [{}]", indicator, pkg_colored, version.dimmed(), severity_label);
                    println!("      {} {}", "Path:".dimmed(), full_path);
                } else {
                    println!("   {} {} [{}]", indicator, pkg_colored, severity_label);
                }
            }
            println!();
            println!("{}", "Tip: Run 'npm ls <package-name>' to find the dependency chain.".dimmed());
        }
    }
}

fn print_vulnerability_header(vuln_pkg: &str, severity: &str, graph: &DependencyGraph, path_count: usize) {
    let indicator = get_severity_indicator(severity);
    let severity_label = match severity.to_lowercase().as_str() {
        "critical" => "CRITICAL".bright_red().bold(),
        "high" => "HIGH".red().bold(),
        "moderate" => "MODERATE".yellow(),
        "low" => "LOW".blue(),
        _ => "UNKNOWN".white(),
    };

    let version = graph.get_version(vuln_pkg).map(|v| v.as_str()).unwrap_or("?");
    let pkg_colored = colorize_by_severity(vuln_pkg, severity);
    
    println!("{} {}@{} [{}]", indicator, pkg_colored, version.dimmed(), severity_label);
    
    // Show the full OS path to the vulnerable package
    if let Some(rel_path) = graph.get_path(vuln_pkg) {
        let full_path = if let Some(base) = &graph.base_path {
            format!("{}/{}", base, rel_path).replace('/', std::path::MAIN_SEPARATOR_STR)
        } else {
            rel_path.replace('/', std::path::MAIN_SEPARATOR_STR)
        };
        println!("   {} {}", "Path:".dimmed(), full_path);
    }
    
    println!("   {} {} direct {} pull this in:", 
        "→".dimmed(), 
        path_count,
        if path_count == 1 { "dependency" } else { "dependencies" }
    );
}

fn print_compact_path(path: &[String], vuln_pkg: &str, severity: &str, graph: &DependencyGraph) {
    // Format: "     eslint → @eslint/eslintrc → js-yaml@4.1.1"
    let formatted: Vec<String> = path.iter().map(|pkg| {
        let is_vuln = pkg == vuln_pkg;
        let is_first = path.first().map(|s| s.as_str()) == Some(pkg);
        
        if is_vuln {
            let version = graph.get_version(pkg).map(|v| v.as_str()).unwrap_or("?");
            colorize_by_severity(&format!("{}@{}", pkg, version), severity)
        } else if is_first {
            // First item (direct dep) in bold
            pkg.bold().to_string()
        } else {
            pkg.to_string()
        }
    }).collect();
    
    println!("     {}", formatted.join(&format!(" {} ", "→".dimmed())));
}

fn print_vulnerability_no_path(vuln_pkg: &str, severity: &str, graph: &DependencyGraph) {
    let indicator = get_severity_indicator(severity);
    let severity_label = match severity.to_lowercase().as_str() {
        "critical" => "CRITICAL".bright_red().bold(),
        "high" => "HIGH".red().bold(),
        "moderate" => "MODERATE".yellow(),
        "low" => "LOW".blue(),
        _ => "UNKNOWN".white(),
    };

    let version = graph.get_version(vuln_pkg).map(|v| v.as_str()).unwrap_or("?");
    let pkg_colored = colorize_by_severity(vuln_pkg, severity);

    println!("{} {}@{} [{}]", indicator, pkg_colored, version.dimmed(), severity_label);
    
    // Show the full OS path to the vulnerable package
    if let Some(rel_path) = graph.get_path(vuln_pkg) {
        let full_path = if let Some(base) = &graph.base_path {
            format!("{}/{}", base, rel_path).replace('/', std::path::MAIN_SEPARATOR_STR)
        } else {
            rel_path.replace('/', std::path::MAIN_SEPARATOR_STR)
        };
        println!("   {} {}", "Path:".dimmed(), full_path);
    }
    
    println!("   {}", "(direct or untraced dependency)".dimmed());
}

#[allow(dead_code)]
fn print_vulnerability_path(path: &[String], vuln_pkg: &str, severity: &str, graph: &DependencyGraph) {
    let indicator = get_severity_indicator(severity);
    let severity_label = match severity.to_lowercase().as_str() {
        "critical" => "CRITICAL".bright_red().bold(),
        "high" => "HIGH".red().bold(),
        "moderate" => "MODERATE".yellow(),
        "low" => "LOW".blue(),
        _ => "UNKNOWN".white(),
    };

    println!("{} {} [{}]", indicator, vuln_pkg.bold(), severity_label);

    for (i, pkg) in path.iter().enumerate() {
        let version = graph.get_version(pkg).map(|v| v.as_str()).unwrap_or("?");
        let is_vulnerable = pkg == vuln_pkg;

        let pkg_display = if is_vulnerable {
            colorize_by_severity(&format!("{}@{}", pkg, version), severity)
        } else {
            format!("{}@{}", pkg, version.dimmed())
        };

        if i == 0 {
            println!("   {} {}", "→".dimmed(), pkg_display);
        } else {
            let indent = "   ".repeat(i);
            println!("{}└─ {}", indent, pkg_display);
        }
    }
}
