// src/tree.rs
//! Dependency tree rendering with colored output and vulnerability highlighting.

use crate::audit::AuditResult;
use colored::Colorize;
use serde_json::Value as Json;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// Represents the dependency graph extracted from a lockfile.
#[derive(Debug, Default, Clone)]
pub struct DependencyGraph {
    /// Package name -> version
    pub packages: BTreeMap<String, String>,
    /// Package name -> set of packages it depends on
    pub dependencies: BTreeMap<String, BTreeSet<String>>,
    /// Package name -> set of packages that depend on it (reverse lookup)
    pub dependents: BTreeMap<String, BTreeSet<String>>,
    /// Direct dependencies of the root project
    pub root_deps: BTreeSet<String>,
    /// Root project name (if found)
    pub root_name: Option<String>,
}

impl DependencyGraph {
    /// Get the version of a package.
    pub fn get_version(&self, name: &str) -> Option<&String> {
        self.packages.get(name)
    }
}

/// Parses a package-lock.json (v2+) and extracts the full dependency graph.
pub fn parse_dependency_graph(bytes: &[u8]) -> Option<DependencyGraph> {
    let v: Json = serde_json::from_slice(bytes).ok()?;
    let mut graph = DependencyGraph::default();

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

            // Extract package name from path
            let name = extract_package_name(path)?;
            graph.packages.insert(name.clone(), version);

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

/// Finds all paths from root dependencies to a target package.
fn find_paths_to_package(graph: &DependencyGraph, target: &str) -> Vec<Vec<String>> {
    let mut all_paths = Vec::new();

    // For each root dependency, try to find a path to target
    for root_dep in &graph.root_deps {
        let mut current_path = vec![root_dep.clone()];
        let mut visited = HashSet::new();
        find_paths_dfs(graph, root_dep, target, &mut current_path, &mut visited, &mut all_paths);
    }

    all_paths
}

fn find_paths_dfs(
    graph: &DependencyGraph,
    current: &str,
    target: &str,
    path: &mut Vec<String>,
    visited: &mut HashSet<String>,
    results: &mut Vec<Vec<String>>,
) {
    if current == target {
        results.push(path.clone());
        return;
    }

    if visited.contains(current) {
        return;
    }
    visited.insert(current.to_string());

    if let Some(deps) = graph.dependencies.get(current) {
        for dep in deps {
            path.push(dep.clone());
            find_paths_dfs(graph, dep, target, path, visited, results);
            path.pop();
        }
    }

    visited.remove(current);
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

    let mut shown_paths: HashSet<String> = HashSet::new();

    for (vuln_pkg, severity) in &vulnerable_packages {
        let paths = find_paths_to_package(graph, vuln_pkg);

        for path in paths {
            let path_key = path.join(" → ");
            if shown_paths.contains(&path_key) {
                continue;
            }
            shown_paths.insert(path_key);

            print_vulnerability_path(&path, vuln_pkg, severity, graph);
            println!();
        }
    }
}

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

