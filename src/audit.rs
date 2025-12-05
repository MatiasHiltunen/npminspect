// src/audit.rs
//! Security audit module for checking npm package vulnerabilities via the npm Registry Bulk Advisory API.

use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use thiserror::Error;

/// The npm Registry Bulk Advisory API endpoint.
const BULK_ADVISORY_URL: &str = "https://registry.npmjs.org/-/npm/v1/security/advisories/bulk";

/// Request timeout for the advisory API (in seconds).
const REQUEST_TIMEOUT_SECS: u64 = 30;

/// Represents a single security advisory from the npm registry.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Advisory {
    /// Unique identifier for this advisory.
    pub id: u64,
    /// Human-readable title describing the vulnerability.
    pub title: String,
    /// Severity level: "info", "low", "moderate", "high", or "critical".
    pub severity: String,
    /// URL to the full advisory details.
    pub url: String,
    /// Package name this advisory applies to.
    #[serde(default)]
    pub name: String,
    /// Semver range of vulnerable versions (e.g., "<4.17.21").
    pub vulnerable_versions: String,
}

/// Summary of vulnerabilities found, categorized by severity.
#[derive(Debug, Clone, Default, Serialize)]
pub struct VulnerabilitySummary {
    pub critical: usize,
    pub high: usize,
    pub moderate: usize,
    pub low: usize,
    pub info: usize,
    pub total: usize,
}

impl VulnerabilitySummary {
    /// Returns true if any vulnerabilities were found.
    pub fn has_vulnerabilities(&self) -> bool {
        self.total > 0
    }

    fn increment(&mut self, severity: &str) {
        match severity.to_lowercase().as_str() {
            "critical" => self.critical += 1,
            "high" => self.high += 1,
            "moderate" => self.moderate += 1,
            "low" => self.low += 1,
            "info" => self.info += 1,
            _ => {} // Unknown severity levels are counted in total only
        }
        self.total += 1;
    }
}

/// Complete audit result containing all advisories and summary statistics.
#[derive(Debug, Clone, Default, Serialize)]
pub struct AuditResult {
    /// Map of package name to list of advisories affecting that package.
    pub advisories: BTreeMap<String, Vec<Advisory>>,
    /// Summary counts by severity level.
    pub summary: VulnerabilitySummary,
}

impl AuditResult {
    /// Constructs an AuditResult from the raw API response.
    fn from_response(response: HashMap<String, Vec<Advisory>>) -> Self {
        let mut result = AuditResult::default();

        for (package_name, mut advisories) in response {
            for advisory in &mut advisories {
                // Ensure the package name is set on each advisory
                if advisory.name.is_empty() {
                    advisory.name = package_name.clone();
                }
                result.summary.increment(&advisory.severity);
            }
            if !advisories.is_empty() {
                result.advisories.insert(package_name, advisories);
            }
        }

        result
    }
}

/// Errors that can occur during the security audit process.
#[derive(Error, Debug)]
pub enum AuditError {
    #[error("HTTP request failed: {0}")]
    RequestFailed(#[from] reqwest::Error),

    #[error("Registry returned error status {status}: {message}")]
    RegistryError { status: u16, message: String },

    #[error("No packages to audit")]
    NoPackages,
}

/// Performs a bulk security audit against the npm registry.
///
/// Takes a map of package names to their resolved versions and queries the
/// npm Bulk Advisory API to find any known security vulnerabilities.
///
/// # Arguments
/// * `packages` - Map of package names to sets of resolved version strings
///
/// # Returns
/// * `Ok(AuditResult)` - Audit completed, may contain zero or more advisories
/// * `Err(AuditError)` - Failed to complete the audit
///
/// # Example
/// ```ignore
/// let mut packages = HashMap::new();
/// packages.insert("lodash".to_string(), vec!["4.17.15".to_string()]);
/// let result = audit_packages(&packages).await?;
/// ```
pub async fn audit_packages(
    packages: &BTreeMap<String, std::collections::BTreeSet<String>>,
) -> Result<AuditResult, AuditError> {
    if packages.is_empty() {
        return Err(AuditError::NoPackages);
    }

    // Convert BTreeSet<String> to Vec<String> for the API payload
    let payload: HashMap<String, Vec<String>> = packages
        .iter()
        .filter(|(_, versions)| !versions.is_empty())
        .map(|(name, versions)| {
            (name.clone(), versions.iter().cloned().collect::<Vec<_>>())
        })
        .collect();

    if payload.is_empty() {
        return Err(AuditError::NoPackages);
    }

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .user_agent(concat!("npminspect/", env!("CARGO_PKG_VERSION")))
        .build()?;

    let response = client
        .post(BULK_ADVISORY_URL)
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await?;

    if response.status().is_success() {
        let advisories: HashMap<String, Vec<Advisory>> = response.json().await?;
        Ok(AuditResult::from_response(advisories))
    } else {
        let status = response.status().as_u16();
        let message = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());
        Err(AuditError::RegistryError { status, message })
    }
}

/// Formats the severity string with consistent casing for display.
pub fn format_severity(severity: &str) -> &'static str {
    match severity.to_lowercase().as_str() {
        "critical" => "CRITICAL",
        "high" => "HIGH",
        "moderate" => "MODERATE",
        "low" => "LOW",
        "info" => "INFO",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vulnerability_summary_increment() {
        let mut summary = VulnerabilitySummary::default();
        summary.increment("critical");
        summary.increment("high");
        summary.increment("moderate");
        summary.increment("low");
        summary.increment("info");

        assert_eq!(summary.critical, 1);
        assert_eq!(summary.high, 1);
        assert_eq!(summary.moderate, 1);
        assert_eq!(summary.low, 1);
        assert_eq!(summary.info, 1);
        assert_eq!(summary.total, 5);
    }

    #[test]
    fn test_vulnerability_summary_case_insensitive() {
        let mut summary = VulnerabilitySummary::default();
        summary.increment("CRITICAL");
        summary.increment("High");
        summary.increment("MODERATE");

        assert_eq!(summary.critical, 1);
        assert_eq!(summary.high, 1);
        assert_eq!(summary.moderate, 1);
        assert_eq!(summary.total, 3);
    }

    #[test]
    fn test_has_vulnerabilities() {
        let mut summary = VulnerabilitySummary::default();
        assert!(!summary.has_vulnerabilities());

        summary.increment("low");
        assert!(summary.has_vulnerabilities());
    }

    #[test]
    fn test_format_severity() {
        assert_eq!(format_severity("critical"), "CRITICAL");
        assert_eq!(format_severity("CRITICAL"), "CRITICAL");
        assert_eq!(format_severity("high"), "HIGH");
        assert_eq!(format_severity("unknown_value"), "UNKNOWN");
    }
}

