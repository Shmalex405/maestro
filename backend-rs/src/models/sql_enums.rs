//! sqlx Type wrappers for every Postgres enum that Python's SQLAlchemy
//! creates.
//!
//! Each variant's lowercase identifier is the Postgres enum label. Wire
//! representation (serde) also produces the same lowercase strings, so the
//! JSON shape is unchanged from the Python backend.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "severity", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum SeverityDb {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "findingstatus", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum FindingStatusDb {
    Open,
    InProgress,
    Remediated,
    Accepted,
    FalsePositive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "assessmentstatus", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum AssessmentStatusDb {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
    NotStarted,
    /// Ran but never completed — went idle (no heartbeat for 3h) or was
    /// archived while still running, without promoting any deliverables.
    /// Neutral terminal state; not an error (that's `Failed`). Added in
    /// migration 0042.
    Incomplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "assessmenttype", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum AssessmentTypeDb {
    Full,
    Recon,
    VulnScan,
    WebApp,
    ApiSecurity,
    CloudAssessment,
    Combined,
    CodeScan,
    CycodeValidation,
    ExploitValidation,
    Custom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "projectstatus", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum ProjectStatusDb {
    Active,
    Archived,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "messagerole", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum MessageRoleDb {
    User,
    Assistant,
    System,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "reposourcetype", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum RepoSourceTypeDb {
    Local,
    Github,
    Gitlab,
}

/// Converts a db enum back to the wire-format string (same as serde_json
/// would produce) so response schemas can keep exposing `String`.
pub trait WireName {
    fn wire_name(&self) -> &'static str;
}

impl WireName for SeverityDb {
    fn wire_name(&self) -> &'static str {
        match self {
            SeverityDb::Critical => "critical",
            SeverityDb::High => "high",
            SeverityDb::Medium => "medium",
            SeverityDb::Low => "low",
            SeverityDb::Info => "info",
        }
    }
}

impl WireName for FindingStatusDb {
    fn wire_name(&self) -> &'static str {
        match self {
            FindingStatusDb::Open => "open",
            FindingStatusDb::InProgress => "in_progress",
            FindingStatusDb::Remediated => "remediated",
            FindingStatusDb::Accepted => "accepted",
            FindingStatusDb::FalsePositive => "false_positive",
        }
    }
}

impl WireName for AssessmentStatusDb {
    fn wire_name(&self) -> &'static str {
        match self {
            AssessmentStatusDb::Pending => "pending",
            AssessmentStatusDb::Running => "running",
            AssessmentStatusDb::Completed => "completed",
            AssessmentStatusDb::Failed => "failed",
            AssessmentStatusDb::Cancelled => "cancelled",
            AssessmentStatusDb::NotStarted => "not_started",
            AssessmentStatusDb::Incomplete => "incomplete",
        }
    }
}

impl WireName for AssessmentTypeDb {
    fn wire_name(&self) -> &'static str {
        match self {
            AssessmentTypeDb::Full => "full",
            AssessmentTypeDb::Recon => "recon",
            AssessmentTypeDb::VulnScan => "vuln_scan",
            AssessmentTypeDb::WebApp => "web_app",
            AssessmentTypeDb::ApiSecurity => "api_security",
            AssessmentTypeDb::CloudAssessment => "cloud_assessment",
            AssessmentTypeDb::Combined => "combined",
            AssessmentTypeDb::CodeScan => "code_scan",
            AssessmentTypeDb::CycodeValidation => "cycode_validation",
            AssessmentTypeDb::ExploitValidation => "exploit_validation",
            AssessmentTypeDb::Custom => "custom",
        }
    }
}

impl WireName for ProjectStatusDb {
    fn wire_name(&self) -> &'static str {
        match self {
            ProjectStatusDb::Active => "active",
            ProjectStatusDb::Archived => "archived",
        }
    }
}

impl WireName for MessageRoleDb {
    fn wire_name(&self) -> &'static str {
        match self {
            MessageRoleDb::User => "user",
            MessageRoleDb::Assistant => "assistant",
            MessageRoleDb::System => "system",
        }
    }
}

impl WireName for RepoSourceTypeDb {
    fn wire_name(&self) -> &'static str {
        match self {
            RepoSourceTypeDb::Local => "local",
            RepoSourceTypeDb::Github => "github",
            RepoSourceTypeDb::Gitlab => "gitlab",
        }
    }
}
