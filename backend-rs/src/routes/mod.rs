pub mod api_keys;
pub mod applications;
pub mod assessment_events;
pub mod assessments;
pub mod attack_paths;
pub mod audit_logs;
pub mod auth;
pub mod cache_drift_alerts;
pub mod cache_stats;
#[allow(dead_code)] // dormant — router not merged (see routes() below)
pub mod chat;
pub mod cloud;
pub mod cloud_inventory;
pub mod configs;
pub mod conversations;
pub mod correlation;
pub mod dashboard;
pub mod findings;
pub mod footholds;
pub mod graph;
pub mod health;
pub mod imports;
pub mod org_settings;
pub mod projects;
pub mod recon_cache;
pub mod report_subscriptions;
pub mod reports;
pub mod repositories;
pub mod scans;
pub mod sast_cache;
pub mod scan_configs;
pub mod scan_policies;
pub mod scan_schedules;
pub mod scan_snapshots;
pub mod scope_decisions;
pub mod targets;
pub mod sync;
pub mod test_results;
pub mod tool_provenance;
pub mod toolkit;
pub mod users;
pub mod version;

use axum::{middleware, Router};

use crate::auth::read_only_guard;
use crate::state::AppState;

pub fn build_router(state: AppState) -> Router {
    // `/health*` sits at the root; `/api/v1/*` gets the versioned prefix.
    let api_prefix = state.settings.api_prefix.clone();

    let api = Router::new()
        .merge(version::router())
        .merge(auth::router())
        .merge(api_keys::router())
        .merge(applications::router())
        .merge(assessments::router())
        .merge(assessment_events::router())
        .merge(audit_logs::router())
        .merge(cache_drift_alerts::router())
        .merge(cache_stats::router())
        .merge(dashboard::router())
        .merge(findings::router())
        .merge(footholds::router())
        .merge(imports::router())
        .merge(org_settings::router())
        .merge(recon_cache::router())
        .merge(reports::router())
        .merge(report_subscriptions::router())
        .merge(sast_cache::router())
        .merge(scan_snapshots::router())
        .merge(scans::router())
        .merge(scan_schedules::router())
        .merge(scan_policies::router())
        .merge(scan_configs::router())
        .merge(targets::router())
        .merge(sync::router())
        .merge(projects::router())
        .merge(repositories::router())
        .merge(configs::router())
        .merge(conversations::router())
        // chat::router() intentionally NOT merged — the handlers return placeholder
        // text (no LLM wiring) and nothing calls the route. Re-merge once /chat is
        // backed by a real model so it can't ship a dormant route that only lies.
        .merge(cloud::router())
        .merge(cloud_inventory::router())
        .merge(correlation::router())
        .merge(attack_paths::router())
        .merge(graph::router())
        .merge(tool_provenance::router())
        .merge(test_results::router())
        .merge(scope_decisions::router())
        .merge(toolkit::router())
        .merge(users::router())
        // Server-side read-only enforcement: blocks mutating requests from
        // view-only users across every /api/v1 route in one place. Sits
        // outside `/health`.
        .layer(middleware::from_fn_with_state(
            state.clone(),
            read_only_guard,
        ));

    Router::new()
        .merge(health::router())
        .nest(&api_prefix, api)
        .with_state(state)
}
