// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod claude_auth;
mod cloud;
mod codex_auth;
mod commands;
mod database;
mod docker;
mod error;
mod mcp;
mod state;

use state::AppState;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Per-OS directory for the persisted log file sink.
fn log_directory() -> Option<std::path::PathBuf> {
    let home = dirs::home_dir()?;
    #[cfg(target_os = "macos")]
    {
        Some(home.join("Library").join("Logs").join("Maestro"))
    }
    #[cfg(not(target_os = "macos"))]
    {
        Some(home.join(".kali-mcp-pentest").join("logs"))
    }
}

/// Tracing → stdout AND a daily-rolling file (`~/Library/Logs/Maestro/maestro.log`
/// on macOS) so production incidents — like a failed toolkit pull — are
/// diagnosable after the fact rather than vanishing into a release build's
/// stdout. Returns the non-blocking writer guard, which MUST be held for the
/// app's lifetime (bound in `main`) or the file sink stops flushing.
fn init_tracing() -> Option<tracing_appender::non_blocking::WorkerGuard> {
    let (file_layer, guard) = match log_directory() {
        Some(dir) if std::fs::create_dir_all(&dir).is_ok() => {
            let appender = tracing_appender::rolling::daily(&dir, "maestro.log");
            let (non_blocking, guard) = tracing_appender::non_blocking(appender);
            (
                Some(
                    tracing_subscriber::fmt::layer()
                        .with_ansi(false)
                        .with_writer(non_blocking),
                ),
                Some(guard),
            )
        }
        // Never block app start over logging — fall back to stdout-only.
        _ => (None, None),
    };
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .with(file_layer)
        .init();
    guard
}

fn main() {
    // stdout + a persisted rolling file; hold the guard for the app's lifetime.
    let _log_guard = init_tracing();

    // One-time migration — strip the legacy llm-config.yml left behind
    // from the Ollama-supporting builds (≤ 0.1.19). Cheap to call on
    // every boot; no-op when the file isn't there.
    commands::credentials::migrate_legacy_llm_config();

    // Create app state
    let app_state = Arc::new(RwLock::new(AppState::new()));

    tauri::Builder::default()
        // single-instance MUST be the first plugin. With the `deep-link`
        // feature it forwards an OAuth callback that launched a second instance
        // (Windows/Linux) into the running app; the closure just focuses it.
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            use tauri::Manager;
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.set_focus();
            }
        }))
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_pty::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .manage(app_state)
        // System commands
        .invoke_handler(tauri::generate_handler![
            // System status
            commands::system::get_system_status,
            commands::system::get_docker_status,
            commands::system::get_egress_stats,
            commands::system::get_test_mode_flags,
            commands::system::get_configured_kali_image,
            commands::self_host::get_self_host_config,
            commands::self_host::set_local_mode,
            commands::self_host::set_deployment_config,
            commands::system::start_kali_container,
            commands::system::set_toolkit_credentials,
            commands::system::stop_kali_container,
            commands::system::get_available_tools,
            commands::system::validate_scope,
            commands::system::check_docker_installed,
            commands::system::resolve_docker_path,
            commands::system::open_docker_desktop,
            commands::system::diagnose_docker,
            commands::system::restart_docker_desktop,
            commands::system::check_kali_image_exists,
            commands::system::pull_kali_image,
            commands::system::pull_kali_image_with_auth,
            commands::system::ensure_mcp_server,
            // Assessments
            commands::assessments::list_assessments,
            commands::assessments::get_assessment,
            commands::assessments::create_assessment,
            commands::assessments::update_assessment,
            commands::assessments::update_assessment_options,
            commands::assessments::start_assessment,
            commands::assessments::cancel_assessment,
            commands::assessments::pause_assessment,
            commands::assessments::resume_assessment,
            commands::assessments::delete_assessment,
            commands::assessments::get_assessment_report,
            commands::assessments::generate_assessment_report,
            commands::assessments::complete_assessment,
            // Findings
            commands::findings::list_findings,
            commands::findings::get_finding,
            commands::findings::create_finding,
            commands::findings::update_finding,
            commands::findings::delete_finding,
            commands::findings::get_findings_stats,
            commands::findings::export_findings,
            commands::findings::create_jira_ticket,
            commands::findings::create_scan_snapshot,
            commands::findings::list_scan_history,
            // Reports
            commands::reports::list_reports,
            commands::reports::get_report,
            commands::reports::generate_report,
            commands::reports::export_report,
            commands::reports::list_report_files,
            commands::reports::read_report_file,
            commands::reports::generate_pdf_report,
            commands::reports::download_url_to_downloads,
            // Config
            commands::config::get_scope_config,
            commands::config::save_scope_config,
            commands::config::validate_cloud_scope,
            commands::config::validate_identity_target,
            commands::config::validate_ai_target,
            commands::config::save_identity_sa_key,
            commands::config::get_credentials_config,
            commands::config::save_credentials_config,
            commands::config::get_tools_config,
            commands::config::save_tools_config,
            commands::config::get_agents_config,
            commands::config::save_agents_config,
            commands::config::get_integrations_config,
            commands::config::save_integrations_config,
            // Claude credentials (replaces the old LLM config / Ollama suite)
            commands::credentials::set_claude_api_key,
            commands::credentials::clear_claude_api_key,
            commands::credentials::test_claude_api_key,
            commands::credentials::get_claude_auth_state,
            commands::credentials::set_active_credential_mode,
            commands::credentials::get_claude_container_env,
            // Codex credentials (parallel of the Claude block above — same
            // two modes, OpenAI/GPT-5.5 instead of Anthropic/Claude).
            commands::codex_credentials::set_codex_api_key,
            commands::codex_credentials::clear_codex_api_key,
            commands::codex_credentials::test_codex_api_key,
            commands::codex_credentials::get_codex_auth_state,
            commands::codex_credentials::set_active_codex_credential_mode,
            commands::codex_credentials::get_codex_container_env,
            // Per-user secret storage (split-config secrets — Jira API
            // tokens, GitHub PATs, app passwords) backed by the OS keyring.
            commands::secrets::get_secret_blob,
            commands::secrets::set_secret_blob,
            commands::secrets::clear_secret_blob,
            // Per-user repo path overrides (item #6) — each user has their
            // own local clone path; cloud stores creator's path as a hint.
            commands::repo_paths::get_local_repo_paths,
            commands::repo_paths::set_local_repo_path,
            // Repositories
            commands::repos::list_repositories,
            commands::repos::get_repository,
            commands::repos::add_repository,
            commands::repos::remove_repository,
            commands::repos::update_repository,
            commands::repos::scan_repository,
            // Projects
            commands::projects::list_projects,
            commands::projects::get_project,
            commands::projects::create_project,
            commands::projects::update_project,
            commands::projects::delete_project,
            commands::projects::assign_assessment_to_project,
            // Tools (MCP)
            commands::tools::scan_ports,
            commands::tools::enumerate_subdomains,
            commands::tools::fingerprint_services,
            commands::tools::discover_hosts,
            commands::tools::run_nuclei,
            commands::tools::run_nikto,
            commands::tools::run_sqlmap,
            commands::tools::run_ffuf,
            commands::tools::run_xss_scan,
            // Agents
            commands::agents::run_orchestrator,
            commands::agents::run_agent,
            commands::agents::get_agent_status,
            commands::agents::cancel_agent,
            commands::agents::list_running_agents,
            // Audit logs
            commands::audit::get_audit_logs,
            // Cloud sync
            commands::cloud::get_cloud_config,
            commands::cloud::save_cloud_config_cmd,
            commands::cloud::test_cloud_connection,
            commands::cloud::get_cloud_auth_providers,
            commands::cloud::cloud_login,
            commands::cloud::cloud_logout,
            commands::cloud::get_cloud_status,
            commands::cloud::sync_with_cloud,
            commands::cloud::set_cloud_tokens,
            commands::cloud::write_cloud_session_file,
            commands::cloud::clear_cloud_session_file,
            commands::cloud::write_oast_config_file,
            commands::cloud::clear_oast_config_file,
            commands::cloud::write_merged_credentials_file,
            commands::cloud::clear_merged_credentials_file,
            commands::cloud::write_merged_scope_file,
            commands::cloud::clear_merged_scope_file,
            // Multi-account cloud management
            commands::cloud::list_cloud_accounts,
            commands::cloud::get_cloud_account,
            commands::cloud::add_cloud_account,
            commands::cloud::update_cloud_account,
            commands::cloud::remove_cloud_account,
            commands::cloud::set_active_cloud_account,
            // Cache stats (Phase 0 caching telemetry)
            commands::cloud::record_cache_stats,
            commands::cloud::get_cache_stats_for_assessment,
            // Baseline-aware findings (Phase 3 caching plan)
            commands::cloud::get_baseline_findings_for_target,
            // SAST + recon caches (Phase 4 + 5 caching plan)
            commands::cloud::sast_cache_lookup,
            commands::cloud::sast_cache_upsert,
            commands::cloud::recon_cache_lookup,
            commands::cloud::recon_cache_upsert,
            // Org-level cache settings + drift summary (Phase 6 caching plan)
            commands::cloud::get_org_settings,
            commands::cloud::update_org_settings,
            commands::cloud::get_drift_alerts_summary,
            // Cloud credential validation (save-time probe)
            commands::cloud_validation::validate_cloud_account,
            // Assessment-time assume-role injection into the container
            commands::cloud_validation::start_cloud_assessment_credentials,
            commands::cloud_validation::stop_cloud_assessment_credentials,
            // AWS SSO sign-in wizard — drives the device-code flow
            // when the probe needs source credentials.
            commands::aws_sso::aws_sso_start_device_auth,
            commands::aws_sso::aws_sso_poll_device_auth,
            commands::aws_sso::aws_sso_list_accounts,
            commands::aws_sso::aws_sso_list_account_roles,
            commands::aws_sso::aws_sso_get_role_credentials,
            commands::aws_sso::aws_sso_refresh_token,
            commands::aws_sso::aws_sts_assume_role_web_identity,
            // Terminal
            commands::terminal::spawn_terminal_session,
            commands::terminal::list_terminal_sessions,
            commands::terminal::get_terminal_session,
            commands::terminal::end_terminal_session,
            commands::terminal::link_session_to_assessment,
            commands::terminal::check_claude_installed,
            commands::terminal::check_codex_installed,
            commands::terminal::check_available_clis,
            commands::terminal::record_brain_selected,
            commands::terminal::check_claude_auth_in_container,
            commands::terminal::check_codex_auth_in_container,
            commands::terminal::ensure_codex_mcp_config,
            commands::terminal::ensure_claude_mcp_config,
            commands::terminal::capture_codex_session_id,
            commands::terminal::check_assessment_session_live,
            commands::terminal::check_claude_session_resumable,
            commands::terminal::kill_assessment_sessions,
            commands::terminal::list_live_assessment_sessions,
            commands::terminal::get_terminal_working_dir,
            // Help — slash commands + agents reference
            commands::help::list_help_resources,
            commands::help::list_user_guide,
            commands::help::read_user_guide_doc,
            commands::terminal::save_terminal_transcript,
            commands::terminal::get_terminal_sessions_for_assessment,
            commands::terminal::save_assessment_chat_messages,
            commands::terminal::load_assessment_chat_messages,
            // Tmux session management
            commands::terminal::check_tmux_installed,
            commands::terminal::get_tmux_path,
            commands::terminal::check_tmux_session,
            commands::terminal::list_tmux_sessions,
            commands::terminal::capture_tmux_pane,
            commands::terminal::kill_tmux_session,
            // Imports
            commands::imports::preview_csv,
            commands::imports::import_csv,
            commands::imports::list_imports,
            commands::imports::get_import,
            commands::imports::delete_import,
            commands::imports::list_imported_findings,
            commands::imports::get_imported_finding,
            commands::imports::update_imported_finding_status,
            commands::imports::link_findings_to_repository,
            commands::imports::get_import_stats,
            commands::imports::create_validation_assessment,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
