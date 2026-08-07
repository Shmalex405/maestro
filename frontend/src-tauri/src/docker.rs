use bollard::container::{
    Config, CreateContainerOptions, ListContainersOptions, RemoveContainerOptions,
    StartContainerOptions, StopContainerOptions,
};
use bollard::image::{CreateImageOptions, ListImagesOptions, RemoveImageOptions};
use bollard::Docker;

pub use bollard::models::CreateImageInfo;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use tauri::{AppHandle, Emitter};
use tokio::io::{AsyncBufReadExt, BufReader};
use tracing::{info, warn};

use crate::error::{AppError, Result};

/// Container image the desktop app expects to run. Pinned to a GHCR tag
/// at build time so a given Maestro version always pairs with a known
/// toolkit version — release-desktop.yml sets `KALI_IMAGE` as a build
/// env var; local dev builds fall back to `:latest`.
///
/// Image source: https://github.com/Shmalex405/kali-mcp-pentest/pkgs/container/docker-kali
///
/// That registry is private and available to Maestro subscribers. A
/// self-hosted build has no access to it and instead builds the identical
/// image from `docker/Dockerfile.kali` (Apache-2.0, and the same definition CI
/// publishes) via `scripts/build-self-host-toolkit.sh`, then sets `KALI_IMAGE`
/// to the local tag at build time:
///
/// ```text
/// KALI_IMAGE=maestro-toolkit:local npm run tauri:build -- \
///   --config src-tauri/tauri.self-host.conf.json
/// ```
///
/// The startup gate checks for the image locally before attempting any
/// registry pull, so a local-only tag is used as-is and never fetched. See
/// SELF-HOSTING.md.
pub fn kali_image() -> &'static str {
    option_env!("KALI_IMAGE").unwrap_or("ghcr.io/shmalex405/docker-kali:latest")
}

const CONTAINER_NAME: &str = "kali-pentest";

/// Ceiling for a single *quick* Docker daemon API call (inspect/list/create/
/// start/stop/remove) before we treat the daemon as hung. See
/// [`DockerManager::bounded`]. Image pulls are excluded — they have their own
/// streaming progress + stall detection.
const DAEMON_CALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerStatus {
    pub running: bool,
    pub container_id: Option<String>,
    pub image: Option<String>,
    pub status: String,
    pub ports: Vec<PortMapping>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortMapping {
    pub host_port: u16,
    pub container_port: u16,
    pub protocol: String,
}

/// Brokered GHCR pull credential, cached on the manager so the container
/// lifecycle (`create_container`, `start_container` recreate) pulls the
/// private toolkit image authenticated. Sourced from the backend broker (a
/// read-only GHCR PAT) and handed in by the `set_toolkit_credentials` command
/// via `new_with_credentials`. Without it, the lifecycle pulls anonymously and
/// 404s the private image — the exact bug behind "error from registry:
/// unauthorized".
#[derive(Clone, Debug)]
pub struct BrokeredRegistryCredentials {
    pub username: String,
    pub password: String,
    pub expires_at: Option<i64>,
}

pub struct DockerManager {
    docker: Docker,
    registry_credentials: Option<BrokeredRegistryCredentials>,
}

impl DockerManager {
    /// Borrowed reference to the underlying bollard client. Lets sibling
    /// modules call bollard APIs that DockerManager doesn't wrap (e.g.
    /// cloud-credential probes that need to exec arbitrary commands and
    /// inspect their exit codes).
    pub fn docker(&self) -> &Docker {
        &self.docker
    }

    pub async fn new() -> Result<Self> {
        Self::new_with_credentials(None).await
    }

    /// Like [`new`](Self::new) but caches a brokered GHCR credential so this
    /// manager's lifecycle pulls authenticate to the private registry. Used by
    /// `start_kali_container`, which reads the credential the frontend cached
    /// in `AppState` after the backend broker call.
    pub async fn new_with_credentials(
        registry_credentials: Option<BrokeredRegistryCredentials>,
    ) -> Result<Self> {
        let docker = Docker::connect_with_local_defaults()
            .map_err(|e| AppError::Docker(e))?;

        // Verify connection with a 3-second timeout so we don't hang
        // when the socket exists but daemon is unresponsive
        tokio::time::timeout(std::time::Duration::from_secs(3), docker.ping())
            .await
            .map_err(|_| AppError::Other("Docker daemon ping timed out".into()))?
            .map_err(|e| AppError::Docker(e))?;

        info!("Connected to Docker daemon");
        Ok(Self {
            docker,
            registry_credentials,
        })
    }

    /// Bound a *quick* Docker daemon API call so a half-hung daemon — one
    /// that still answers the cheap connection ping but stalls on real work
    /// (Docker Desktop's Linux VM wedges, a common macOS failure mode) —
    /// surfaces an actionable, retryable error instead of freezing startup
    /// forever. Before this, `start_container` could spin indefinitely on an
    /// unanswered `inspect`/`list`/`create` call, leaving the gate stuck on
    /// "Start Kali Container"; the only fix was quitting the app AND
    /// restarting Docker.
    ///
    /// Image PULLS are deliberately NOT routed through here — they stream
    /// progress and legitimately run for minutes (see
    /// `pull_image_with_progress`). Inspect/list/create/start/stop/remove all
    /// return in well under a second on a healthy daemon, so 30s is a
    /// generous ceiling that only trips on a genuine hang.
    async fn bounded<T>(
        &self,
        op: &str,
        fut: impl std::future::Future<Output = Result<T>>,
    ) -> Result<T> {
        match tokio::time::timeout(DAEMON_CALL_TIMEOUT, fut).await {
            Ok(res) => res,
            Err(_) => Err(AppError::Other(format!(
                "Docker daemon stopped responding while trying to {op} (waited {}s). \
                 Docker Desktop's Linux VM is likely hung — restart Docker Desktop, then retry.",
                DAEMON_CALL_TIMEOUT.as_secs(),
            ))),
        }
    }

    /// Get the status of the Kali container
    pub async fn get_container_status(&self) -> Result<ContainerStatus> {
        let mut filters = HashMap::new();
        filters.insert("name", vec![CONTAINER_NAME]);

        let containers = self
            .docker
            .list_containers(Some(ListContainersOptions {
                all: true,
                filters,
                ..Default::default()
            }))
            .await
            .map_err(|e| AppError::Docker(e))?;

        if let Some(container) = containers.first() {
            let running = container.state.as_deref() == Some("running");
            let ports = container
                .ports
                .as_ref()
                .map(|ports| {
                    ports
                        .iter()
                        .filter_map(|p| {
                            Some(PortMapping {
                                host_port: p.public_port? as u16,
                                container_port: p.private_port as u16,
                                protocol: p.typ.as_ref().map(|t| t.to_string()).unwrap_or_else(|| "tcp".to_string()),
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();

            Ok(ContainerStatus {
                running,
                container_id: container.id.clone(),
                image: container.image.clone(),
                status: container.status.clone().unwrap_or_default(),
                ports,
            })
        } else {
            Ok(ContainerStatus {
                running: false,
                container_id: None,
                image: None,
                status: "not found".to_string(),
                ports: vec![],
            })
        }
    }

    /// Start the Kali container. Self-heals when the existing container's
    /// config has drifted (image tag changed, binds changed) by tearing
    /// the stale one down and recreating from the expected config — so
    /// customers don't need to know about `docker rm` after a desktop
    /// upgrade that bumped the image or added a new mount.
    pub async fn start_container(&self) -> Result<ContainerStatus> {
        // Check for drift BEFORE the early-return-on-running path: a
        // stale running container still counts as drifted.
        if self
            .bounded("inspect the container", self.container_needs_recreate())
            .await?
        {
            // OBTAIN-BEFORE-TEARDOWN (enterprise invariant: always up).
            // Drift can mean the pinned image changed (a Maestro upgrade
            // pins a new :v{version} tag). NEVER remove a working container
            // until the replacement image is actually in hand — otherwise a
            // failed pull (expired cloud session, offline, GHCR hiccup)
            // leaves the app with no container at all. If the expected image
            // is missing, try to obtain it FIRST; if that fails, fall back to
            // the existing container (degraded — running on the old image)
            // rather than bricking. The frontend startup gate does the
            // license-brokered authenticated pull before calling us, so by
            // the time we get here the image is usually already present; this
            // anonymous pull is a best-effort secondary path.
            if !self
                .bounded("check for the toolkit image", self.image_exists())
                .await?
            {
                info!(
                    "Recreate needed but expected image {} is absent — obtaining before teardown",
                    kali_image()
                );
                if let Err(e) = self.pull_image().await {
                    tracing::warn!(
                        "Could not obtain toolkit image {} ({}). Keeping existing container (degraded — toolkit update pending).",
                        kali_image(),
                        e
                    );
                    let status = self
                        .bounded("read container status", self.get_container_status())
                        .await?;
                    if status.running {
                        return Ok(status);
                    }
                    if status.container_id.is_some() {
                        self.bounded("start the existing container", async {
                            self.docker
                                .start_container(
                                    CONTAINER_NAME,
                                    None::<StartContainerOptions<String>>,
                                )
                                .await
                                .map_err(AppError::Docker)
                        })
                        .await?;
                        return self
                            .bounded("read container status", self.get_container_status())
                            .await;
                    }
                    // No usable container AND no obtainable image — the only
                    // genuinely unrecoverable case. Honest, actionable error
                    // (NOT the old "docker dir not found" from the dead
                    // CARGO_MANIFEST_DIR build fallback).
                    return Err(AppError::Config(format!(
                        "Toolkit image {} isn't available locally and couldn't be downloaded ({}). \
                         Sign in to Maestro Cloud so the desktop can fetch the licensed toolkit, then retry.",
                        kali_image(),
                        e
                    )));
                }
            }
            // Replacement image confirmed present — safe to tear down + recreate.
            let _ = self
                .bounded("stop the old container", async {
                    self.docker
                        .stop_container(CONTAINER_NAME, Some(StopContainerOptions { t: 10 }))
                        .await
                        .map_err(AppError::Docker)
                })
                .await; // best-effort; container may already be stopped
            self.bounded("remove the old container", self.remove_container())
                .await?;
        }

        let status = self
            .bounded("read container status", self.get_container_status())
            .await?;

        if status.running {
            info!("Container already running");
            return Ok(status);
        }

        if status.container_id.is_some() {
            // Container exists but is stopped, start it
            info!("Starting existing container");
            self.bounded("start the container", async {
                self.docker
                    .start_container(CONTAINER_NAME, None::<StartContainerOptions<String>>)
                    .await
                    .map_err(AppError::Docker)
            })
            .await?;
        } else {
            // Need to create the container
            info!("Creating new container");
            self.create_container().await?;

            self.bounded("start the new container", async {
                self.docker
                    .start_container(CONTAINER_NAME, None::<StartContainerOptions<String>>)
                    .await
                    .map_err(AppError::Docker)
            })
            .await?;
        }

        // New image is now active — opportunistically remove any older
        // Kali image versions left over from previous Maestro upgrades.
        // Best-effort: errors are logged inside, never block startup.
        let status = self
            .bounded("read container status", self.get_container_status())
            .await?;
        if status.running {
            let _ = self.prune_old_kali_images().await;
        }
        Ok(status)
    }

    /// Stop the Kali container
    pub async fn stop_container(&self) -> Result<ContainerStatus> {
        let status = self.get_container_status().await?;

        if !status.running {
            info!("Container already stopped");
            return Ok(status);
        }

        info!("Stopping container");
        self.docker
            .stop_container(CONTAINER_NAME, Some(StopContainerOptions { t: 10 }))
            .await
            .map_err(|e| AppError::Docker(e))?;

        self.get_container_status().await
    }

    /// Render a host-relative path as a forward-slashed string for use as
    /// the **container** (Linux) side of a `/mnt/host-home/<rel>` mount.
    /// `Path::display()` emits backslashes on Windows, which are invalid in
    /// a Linux container path and break Docker's bind parsing — convert them
    /// to forward slashes. The host *source* side keeps its native form
    /// (Docker Desktop resolves `C:\...` sources fine); only the container
    /// destination must be POSIX.
    fn container_rel(rel: &std::path::Path) -> String {
        rel.to_string_lossy().replace('\\', "/")
    }

    /// Push a `host:container` bind where the container path is identical
    /// to the host path. **No-op on non-Unix hosts.**
    ///
    /// Same-path mounts only make sense on Unix: a Windows source like
    /// `C:\Users\you\repo` cannot be a container destination because (a) a
    /// Linux container needs an absolute Unix path, and (b) the drive-letter
    /// colon collides with Docker's `source:dest:mode` bind syntax (the same
    /// footgun the local-repo loop already guards against). On Windows the
    /// container relies solely on the companion `/mnt/host-home/...` and
    /// `/app/config` Linux-target mounts, whose Windows *source* Docker
    /// Desktop resolves automatically.
    fn push_same_path_bind(binds: &mut Vec<String>, path: &std::path::Path, ro: bool) {
        #[cfg(unix)]
        {
            let suffix = if ro { ":ro" } else { "" };
            binds.push(format!("{}:{}{}", path.display(), path.display(), suffix));
        }
        #[cfg(not(unix))]
        {
            let _ = (binds, path, ro);
        }
    }

    /// Build the bind-mount list that a fresh container should have. Kept
    /// in one place so `create_container` and `container_needs_recreate`
    /// can both read from the same source of truth.
    fn expected_binds() -> Result<Vec<String>> {
        let home_dir = dirs::home_dir()
            .ok_or_else(|| AppError::Config("Could not determine home directory".to_string()))?;
        let config_dir = home_dir.join(".kali-mcp-pentest");
        std::fs::create_dir_all(&config_dir)?;
        let claude_home = config_dir.join("claude-home");
        std::fs::create_dir_all(&claude_home)?;
        // Codex auth + MCP config persist in their own dir so the user only
        // runs `codex login --device-auth` once per machine, even across
        // container rebuilds. Mirrors the claude-home pattern.
        let codex_home = config_dir.join("codex-home");
        std::fs::create_dir_all(&codex_home)?;
        // MCP server SQLite DB (assessment_checkpoints, findings, audit logs)
        // lives at /root/.pentest/data/pentest.db inside the container. Without
        // a bind it sits in the container writable layer — it survives a
        // stop→start but is destroyed whenever the drift detector recreates the
        // container (version bump / config change). Persist it on the host so a
        // resumed assessment keeps its checkpoints and audit trail across
        // recreates. The MCP server creates the `data/` subdir itself.
        let pentest_data = config_dir.join("pentest-data");
        std::fs::create_dir_all(&pentest_data)?;

        // Filesystem scope — Tier 1 (v0.1.49):
        // Block writes from inside the container to anything outside a
        // narrow allow-list. This prevents the assessment terminal from
        // being misused as a general dev workspace — claude/codex can no
        // longer modify Maestro source, append to ~/.zshrc, overwrite
        // ~/.ssh/authorized_keys, or write into customer repos. Reads
        // stay broad so SAST scanners and slash-command discovery keep
        // working. Read-side scoping (Tier 2) and network egress
        // filtering (Tier 3) are tracked in
        // memory/project_container_filesystem_scope.md.
        let mut binds = vec![
            // -- Writable carve-outs (the ONLY paths inside the container
            // where writes succeed outside the per-engagement workspace) --
            //
            // /app/config : Maestro state (cloud-session.json,
            //   credentials-merged.json, integrations.yml, scratch).
            //   Same host dir as the legacy /mnt/host-home/.kali-mcp-pentest
            //   bind below — two container paths into the same host dir.
            // /root/.claude, /root/.codex : per-CLI auth + MCP configs so
            //   logins survive container recreates.
            // /mnt/host-home/.kali-mcp-pentest : preserves the legacy
            //   write path used by the in-container reporting.ts
            //   (HOST_REPORTS_DIR = "/mnt/host-home/.kali-mcp-pentest/reports")
            //   without re-opening the broad /mnt/host-home RW mount.
            //   Only this one subtree under /mnt/host-home is writable.
            format!("{}:/app/config", config_dir.display()),
            format!("{}:/root/.claude", claude_home.display()),
            format!("{}:/root/.codex", codex_home.display()),
            format!("{}:/root/.pentest", pentest_data.display()),
            format!("{}:/mnt/host-home/.kali-mcp-pentest", config_dir.display()),
        ];

        // -- Per-engagement workspace carve-outs (v0.1.52) --
        //
        // The assessment workflow writes intermediate .md, .yml checkpoints,
        // and final reports under <project>/reports — and similarly to
        // <project>/logs and <project>/data. Tier 1 made the project tree RO,
        // so /assess hit EROFS on every Write call. We carve the three
        // workspace subdirs back out as RW (same-path AND under
        // /mnt/host-home for tools that hardcode the legacy prefix).
        //
        // The source tree itself (.claude/, src/, frontend/, etc.) stays RO
        // because nothing here mounts it — only `reports/`, `logs/`, `data/`
        // are writable. Scoped enough that claude can't modify Maestro
        // source while still being able to do its actual job.
        //
        // For customers without the kali-mcp-pentest source repo on disk,
        // these dirs don't exist; create_dir_all returns Err and we skip
        // the bind silently — they only have ~/.kali-mcp-pentest/ writable.
        let project_root = std::path::PathBuf::from(
            crate::commands::terminal::get_project_root(),
        );
        for sub in &["reports", "logs", "data"] {
            let dir = project_root.join(sub);
            if std::fs::create_dir_all(&dir).is_ok() && dir.is_dir() {
                Self::push_same_path_bind(&mut binds, &dir, false);
                if let Ok(rel) = dir.strip_prefix(&home_dir) {
                    binds.push(format!(
                        "{}:/mnt/host-home/{}",
                        dir.display(),
                        Self::container_rel(rel)
                    ));
                }
            }
        }

        // -- Tier 2 (v0.1.54+): RO mounts derived from Code Repositories registry --
        //
        // Replaces the broad `~:RO` and `~:/mnt/host-home:RO` mounts
        // that gave the container read access to the user's entire
        // home (SSH keys, AWS creds, browser profiles, every other
        // repo). Now the container can only READ:
        //
        //   - The Maestro project itself (for slash commands, agent
        //     prompts, skills, test-matrix.yml)
        //   - Each LOCAL repo the user has explicitly added via the
        //     desktop's Code Repositories page (registry written by
        //     repos.rs::write_repo_registry to
        //     ~/.kali-mcp-pentest/repo-registry.json).
        //   - GitHub-attached repos don't need an extra bind — their
        //     clones live in ~/.kali-mcp-pentest/repo-cache/ which is
        //     already RW-mounted via the existing carve-out.
        //
        // **scope.local.yml / scope.yml are deliberately NOT read here**.
        // The Code Repositories page is the single source of truth for
        // "what does the container have access to". This avoids the
        // surprise of the container auto-mounting paths the user never
        // explicitly registered (v0.1.55 hit this with operator-specific repo paths in
        // scope.local.yml — they had `:` in the directory name which
        // also broke Docker's bind syntax).
        Self::push_same_path_bind(&mut binds, &project_root, true);
        if let Ok(rel) = project_root.strip_prefix(&home_dir) {
            binds.push(format!(
                "{}:/mnt/host-home/{}:ro",
                project_root.display(),
                Self::container_rel(rel)
            ));
        }

        let (has_any_repos, local_paths) = Self::read_repo_registry(&config_dir);
        if !has_any_repos {
            // Tier 2 hardening (v0.1.74+): empty registry NO LONGER falls
            // back to broad ~:ro. The previous behavior gave the
            // container read access to the entire user home (SSH keys,
            // AWS creds, browser profiles) for any user who hadn't
            // explicitly registered a repo — exactly the scope leak
            // Tier 2 was supposed to close.
            //
            // After this version, an empty registry produces NO host-home
            // RO mount. The container can still:
            //   - Read the Maestro project itself (slash commands, agent
            //     prompts, skills) — bound above
            //   - RW its own state (/app/config, /root/.claude, /root/.codex)
            //   - RW the carved-out reports/logs/data dirs
            //   - Egress to in-scope targets (Tier 3 not yet enforcing)
            //
            // What it CAN'T do: read ~/.ssh/, ~/.aws/, anything outside
            // the registered repos.
            //
            // Escape valve: setting MAESTRO_ALLOW_BROAD_HOME=1 in the
            // environment re-enables the legacy broad mount. Logged
            // loudly when active so it shows up in audit. Intended only
            // for customers in transition who have a legacy workflow
            // that can't yet fit through the Code Repositories page.
            let allow_broad =
                std::env::var("MAESTRO_ALLOW_BROAD_HOME").as_deref() == Ok("1");
            if allow_broad {
                warn!(
                    "MAESTRO_ALLOW_BROAD_HOME=1 — broad ~:ro mount enabled. \
                     This is a deprecated escape valve; register repos via the \
                     Code Repositories page instead so this can be removed."
                );
                binds.push(format!("{}:/mnt/host-home:ro", home_dir.display()));
                Self::push_same_path_bind(&mut binds, &home_dir, true);
            } else {
                info!(
                    "Code Repositories registry empty — container has no \
                     host-home read access (Tier 2 lockdown engaged). Add a \
                     repo via the Code Repositories page to enable scanning."
                );
            }
        } else {
            // Lockdown engaged. GitHub-attached repos are already
            // accessible via the always-mounted ~/.kali-mcp-pentest/
            // carve-out (their cache clones live under repo-cache/).
            // Only legacy local-source repos (deprecated in v0.1.57 but
            // still tolerated for existing rows in the SQLite) need a
            // per-path bind. New repos must be Git-hosted.
            for repo in &local_paths {
                if repo.contains(':') {
                    warn!(
                        "Skipping repo with colon in path (Docker bind syntax conflict): {}",
                        repo
                    );
                    continue;
                }
                let repo_path = std::path::PathBuf::from(repo);
                if !repo_path.is_dir() {
                    warn!(
                        "Registered repo path doesn't exist on disk, skipping: {}",
                        repo
                    );
                    continue;
                }
                Self::push_same_path_bind(&mut binds, &repo_path, true);
                if let Ok(rel) = repo_path.strip_prefix(&home_dir) {
                    binds.push(format!(
                        "{}:/mnt/host-home/{}:ro",
                        repo_path.display(),
                        Self::container_rel(rel)
                    ));
                }
            }
        }

        Ok(binds)
    }

    /// Tier 3 egress (v0.1.77+) — return `true` when the user has opted
    /// into outbound network filtering. Read once at container-create
    /// time. The flag flips behavior in TWO places:
    ///   - Adds `NET_ADMIN` to the container's caps so the in-container
    ///     entrypoint can run `iptables`.
    ///   - Sets `MAESTRO_TIER3_EGRESS=1` so egress-init.sh actually
    ///     applies the rules (otherwise it's a no-op).
    /// Default off in v0.1.77 so existing customers don't get
    /// surprise-blocked. Default on in v0.1.78 once the watchdog has
    /// proven itself in production.
    fn tier3_egress_enabled() -> bool {
        std::env::var("MAESTRO_TIER3_EGRESS").as_deref() == Ok("1")
    }

    /// Build the container env var set. Centralized so the drift detector
    /// in `container_needs_recreate` can compare against the same source
    /// of truth — flipping MAESTRO_TIER3_EGRESS triggers a recreate so the
    /// new caps + env land cleanly.
    fn container_env(tier3: bool) -> Vec<String> {
        let mut env = vec![
            "MAESTRO_CLOUD_SESSION_PATH=/mnt/host-home/.kali-mcp-pentest/cloud-session.json".to_string(),
            "MAESTRO_CREDENTIALS_PATH=/mnt/host-home/.kali-mcp-pentest/credentials-merged.json".to_string(),
            // OAST listener config for the `oast` verification oracle. The file
            // may not exist (no listener configured for this org) — the oracle
            // then reports `oast_unavailable` and blind findings stay honest
            // unverified candidates rather than being silently dropped.
            "MAESTRO_OAST_CONFIG_PATH=/mnt/host-home/.kali-mcp-pentest/oast.json".to_string(),
        ];
        if tier3 {
            env.push("MAESTRO_TIER3_EGRESS=1".to_string());
            let config_dir = dirs::home_dir()
                .map(|h| h.join(".kali-mcp-pentest"))
                .unwrap_or_default();
            let allowlist = Self::build_egress_allowlist(&config_dir);
            if !allowlist.is_empty() {
                env.push(format!("MAESTRO_TIER3_ALLOWLIST={}", allowlist));
            }
            if let Ok(backend_host) = std::env::var("MAESTRO_BACKEND_HOST") {
                if !backend_host.is_empty() {
                    env.push(format!("MAESTRO_BACKEND_HOST={}", backend_host));
                }
            }
        }
        env
    }

    /// Read `~/.kali-mcp-pentest/scope-merged.json` (written by
    /// `cloud.rs::write_merged_scope_file`) and produce the comma-separated
    /// allowlist string that egress-init.sh consumes.
    ///
    /// Format per entry:
    ///   - `<ip-or-cidr>:<port>` — opens that port to that destination
    ///   - `<ip-or-cidr>` — opens 80+443 (covers HTTP and HTTPS scans)
    ///   - `<hostname>` — passed through; egress-init.sh resolves at startup
    ///
    /// Wildcard domains (`*.example.com`) are NOT expanded — iptables can't
    /// match on hostname and we can't enumerate every possible subdomain.
    /// Users with wildcard scope must add the specific subdomains they want
    /// to scan as `networks` entries (or as concrete hostnames). Logs a
    /// warning when wildcards are present so the user notices the gap.
    ///
    /// The per-org backend host is emitted SEPARATELY via `MAESTRO_BACKEND_HOST`
    /// rather than folded into the allowlist — egress-init treats it as a
    /// system endpoint that's always reachable, never gated on scope.
    fn build_egress_allowlist(config_dir: &std::path::Path) -> String {
        let scope_path = config_dir.join("scope-merged.json");
        let content = match std::fs::read_to_string(&scope_path) {
            Ok(c) => c,
            Err(_) => return String::new(),
        };
        let parsed = match serde_json::from_str::<serde_json::Value>(&content) {
            Ok(v) => v,
            Err(_) => return String::new(),
        };
        let mut entries: Vec<String> = Vec::new();

        if let Some(networks) = parsed.get("networks").and_then(|n| n.as_array()) {
            for net in networks {
                let cidr = net.get("cidr").and_then(|v| v.as_str())
                    .or_else(|| net.get("address").and_then(|v| v.as_str()))
                    .or_else(|| net.get("pattern").and_then(|v| v.as_str()));
                let Some(cidr) = cidr else { continue };
                let cidr = cidr.trim();
                if cidr.is_empty() { continue }
                if let Some(port) = net.get("port").and_then(|v| v.as_u64()) {
                    entries.push(format!("{}:{}", cidr, port));
                } else {
                    entries.push(cidr.to_string());
                }
            }
        }

        let mut wildcard_skipped = 0usize;
        if let Some(domains) = parsed.get("domains").and_then(|d| d.as_array()) {
            for dom in domains {
                let pattern = dom.get("pattern").and_then(|v| v.as_str())
                    .or_else(|| dom.get("domain").and_then(|v| v.as_str()));
                let Some(pattern) = pattern else { continue };
                let pattern = pattern.trim();
                if pattern.is_empty() { continue }
                if pattern.contains('*') {
                    wildcard_skipped += 1;
                    continue;
                }
                entries.push(pattern.to_string());
            }
        }

        if wildcard_skipped > 0 {
            warn!(
                "Tier 3 egress: skipped {} wildcard domain(s) — iptables can't \
                 match on hostname. Add concrete subdomains as `networks` \
                 entries to bring them under enforcement.",
                wildcard_skipped
            );
        }

        entries.join(",")
    }

    /// Read `~/.kali-mcp-pentest/repo-registry.json` (written by
    /// `repos.rs::write_repo_registry`) and return:
    ///   - whether ANY repos are registered (any source type), and
    ///   - the host paths of LEGACY local-source repos that still need
    ///     per-repo bind mounts. GitHub-attached repos are skipped
    ///     because their cache clones live under
    ///     ~/.kali-mcp-pentest/repo-cache/, which is already RW-mounted.
    fn read_repo_registry(config_dir: &std::path::Path) -> (bool, Vec<String>) {
        let registry_path = config_dir.join("repo-registry.json");
        let content = match std::fs::read_to_string(&registry_path) {
            Ok(c) => c,
            Err(_) => return (false, Vec::new()),
        };
        let parsed = match serde_json::from_str::<serde_json::Value>(&content) {
            Ok(v) => v,
            Err(_) => return (false, Vec::new()),
        };
        let Some(repos) = parsed.get("repos").and_then(|r| r.as_array()) else {
            return (false, Vec::new());
        };
        let has_any = !repos.is_empty();
        let mut local_paths: Vec<String> = Vec::new();
        for repo in repos {
            let source_type = repo.get("source_type").and_then(|s| s.as_str());
            if source_type == Some("github") {
                continue;
            }
            if let Some(host_path) = repo.get("host_path").and_then(|h| h.as_str()) {
                local_paths.push(host_path.to_string());
            }
        }
        (has_any, local_paths)
    }

    /// Returns `true` when the running container's config has drifted from
    /// what this build of the desktop app expects — either a different
    /// image tag or a different bind-mount set. Triggers an automatic
    /// recreate in `start_container`.
    async fn container_needs_recreate(&self) -> Result<bool> {
        let inspect = match self.docker.inspect_container(CONTAINER_NAME, None).await {
            Ok(i) => i,
            Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 404, ..
            }) => return Ok(false), // No container, nothing to recreate.
            Err(e) => return Err(AppError::Docker(e)),
        };

        // Image tag: bollard's `.image` returns the resolved sha256 digest on
        // running containers and the tag string when the image is pulled by
        // name. Cover both: inspect `Config.Image` which keeps the original
        // tag the container was started from.
        let actual_image = inspect
            .config
            .as_ref()
            .and_then(|c| c.image.as_deref())
            .unwrap_or("");
        if actual_image != kali_image() {
            info!(
                "Container image drift: running={} expected={}",
                actual_image,
                kali_image()
            );
            return Ok(true);
        }

        // Bind mounts — compare as sets so order doesn't matter. Bollard
        // normalizes paths (drops trailing slashes, rewrites `:ro` etc.),
        // so compare on the raw strings after the same normalization.
        let expected: HashSet<String> = Self::expected_binds()?.into_iter().collect();
        let actual: HashSet<String> = inspect
            .host_config
            .as_ref()
            .and_then(|h| h.binds.clone())
            .unwrap_or_default()
            .into_iter()
            .collect();
        if expected != actual {
            info!(
                "Container bind drift — expected {:?}, got {:?}",
                expected, actual
            );
            return Ok(true);
        }

        // Env vars — we only check the ones we explicitly set so unrelated
        // image-defined env (PATH, etc.) doesn't trigger spurious recreates.
        // MAESTRO_CLOUD_SESSION_PATH (v0.1.9) tells the in-container MCP
        // where the cloud-session bridge file lives; MAESTRO_CREDENTIALS_PATH
        // (v0.1.45) does the same for the merged credentials file. Either
        // missing means the container predates a feature that needs them.
        let envs = inspect.config.as_ref().and_then(|c| c.env.as_ref());
        let cloud_session_present = envs
            .map(|e| e.iter().any(|v| v.starts_with("MAESTRO_CLOUD_SESSION_PATH=")))
            .unwrap_or(false);
        let credentials_path_present = envs
            .map(|e| e.iter().any(|v| v.starts_with("MAESTRO_CREDENTIALS_PATH=")))
            .unwrap_or(false);
        if !cloud_session_present {
            info!("Container env drift — MAESTRO_CLOUD_SESSION_PATH missing");
            return Ok(true);
        }
        if !credentials_path_present {
            info!("Container env drift — MAESTRO_CREDENTIALS_PATH missing");
            return Ok(true);
        }

        // Tier 3 egress (v0.1.77+): flipping the feature flag must rebuild
        // the container because (a) the iptables-applying entrypoint only
        // engages when MAESTRO_TIER3_EGRESS=1 is in the container env and
        // (b) NET_ADMIN cap-add/drop is set at create-time and can't be
        // toggled on a running container. Detect drift by comparing the
        // configured flag state against what's actually in the container.
        let tier3_flag_now = Self::tier3_egress_enabled();
        let tier3_in_container = envs
            .map(|e| e.iter().any(|v| v == "MAESTRO_TIER3_EGRESS=1"))
            .unwrap_or(false);
        if tier3_flag_now != tier3_in_container {
            info!(
                "Container env drift — Tier 3 egress flag changed (configured={}, container={})",
                tier3_flag_now, tier3_in_container
            );
            return Ok(true);
        }

        // Platform check — Apple Silicon hosts that ran an old multi-arch
        // build of the Kali image got an arm64-native container. The Kali
        // image is now amd64-only (qemu-aarch64 segfault on systemd 260.1
        // forced us to drop arm64 from the build), so existing arm64
        // containers don't have the v0.1.32+ tooling (codex, etc.) that
        // only ships in the amd64 image. Force a recreate so the new
        // container is created via Rosetta2 from the amd64 image.
        let actual_platform = inspect.platform.as_deref().unwrap_or("");
        if !actual_platform.is_empty() && actual_platform != "linux/amd64" {
            info!(
                "Container platform drift — running={}, expected=linux/amd64",
                actual_platform,
            );
            return Ok(true);
        }

        Ok(false)
    }

    /// Remove the existing container (stopping it first if needed). Used
    /// when `container_needs_recreate` detects drift.
    async fn remove_container(&self) -> Result<()> {
        info!("Removing container {} for recreation", CONTAINER_NAME);
        self.docker
            .remove_container(
                CONTAINER_NAME,
                Some(RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                }),
            )
            .await
            .map_err(|e| AppError::Docker(e))?;
        Ok(())
    }

    /// Create the Kali container with proper configuration. Auto-pulls
    /// the image from GHCR if it's not present locally.
    async fn create_container(&self) -> Result<()> {
        if !self.image_exists().await? {
            info!("Kali image not found locally — pulling from GHCR");
            // Honest, actionable error instead of a raw registry "unauthorized"
            // when the brokered credential is missing/expired.
            self.pull_image().await.map_err(|e| {
                AppError::Config(format!(
                    "Licensed toolkit image {} couldn't be downloaded ({}). \
                     Re-sign into Maestro Cloud (Settings → Cloud), then retry.",
                    kali_image(),
                    e
                ))
            })?;
        }

        // NET_RAW lets nmap/hping/masscan open raw sockets for SYN scans
        // and ICMP probes. NET_ADMIN was dropped in v0.1.54 because the
        // assessment toolkit didn't need it; it now comes back conditionally
        // when the user opts into Tier 3 outbound egress (v0.1.77+) so the
        // in-container entrypoint can run `iptables` to install the
        // allowlist. When Tier 3 is off, NET_ADMIN stays dropped and the
        // container behaves identically to v0.1.54+.
        let tier3 = Self::tier3_egress_enabled();
        let mut cap_add = vec!["NET_RAW".to_string()];
        let mut cap_drop = Vec::<String>::new();
        if tier3 {
            cap_add.push("NET_ADMIN".to_string());
        } else {
            cap_drop.push("NET_ADMIN".to_string());
        }

        let host_config = bollard::service::HostConfig {
            binds: Some(Self::expected_binds()?),
            port_bindings: Some({
                let mut bindings = HashMap::new();
                bindings.insert(
                    "3001/tcp".to_string(),
                    Some(vec![bollard::service::PortBinding {
                        host_ip: Some("127.0.0.1".to_string()),
                        host_port: Some("3001".to_string()),
                    }]),
                );
                bindings
            }),
            network_mode: Some("bridge".to_string()),
            cap_add: Some(cap_add),
            cap_drop: Some(cap_drop),
            // Auto-restart the container on host reboot / Docker Desktop
            // relaunch so a long-running assessment survives a shutdown without
            // the user manually restarting it. `unless-stopped` (not `always`)
            // means an explicit `docker stop` — i.e. our own stop_container()
            // and the drift-recreate teardown — is respected and NOT
            // auto-restarted. The daemon must be up for this to fire, so it
            // covers the daemon-already-running reboot and Docker-restart cases;
            // a cold boot still relies on the app's startup start_container().
            restart_policy: Some(bollard::service::RestartPolicy {
                name: Some(bollard::service::RestartPolicyNameEnum::UNLESS_STOPPED),
                maximum_retry_count: None,
            }),
            ..Default::default()
        };

        // Container env contains both static feature defaults and dynamic
        // values (allowlist string built from scope.json), so keep it as a
        // Vec<String> and use Config<String> below to match. Bollard's
        // Config is generic over the string type — `String` reads identically
        // upstream as `&str`, just owned.
        let env_strings = Self::container_env(tier3);
        let image_tag = kali_image().to_string();
        let config: Config<String> = Config {
            image: Some(image_tag),
            hostname: Some(CONTAINER_NAME.to_string()),
            host_config: Some(host_config),
            // Tell the in-container MCP HTTP server where to find the desktop's
            // active cloud-session file and the merged credentials file.
            // Inside the container, the host home is mounted at /mnt/host-home,
            // so .kali-mcp-pentest sits beside it. The desktop writes/clears
            // these files via write_cloud_session_file and
            // write_merged_credentials_file. With both paths set, MCP
            // scope-config + auth-handler read scope/credentials from the
            // org's cloud backend instead of the project's local YAML — so
            // customers configure scope and creds in the desktop UI and the
            // assessment runtime sees them without local YAML maintenance.
            env: Some(env_strings),
            exposed_ports: Some({
                let mut ports: HashMap<String, HashMap<(), ()>> = HashMap::new();
                ports.insert("3001/tcp".to_string(), HashMap::new());
                ports
            }),
            ..Default::default()
        };

        self.bounded("create the container", async {
            self.docker
                .create_container(
                    Some(CreateContainerOptions {
                        name: CONTAINER_NAME,
                        // Match the platform we pulled (see pull_image_with_progress).
                        // amd64 explicit so Apple Silicon hosts run the container
                        // through Rosetta2 instead of failing the platform match.
                        platform: Some("linux/amd64"),
                    }),
                    config,
                )
                .await
                .map_err(AppError::Docker)
        })
        .await?;

        info!("Container {} created from {}", CONTAINER_NAME, kali_image());
        Ok(())
    }

    /// Check if the Kali image exists locally
    /// True only when the expected image is present locally AND is the right
    /// platform (linux/amd64). A present-but-wrong-arch image (e.g. a stray
    /// local arm64 build retagged to the expected tag) is treated as ABSENT —
    /// otherwise the recreate guard would tear down a working container and
    /// then fail to create one from an unusable image. This is the exact brick
    /// a manual arm64 retag caused; "usable" must mean right-platform, not just
    /// "the tag exists".
    pub async fn image_exists(&self) -> Result<bool> {
        match self.docker.inspect_image(kali_image()).await {
            Ok(img) => {
                let arch_ok = img.architecture.as_deref() == Some("amd64");
                if !arch_ok {
                    warn!(
                        "Local image {} is present but not linux/amd64 (arch={:?}) — treating as absent so it isn't used",
                        kali_image(),
                        img.architecture
                    );
                }
                Ok(arch_ok)
            }
            Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 404, ..
            }) => Ok(false),
            Err(e) => Err(AppError::Docker(e)),
        }
    }

    /// Pure decision: should this locally-cached image be removed during
    /// post-upgrade cleanup? Extracted from `prune_old_kali_images` so
    /// the filter logic is unit-testable without a Docker daemon.
    ///
    /// `repo_match` must include the trailing `:` (e.g.
    /// `"ghcr.io/shmalex405/docker-kali:"`) so the prefix check can't
    /// accidentally match `…-extra:tag`.
    fn should_prune_kali_image(
        image_id: &str,
        repo_tags: &[String],
        current_id: &str,
        repo_match: &str,
    ) -> bool {
        if image_id == current_id {
            return false;
        }
        repo_tags.iter().any(|t| t.starts_with(repo_match))
    }

    /// Remove old Kali image versions left over from previous Maestro
    /// upgrades. Each Maestro release pins `KALI_IMAGE` to a new GHCR
    /// tag (e.g. `:v0.1.77`), so without explicit cleanup every upgrade
    /// adds another ~21 GB Kali image to the host while the previous
    /// versions stay tagged and cached. This scans local images that
    /// share the active image's repository and removes anything that
    /// isn't the currently-running image ID.
    ///
    /// Scoped strictly to `ghcr.io/shmalex405/docker-kali` (or whatever
    /// `KALI_IMAGE` is set to) so unrelated Docker projects on the host
    /// are untouched. Per-image failures (image-in-use, daemon error)
    /// are logged at `warn` and swallowed — cleanup is opportunistic
    /// and must never block the assessment workflow.
    async fn prune_old_kali_images(&self) -> Result<()> {
        let current = match self.docker.inspect_image(kali_image()).await {
            Ok(img) => img,
            Err(e) => {
                warn!(
                    "Skipping old-image cleanup — inspect of current image failed: {}",
                    e
                );
                return Ok(());
            }
        };
        let Some(current_id) = current.id else {
            return Ok(());
        };

        // Repo prefix = everything before the final `:` in the image
        // reference. We only consider images tagged under this exact
        // repository so other projects (postgres, redis, customer
        // images) stay completely untouched.
        let image_ref = kali_image();
        let repo_prefix = image_ref
            .rsplit_once(':')
            .map(|(repo, _)| repo)
            .unwrap_or(image_ref);
        let repo_match = format!("{}:", repo_prefix);

        let images = match self
            .docker
            .list_images(Some(ListImagesOptions::<String> {
                all: false,
                ..Default::default()
            }))
            .await
        {
            Ok(imgs) => imgs,
            Err(e) => {
                warn!("Old-image cleanup skipped — list_images failed: {}", e);
                return Ok(());
            }
        };

        for img in images {
            if !Self::should_prune_kali_image(&img.id, &img.repo_tags, &current_id, &repo_match) {
                continue;
            }
            // `force: false` is deliberate. If something else on the host
            // is still using the image (a manually-started container,
            // another project that happened to pull the same SHA), the
            // daemon refuses the delete and we log + move on. Skipping
            // is always safer than ripping an image out from under a
            // running container.
            match self
                .docker
                .remove_image(
                    &img.id,
                    Some(RemoveImageOptions {
                        force: false,
                        noprune: false,
                    }),
                    None,
                )
                .await
            {
                Ok(_) => info!(
                    "Removed superseded Kali image {} (tags: {:?})",
                    img.id, img.repo_tags
                ),
                Err(e) => warn!(
                    "Could not remove old Kali image {} (tags: {:?}): {}",
                    img.id, img.repo_tags, e
                ),
            }
        }
        Ok(())
    }

    /// Pull the Kali image from GHCR. Streams progress lines to `tracing`
    /// so users can watch `~/Library/Logs/Maestro` for a heartbeat during
    /// a cold-install; the startup gate surfaces coarser progress via the
    /// `kali-pull-progress` event emitted below when an AppHandle is
    /// provided.
    pub async fn pull_image(&self) -> Result<()> {
        // Use the brokered credential when present so the container lifecycle
        // pulls the PRIVATE toolkit image authenticated. Anonymous (None) only
        // happens when no credential was cached — which can't pull the private
        // image, so the caller surfaces an honest "sign into Maestro Cloud".
        let auth = self.registry_credentials.as_ref().map(|c| {
            bollard::auth::DockerCredentials {
                username: Some(c.username.clone()),
                password: Some(c.password.clone()),
                ..Default::default()
            }
        });
        self.pull_image_with_progress::<fn(&CreateImageInfo)>(None, auth)
            .await
    }

    /// Pull with an explicit GHCR auth config — used by the toolkit flow
    /// where the backend brokers a PAT on behalf of authenticated desktop
    /// clients. Docker SDK auth config is a JSON blob with `username` +
    /// `password` fields, base64-encoded in the `X-Registry-Auth` header;
    /// bollard handles the encoding for us.
    pub async fn pull_image_with_auth<F>(
        &self,
        username: &str,
        password: &str,
        on_progress: Option<F>,
    ) -> Result<()>
    where
        F: Fn(&CreateImageInfo),
    {
        let auth = bollard::auth::DockerCredentials {
            username: Some(username.to_string()),
            password: Some(password.to_string()),
            ..Default::default()
        };
        self.pull_image_with_progress(on_progress, Some(auth)).await
    }

    /// Internal pull helper that takes an optional progress callback so
    /// the Tauri command layer can forward per-layer `CreateImageInfo`
    /// frames to the front-end. Each frame carries `id` (layer hash),
    /// `status` ("Downloading"/"Extracting"/…), and `progress_detail`
    /// (current/total bytes) — enough to compute an overall percentage.
    pub async fn pull_image_with_progress<F>(
        &self,
        on_progress: Option<F>,
        auth: Option<bollard::auth::DockerCredentials>,
    ) -> Result<()>
    where
        F: Fn(&CreateImageInfo),
    {
        let image = kali_image();
        info!("Pulling image {}", image);

        // Force `linux/amd64`. The Kali image is built amd64-only because
        // qemu-aarch64 segfaults on systemd 260.1's postinst (see
        // .github/workflows/publish-kali.yml). On Apple Silicon hosts
        // Docker Desktop runs amd64 images via Rosetta2 emulation
        // transparently, so pulling and running amd64 works fine — but
        // without an explicit platform here, Docker tries to satisfy the
        // host arch (arm64) and fails with
        //   "no matching manifest for linux/arm64/v8"
        // Setting the platform on both the pull AND the container create
        // (below in create_container) keeps the two in lockstep.
        let options = CreateImageOptions {
            from_image: image,
            platform: "linux/amd64",
            ..Default::default()
        };

        let mut stream = self.docker.create_image(Some(options), None, auth);

        while let Some(result) = stream.next().await {
            match result {
                Ok(info) => {
                    if let Some(status) = info.status.as_deref() {
                        info!("Pull status: {}", status);
                    }
                    if let Some(cb) = on_progress.as_ref() {
                        cb(&info);
                    }
                }
                Err(e) => {
                    return Err(AppError::Docker(e));
                }
            }
        }

        info!("Image pulled successfully");
        Ok(())
    }

    /// Start the MCP server process inside the running container.
    /// Copies the compiled MCP server from the host mount to a container-local
    /// workspace (to preserve host node_modules), installs Linux-native deps,
    /// and launches the autonomous HTTP server on port 3001.
    pub async fn start_mcp_server(&self, host_mcp_path: &str) -> Result<()> {
        use bollard::exec::CreateExecOptions;

        let status = self.get_container_status().await?;
        if !status.running {
            return Err(AppError::ContainerNotRunning);
        }

        let script = format!(
            r#"
# Skip if MCP server is already running
if curl -sf http://127.0.0.1:3001/health > /dev/null 2>&1; then
    echo "MCP server already running"
    exit 0
fi

SOURCE="{source}"
MCP_DIR="/opt/pentest/mcp-server"

# Verify source dist/ exists
if [ ! -f "$SOURCE/dist/autonomous-runner.js" ]; then
    echo "ERROR: MCP server dist/ not found at $SOURCE/dist/"
    exit 1
fi

# Setup container-local workspace
mkdir -p "$MCP_DIR"
cp "$SOURCE/package.json" "$MCP_DIR/"
cp -r "$SOURCE/dist" "$MCP_DIR/"

# Install production deps if needed (rebuilds native modules for Linux)
if [ ! -d "$MCP_DIR/node_modules" ] || \
   ! diff -q "$SOURCE/package.json" "$MCP_DIR/.pkg-stamp" > /dev/null 2>&1; then
    cd "$MCP_DIR"
    npm install --production > /tmp/mcp-npm-install.log 2>&1
    cp "$SOURCE/package.json" "$MCP_DIR/.pkg-stamp"
fi

# Start the autonomous HTTP server in the background
cd "$MCP_DIR"
nohup node dist/autonomous-runner.js > /tmp/mcp-server.log 2>&1 &
echo "MCP server started (PID: $!)"
"#,
            source = host_mcp_path,
        );

        let exec = self
            .docker
            .create_exec(
                CONTAINER_NAME,
                CreateExecOptions {
                    attach_stdout: Some(true),
                    attach_stderr: Some(true),
                    cmd: Some(vec!["bash", "-c", &script]),
                    ..Default::default()
                },
            )
            .await
            .map_err(|e| AppError::Docker(e))?;

        let output = self
            .docker
            .start_exec(&exec.id, None)
            .await
            .map_err(|e| AppError::Docker(e))?;

        // Read output (the script backgrounds the server, so this returns quickly)
        let mut result = String::new();
        if let bollard::exec::StartExecResults::Attached { mut output, .. } = output {
            while let Some(msg) = output.next().await {
                if let Ok(msg) = msg {
                    result.push_str(&msg.to_string());
                }
            }
        }

        info!("MCP server start result: {}", result.trim());
        Ok(())
    }

    /// Tier 3 egress stats — runs `iptables -L OUTPUT -nvx` in the
    /// container and parses the packet counter on the rule that LOGs
    /// blocked egress. Returns `(blocked_packets, rule_count)`.
    /// Returns `(0, 0)` when the container is stopped or Tier 3 is off
    /// (iptables -L succeeds with no rules in that case). Errors only
    /// when bollard exec fails — caller can swallow them since "stats
    /// unavailable" should not break the UI.
    pub async fn get_egress_stats(&self) -> Result<(u64, usize)> {
        let output = self.exec_command(vec![
            "iptables", "-L", "OUTPUT", "-nvx", "-w", "2",
        ]).await?;
        let mut blocked = 0u64;
        let mut rule_count = 0usize;
        for line in output.lines() {
            // Format: "    pkts      bytes target ..."
            let trimmed = line.trim_start();
            if trimmed.starts_with("Chain ") || trimmed.starts_with("pkts") || trimmed.is_empty() {
                continue;
            }
            rule_count += 1;
            if line.contains("MAESTRO_BLOCKED_EGRESS") {
                if let Some(pkts_str) = trimmed.split_whitespace().next() {
                    if let Ok(n) = pkts_str.parse::<u64>() {
                        blocked = blocked.saturating_add(n);
                    }
                }
            }
        }
        Ok((blocked, rule_count))
    }

    /// Execute a command in the running container
    pub async fn exec_command(&self, command: Vec<&str>) -> Result<String> {
        use bollard::exec::{CreateExecOptions, StartExecResults};

        let status = self.get_container_status().await?;
        if !status.running {
            return Err(AppError::ContainerNotRunning);
        }

        let exec = self
            .docker
            .create_exec(
                CONTAINER_NAME,
                CreateExecOptions {
                    attach_stdout: Some(true),
                    attach_stderr: Some(true),
                    cmd: Some(command),
                    ..Default::default()
                },
            )
            .await
            .map_err(|e| AppError::Docker(e))?;

        let output = self
            .docker
            .start_exec(&exec.id, None)
            .await
            .map_err(|e| AppError::Docker(e))?;

        let mut result = String::new();
        if let StartExecResults::Attached { mut output, .. } = output {
            while let Some(msg) = output.next().await {
                if let Ok(msg) = msg {
                    result.push_str(&msg.to_string());
                }
            }
        }

        Ok(result)
    }
}

/// Build the Kali Docker image using the Docker CLI.
/// Emits `startup:build-progress` events with each line of build output.
/// This is a standalone function (not on DockerManager) because it only needs
/// the Docker CLI binary, not a daemon connection via bollard.
pub async fn build_kali_docker_image(docker_dir: &Path, app_handle: AppHandle) -> Result<()> {
    info!("Building Kali Docker image from {:?}", docker_dir);

    let mut child = tokio::process::Command::new(crate::commands::system::resolve_docker_binary())
        .args(["build", "-t", kali_image(), "-f", "Dockerfile.kali", "."])
        .current_dir(docker_dir)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| AppError::Config(format!("Failed to start docker build: {}", e)))?;

    // Docker outputs build progress to stderr
    if let Some(stderr) = child.stderr.take() {
        let reader = BufReader::new(stderr);
        let mut lines = reader.lines();
        let handle = app_handle.clone();

        tokio::spawn(async move {
            while let Ok(Some(line)) = lines.next_line().await {
                let _ = handle.emit("startup:build-progress", &line);
            }
        });
    }

    // Also capture stdout (docker buildx outputs there)
    if let Some(stdout) = child.stdout.take() {
        let reader = BufReader::new(stdout);
        let mut lines = reader.lines();
        let handle = app_handle.clone();

        tokio::spawn(async move {
            while let Ok(Some(line)) = lines.next_line().await {
                let _ = handle.emit("startup:build-progress", &line);
            }
        });
    }

    let status = child
        .wait()
        .await
        .map_err(|e| AppError::Config(format!("Docker build process error: {}", e)))?;

    if !status.success() {
        return Err(AppError::Config(format!(
            "Docker build failed with exit code: {}",
            status.code().unwrap_or(-1)
        )));
    }

    info!("Kali Docker image built successfully");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_scope(dir: &std::path::Path, json: &str) {
        let path = dir.join("scope-merged.json");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(json.as_bytes()).unwrap();
    }

    #[test]
    fn allowlist_empty_when_no_scope_file() {
        let tmp = tempfile::tempdir().unwrap();
        let out = DockerManager::build_egress_allowlist(tmp.path());
        assert_eq!(out, "");
    }

    #[test]
    fn allowlist_emits_networks_with_explicit_port() {
        let tmp = tempfile::tempdir().unwrap();
        write_scope(tmp.path(), r#"{
            "networks": [{"cidr": "10.0.0.0/8", "port": 8080}],
            "domains": [],
            "exclusions": []
        }"#);
        let out = DockerManager::build_egress_allowlist(tmp.path());
        assert_eq!(out, "10.0.0.0/8:8080");
    }

    #[test]
    fn allowlist_emits_networks_without_port_as_bare_cidr() {
        let tmp = tempfile::tempdir().unwrap();
        write_scope(tmp.path(), r#"{
            "networks": [{"cidr": "192.168.1.0/24"}],
            "domains": []
        }"#);
        let out = DockerManager::build_egress_allowlist(tmp.path());
        // Bare CIDR — egress-init.sh defaults to opening 80+443.
        assert_eq!(out, "192.168.1.0/24");
    }

    #[test]
    fn allowlist_emits_concrete_domains_skips_wildcards() {
        let tmp = tempfile::tempdir().unwrap();
        write_scope(tmp.path(), r#"{
            "networks": [],
            "domains": [
                {"pattern": "api.example.com"},
                {"pattern": "*.wild.com"},
                {"pattern": "static.example.com"}
            ]
        }"#);
        let out = DockerManager::build_egress_allowlist(tmp.path());
        // Concrete hostnames pass through; wildcard is dropped (with warning).
        // Order: scope file order — we don't sort.
        assert_eq!(out, "api.example.com,static.example.com");
    }

    #[test]
    fn allowlist_combines_networks_and_domains() {
        let tmp = tempfile::tempdir().unwrap();
        write_scope(tmp.path(), r#"{
            "networks": [{"cidr": "10.0.0.0/8"}],
            "domains": [{"pattern": "api.example.com"}]
        }"#);
        let out = DockerManager::build_egress_allowlist(tmp.path());
        assert_eq!(out, "10.0.0.0/8,api.example.com");
    }

    #[test]
    fn allowlist_handles_malformed_json_gracefully() {
        let tmp = tempfile::tempdir().unwrap();
        write_scope(tmp.path(), "{not json");
        let out = DockerManager::build_egress_allowlist(tmp.path());
        // Malformed scope must NOT panic — this runs on the container-create
        // hot path. Return empty so egress-init's scope-allowlist section
        // becomes a no-op (but system endpoints still get opened).
        assert_eq!(out, "");
    }

    #[test]
    fn container_env_omits_tier3_vars_when_flag_off() {
        let env = DockerManager::container_env(false);
        assert!(env.iter().any(|v| v.starts_with("MAESTRO_CLOUD_SESSION_PATH=")));
        assert!(env.iter().any(|v| v.starts_with("MAESTRO_CREDENTIALS_PATH=")));
        assert!(!env.iter().any(|v| v.starts_with("MAESTRO_TIER3_EGRESS=")));
        assert!(!env.iter().any(|v| v.starts_with("MAESTRO_TIER3_ALLOWLIST=")));
    }

    #[test]
    fn container_env_sets_tier3_flag_when_on() {
        let env = DockerManager::container_env(true);
        assert!(env.iter().any(|v| v == "MAESTRO_TIER3_EGRESS=1"));
    }

    const KALI_REPO_MATCH: &str = "ghcr.io/shmalex405/docker-kali:";

    #[test]
    fn prune_skips_currently_active_image() {
        // Same ID as current — never touch the image we just started from,
        // even if it happens to share the Kali repo tag.
        let removable = DockerManager::should_prune_kali_image(
            "sha256:current",
            &["ghcr.io/shmalex405/docker-kali:v0.1.90".into()],
            "sha256:current",
            KALI_REPO_MATCH,
        );
        assert!(!removable);
    }

    #[test]
    fn prune_removes_older_kali_tag() {
        // Different ID under the same repo = leftover from a previous
        // upgrade. This is the whole reason this cleanup exists.
        let removable = DockerManager::should_prune_kali_image(
            "sha256:old",
            &["ghcr.io/shmalex405/docker-kali:v0.1.89".into()],
            "sha256:current",
            KALI_REPO_MATCH,
        );
        assert!(removable);
    }

    #[test]
    fn prune_ignores_unrelated_repos() {
        // postgres, redis, customer images — never touched.
        assert!(!DockerManager::should_prune_kali_image(
            "sha256:pg",
            &["postgres:16-alpine".into()],
            "sha256:current",
            KALI_REPO_MATCH,
        ));
        assert!(!DockerManager::should_prune_kali_image(
            "sha256:redis",
            &["redis:7-alpine".into()],
            "sha256:current",
            KALI_REPO_MATCH,
        ));
    }

    #[test]
    fn prune_skips_dangling_images() {
        // No repo tags = dangling. Conservative: only act on images we
        // can positively identify as ours via the repo prefix. A
        // separate `docker image prune` covers dangling cleanup if the
        // user wants it.
        let removable = DockerManager::should_prune_kali_image(
            "sha256:dangling",
            &[],
            "sha256:current",
            KALI_REPO_MATCH,
        );
        assert!(!removable);
    }

    #[test]
    fn prune_match_does_not_bleed_into_lookalike_repos() {
        // Trailing `:` in repo_match is what guards this — without it,
        // `ghcr.io/shmalex405/docker-kali-extra` would also match.
        let removable = DockerManager::should_prune_kali_image(
            "sha256:other",
            &["ghcr.io/shmalex405/docker-kali-extra:v1".into()],
            "sha256:current",
            KALI_REPO_MATCH,
        );
        assert!(!removable);
    }

    #[test]
    fn prune_handles_image_with_multiple_tags() {
        // Same image re-tagged (e.g. `:v0.1.89` and `:stable`). One
        // matching tag is enough to mark the image for removal — Docker
        // removes the image (and all its tags) in one call.
        let removable = DockerManager::should_prune_kali_image(
            "sha256:old",
            &[
                "ghcr.io/shmalex405/docker-kali:v0.1.89".into(),
                "ghcr.io/shmalex405/docker-kali:stable".into(),
            ],
            "sha256:current",
            KALI_REPO_MATCH,
        );
        assert!(removable);
    }
}

