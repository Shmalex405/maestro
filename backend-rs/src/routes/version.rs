//! Version metadata. Public (no auth). Mirrors
//! `backend/app/routers/version.py`.

use axum::{extract::State, routing::get, Json, Router};

use crate::state::AppState;
use maestro_types::VersionResponse;

/// Minimum desktop-app version this backend can serve. Bump whenever a
/// backend change breaks older desktop clients. The Python constant is
/// `"1.0.0"` (see `backend/app/routers/version.py:MIN_DESKTOP_VERSION`),
/// but the current dev build of the Tauri shell is `0.1.0` — matching here
/// silences the "app too old" banner during local soak without touching
/// `backend/`.
const MIN_DESKTOP_VERSION: &str = "0.1.0";

pub fn router() -> Router<AppState> {
    Router::new().route("/version", get(get_version))
}

async fn get_version(State(state): State<AppState>) -> Json<VersionResponse> {
    Json(VersionResponse {
        version: state.settings.app_version.clone(),
        min_desktop_version: MIN_DESKTOP_VERSION.to_string(),
        name: state.settings.app_name.clone(),
    })
}
