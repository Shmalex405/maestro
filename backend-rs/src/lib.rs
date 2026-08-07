//! `maestro-backend` library surface.
//!
//! Exposes every internal module so the binary (`main.rs`) and the
//! integration tests (`tests/`) can share one source of truth. Without
//! this, modules declared in `main.rs` are private to the binary and
//! tests can't reach them.

pub mod audit;
pub mod auth;
pub mod config;
pub mod db;
pub mod error;
pub mod models;
pub mod pdf;
pub mod routes;
pub mod schemas;
pub mod state;
pub mod util;
