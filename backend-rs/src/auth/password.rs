//! Bcrypt hashing that matches the Python backend's `passlib[bcrypt]`
//! usage — critically, with 72-byte truncation so existing hashes verify.
//!
//! See `backend/app/core/security.py:_truncate_password` — passlib/bcrypt
//! reject passwords longer than 72 bytes, and the Python backend truncates
//! on both hash and verify. We do the same so users who registered on
//! Python can log in on Rust without a password reset.

use crate::error::{AppError, AppResult};

/// Truncate to 72 UTF-8 bytes, dropping any partial multibyte char at the
/// cut point (matches `.encode('utf-8')[:72].decode('utf-8', errors='ignore')`).
fn truncate_72(password: &str) -> Vec<u8> {
    let bytes = password.as_bytes();
    if bytes.len() <= 72 {
        return bytes.to_vec();
    }
    // Walk back until we land on a valid UTF-8 boundary.
    let mut end = 72;
    while end > 0 && (bytes[end] & 0b1100_0000) == 0b1000_0000 {
        end -= 1;
    }
    bytes[..end].to_vec()
}

pub fn hash_password(password: &str) -> AppResult<String> {
    let truncated = truncate_72(password);
    bcrypt::hash(&truncated, bcrypt::DEFAULT_COST)
        .map_err(|e| AppError::Internal(format!("bcrypt hash failed: {e}")))
}

pub fn verify_password(password: &str, hashed: &str) -> bool {
    let truncated = truncate_72(password);
    bcrypt::verify(&truncated, hashed).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_password_round_trip() {
        let h = hash_password("hunter2").unwrap();
        assert!(verify_password("hunter2", &h));
        assert!(!verify_password("wrong", &h));
    }

    #[test]
    fn long_password_truncation_matches_passlib() {
        // 100-byte ASCII password — passlib would hash the first 72 bytes.
        let long = "a".repeat(100);
        let h = hash_password(&long).unwrap();
        // Same 100-byte password verifies.
        assert!(verify_password(&long, &h));
        // Any string that agrees in its first 72 bytes also verifies, which
        // is exactly passlib's (intentional) behavior.
        let different_after_72 = format!("{}{}", "a".repeat(72), "DIFFERENT");
        assert!(verify_password(&different_after_72, &h));
    }
}
