//! Praxis AI, built with this repository's own filters added to its
//! registry.

use praxis_filter::FilterRegistry;

/// Praxis AI's full filter registry plus this crate's filters.
///
/// # Errors
///
/// Returns an error if a filter name collides with one of Praxis AI's.
pub fn registry(
    subrequest_client: &praxis_core::subrequest::SubRequestClient,
) -> Result<FilterRegistry, praxis_filter::FilterError> {
    Ok(praxis_ai::build_full_registry(subrequest_client))
}
