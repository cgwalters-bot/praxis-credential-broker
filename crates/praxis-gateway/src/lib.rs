//! Praxis AI, built with this repository's own filters added to its
//! registry: `run_token`, for per-run bearer tokens. Usage parsing and the
//! caps, per window and per run, are praxis-ai's own `token_count` and
//! `token_rate_limit`.
mod filter;
mod oidc;
mod runs;

#[cfg(test)]
mod integration_tests;

use filter::RunTokenFilter;
use praxis_filter::{FilterFactory, FilterRegistry, SecurityClass};
use std::sync::Arc;

/// Add this crate's filters to `registry`.
///
/// # Errors
///
/// Returns an error if a filter of the same name is already registered.
pub fn register_filters(registry: &mut FilterRegistry) -> Result<(), praxis_filter::FilterError> {
    registry.register_with_class(
        filter::FILTER_NAME,
        FilterFactory::Http(Arc::new(RunTokenFilter::from_config)),
        SecurityClass::Security,
    )
}

/// Praxis AI's full filter registry plus this crate's filters.
///
/// # Errors
///
/// Returns an error if a filter name collides with one of Praxis AI's.
pub fn registry(
    subrequest_client: &praxis_core::subrequest::SubRequestClient,
) -> Result<FilterRegistry, praxis_filter::FilterError> {
    let mut registry = praxis_ai::build_full_registry(subrequest_client);
    register_filters(&mut registry)?;
    Ok(registry)
}
