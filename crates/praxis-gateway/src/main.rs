//! Praxis AI, with the broker's filters registered.
use tracing::info;

const USAGE: &str = "usage: praxis-gateway [--config PATH]";

fn main() {
    // Before anything that might build a TLS config, as praxis-ai does.
    praxis_ai::install_crypto_provider();
    let mut args = std::env::args().skip(1);
    let explicit = match (args.next().as_deref(), args.next(), args.next()) {
        (None, _, _) => std::env::var("PRAXIS_CONFIG").ok(),
        (Some("-c" | "--config"), Some(path), None) => Some(path),
        _ => praxis_ai::fatal(&USAGE),
    };
    let config_path = praxis_ai::resolve_config_path(explicit.as_deref());
    let config =
        praxis_ai::load_config(explicit.as_deref()).unwrap_or_else(|e| praxis_ai::fatal(&e));
    let _tracing_guard = praxis_ai::init_tracing(&config).unwrap_or_else(|e| praxis_ai::fatal(&e));
    let client = praxis_ai::create_subrequest_client(&config);
    let registry = praxis_gateway::registry(&client).unwrap_or_else(|e| praxis_ai::fatal(&e));
    info!("starting server");
    praxis_ai::run_server_with_registry(config, registry, config_path)
}
