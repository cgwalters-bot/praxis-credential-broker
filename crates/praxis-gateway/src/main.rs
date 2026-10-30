//! Praxis AI, with the broker's filters registered.
use tracing::info;

const USAGE: &str = "usage: praxis-gateway [--config PATH] [--usage-state PATH]";

fn main() {
    // Before anything that might build a TLS config, as praxis-ai does.
    praxis_ai::install_crypto_provider();
    let (mut explicit, mut usage_state) = (None, None);
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let slot = match flag.as_str() {
            "-c" | "--config" => &mut explicit,
            "--usage-state" => &mut usage_state,
            _ => praxis_ai::fatal(&USAGE),
        };
        match args.next() {
            Some(value) if slot.is_none() => *slot = Some(value),
            _ => praxis_ai::fatal(&USAGE),
        }
    }
    let explicit = explicit.or_else(|| std::env::var("PRAXIS_CONFIG").ok());
    let config_path = praxis_ai::resolve_config_path(explicit.as_deref());
    let config =
        praxis_ai::load_config(explicit.as_deref()).unwrap_or_else(|e| praxis_ai::fatal(&e));
    let _tracing_guard = praxis_ai::init_tracing(&config).unwrap_or_else(|e| praxis_ai::fatal(&e));
    if let Some(path) = usage_state {
        praxis_gateway::keep_usage_state(path.into());
    }
    let client = praxis_ai::create_subrequest_client(&config);
    let registry = praxis_gateway::registry(&client).unwrap_or_else(|e| praxis_ai::fatal(&e));
    info!("starting server");
    praxis_ai::run_server_with_registry(config, registry, config_path)
}
