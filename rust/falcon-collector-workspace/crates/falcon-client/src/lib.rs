pub mod alerts;
pub mod auth;

pub use auth::AuthManager;
pub use alerts::AlertsCollector;

use reqwest::Client;

/// Build a shared reqwest client with rustls (no OpenSSL dependency ? cross-platform)
pub fn build_http_client() -> Client {
    Client::builder()
        .use_rustls_tls()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("Failed to build HTTP client")
}
