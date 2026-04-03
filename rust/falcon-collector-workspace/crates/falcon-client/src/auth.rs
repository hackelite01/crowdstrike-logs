use std::sync::Arc;
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::Deserialize;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use collector_core::{CollectorError, TenantCredentials};

#[derive(Debug, Clone)]
struct CachedToken {
    access_token: String,
    expires_at: DateTime<Utc>,
}

/// Per-tenant token cache � uses RwLock so concurrent collectors can read
/// without blocking each other; only write on expiry.
#[derive(Debug)]
pub struct AuthManager {
    tenant: String,
    base_url: String,
    credentials: TenantCredentials,
    cache: Arc<RwLock<Option<CachedToken>>>,
    http: Client,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: i64,
}

impl AuthManager {
    pub fn new(tenant: String, base_url: String, credentials: TenantCredentials, http: Client) -> Self {
        Self {
            tenant,
            base_url,
            credentials,
            cache: Arc::new(RwLock::new(None)),
            http,
        }
    }

    /// Returns a valid bearer token, refreshing if within 60 s of expiry.
    pub async fn bearer_token(&self) -> Result<String, CollectorError> {
        // Fast path � valid cached token
        {
            let guard = self.cache.read().await;
            if let Some(ref tok) = *guard {
                if tok.expires_at > Utc::now() + chrono::Duration::seconds(60) {
                    debug!(tenant = %self.tenant, "Using cached token");
                    return Ok(tok.access_token.clone());
                }
            }
        }

        // Slow path � fetch new token
        let mut guard = self.cache.write().await;
        // Double-check after acquiring write lock
        if let Some(ref tok) = *guard {
            if tok.expires_at > Utc::now() + chrono::Duration::seconds(60) {
                return Ok(tok.access_token.clone());
            }
        }

        info!(tenant = %self.tenant, "Refreshing OAuth token");
        let url = format!("{}/oauth2/token", self.base_url);

        // client_secret is NEVER logged � only passed in form body over TLS
        let resp = self.http
            .post(&url)
            .form(&[
                ("client_id",     self.credentials.client_id.as_str()),
                ("client_secret", &self.credentials.client_secret),
            ])
            .send()
            .await
            .map_err(|e| CollectorError::Auth {
                tenant: self.tenant.clone(),
                reason: e.to_string(),
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            warn!(tenant = %self.tenant, status = %status, "Token request failed");
            return Err(CollectorError::Auth {
                tenant: self.tenant.clone(),
                reason: format!("HTTP {status}"),
            });
        }

        let token_resp: TokenResponse = resp.json().await.map_err(|e| CollectorError::Auth {
            tenant: self.tenant.clone(),
            reason: e.to_string(),
        })?;

        let cached = CachedToken {
            access_token: token_resp.access_token,
            expires_at: Utc::now() + chrono::Duration::seconds(token_resp.expires_in),
        };
        let token = cached.access_token.clone();
        *guard = Some(cached);

        Ok(token)
    }

    /// Invalidate the cached token (call on 401 responses)
    pub async fn invalidate(&self) {
        let mut guard = self.cache.write().await;
        *guard = None;
    }
}
