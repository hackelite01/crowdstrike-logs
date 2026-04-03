use std::sync::Arc;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use tracing::{debug, info, warn};

use collector_core::{CollectedEvent, Collector, CollectorError, EventSource};
use crate::auth::AuthManager;

pub struct AlertsCollector {
    pub tenant: String,
    auth:       Arc<AuthManager>,
    http:       reqwest::Client,
    base_url:   String,
    batch_size: u32,
}

impl AlertsCollector {
    pub fn new(
        tenant:     String,
        auth:       Arc<AuthManager>,
        http:       reqwest::Client,
        base_url:   String,
        batch_size: u32,
    ) -> Self {
        Self { tenant, auth, http, base_url, batch_size }
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /// Query the CrowdStrike alert ID list.
    /// Returns `(composite_ids, optional_next_after_cursor)`.
    /// Handles OAuth token acquisition and 401-retry internally.
    pub async fn query_ids(
        &self,
        since: Option<DateTime<Utc>>,
        after: Option<&str>,
    ) -> Result<(Vec<String>, Option<String>), CollectorError> {
        let mut retried = false;
        loop {
            let token = self.auth.bearer_token().await?;
            match self.query_ids_inner(&token, since, after).await {
                Err(CollectorError::Auth { .. }) if !retried => {
                    self.auth.invalidate().await;
                    retried = true;
                }
                other => return other,
            }
        }
    }

    /// Fetch full alert entity objects for a batch of composite IDs.
    /// Handles OAuth token acquisition and 401-retry internally.
    pub async fn fetch_entities(
        &self,
        ids: &[String],
    ) -> Result<Vec<serde_json::Value>, CollectorError> {
        if ids.is_empty() { return Ok(vec![]); }
        let mut retried = false;
        loop {
            let token = self.auth.bearer_token().await?;
            match self.fetch_entities_inner(&token, ids).await {
                Err(CollectorError::Auth { .. }) if !retried => {
                    self.auth.invalidate().await;
                    retried = true;
                }
                other => return other,
            }
        }
    }

    /// Extract the canonical unique ID from an alert entity.
    /// Prefers `composite_id` because that is what the query API returns,
    /// ensuring the dedup cache keys are consistent between query and entity layers.
    pub fn extract_id(entity: &serde_json::Value) -> &str {
        entity.get("composite_id")
            .or_else(|| entity.get("id"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
    }

    /// Convert raw entity JSON values to `CollectedEvent`s.
    /// ID extraction uses `composite_id` first (see `extract_id`).
    pub fn entities_to_events(
        &self,
        entities: Vec<serde_json::Value>,
        fallback_ts: DateTime<Utc>,
    ) -> Vec<CollectedEvent> {
        entities.into_iter().map(|entity| {
            let id = Self::extract_id(&entity).to_string();
            let timestamp = entity.get("created_timestamp")
                .and_then(|v| v.as_str())
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or(fallback_ts);
            CollectedEvent {
                tenant:    self.tenant.clone(),
                source:    EventSource::Alert,
                timestamp,
                id,
                payload:   entity,
            }
        }).collect()
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    async fn query_ids_inner(
        &self,
        token: &str,
        since: Option<DateTime<Utc>>,
        after: Option<&str>,
    ) -> Result<(Vec<String>, Option<String>), CollectorError> {
        let url = format!("{}/alerts/queries/alerts/v2", self.base_url);

        let filter = since
            .map(|ts| format!("created_timestamp:>='{}'", ts.to_rfc3339()))
            .unwrap_or_default();

        let mut query: Vec<(&str, String)> = vec![
            ("sort",  "created_timestamp.asc".to_string()),
            ("limit", self.batch_size.to_string()),
        ];
        if !filter.is_empty() { query.push(("filter", filter)); }
        if let Some(a) = after  { query.push(("after",  a.to_string())); }

        let resp = self.http
            .get(&url)
            .bearer_auth(token)
            .query(&query)
            .send()
            .await
            .map_err(|e| CollectorError::Http(e.to_string()))?;

        self.check_status(&resp)?;

        let body: serde_json::Value = resp.json().await
            .map_err(|e| CollectorError::Http(e.to_string()))?;

        let ids: Vec<String> = body["resources"]
            .as_array()
            .map(|arr| arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect())
            .unwrap_or_default();

        // Pagination cursor is the "after" string token (not an integer offset)
        let next_after = body["meta"]["pagination"]["after"]
            .as_str()
            .map(|s| s.to_string());

        debug!(tenant = %self.tenant, ids = ids.len(), ?next_after, "Query returned IDs");
        Ok((ids, next_after))
    }

    async fn fetch_entities_inner(
        &self,
        token: &str,
        ids: &[String],
    ) -> Result<Vec<serde_json::Value>, CollectorError> {
        let url  = format!("{}/alerts/entities/alerts/v2", self.base_url);
        let body = serde_json::json!({ "composite_ids": ids });

        let resp = self.http
            .post(&url)
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .map_err(|e| CollectorError::Http(e.to_string()))?;

        self.check_status(&resp)?;

        let result: serde_json::Value = resp.json().await
            .map_err(|e| CollectorError::Http(e.to_string()))?;

        let entities = result["resources"]
            .as_array()
            .cloned()
            .unwrap_or_default();

        debug!(tenant = %self.tenant, count = entities.len(), "Fetched entities");
        Ok(entities)
    }

    fn check_status(&self, resp: &reqwest::Response) -> Result<(), CollectorError> {
        match resp.status() {
            s if s == reqwest::StatusCode::UNAUTHORIZED => Err(CollectorError::Auth {
                tenant: self.tenant.clone(),
                reason: "401 Unauthorized".to_string(),
            }),
            s if s == reqwest::StatusCode::TOO_MANY_REQUESTS => {
                warn!(tenant = %self.tenant, "Rate limited");
                Err(CollectorError::RateLimited)
            }
            s if !s.is_success() => Err(CollectorError::Http(format!("HTTP {s}"))),
            _ => Ok(()),
        }
    }
}

/// Keep the `Collector` trait impl for compatibility with any future consumers
/// that don't need the pre-filter path.
#[async_trait]
impl Collector for AlertsCollector {
    fn name(&self) -> &str { "alerts" }

    async fn collect(
        &mut self,
        since: Option<DateTime<Utc>>,
    ) -> Result<Vec<CollectedEvent>, CollectorError> {
        let now = Utc::now();
        let mut all_events: Vec<CollectedEvent> = Vec::new();
        let mut after: Option<String> = None;

        loop {
            let (ids, next_after) = self.query_ids(since, after.as_deref()).await?;
            if !ids.is_empty() {
                let entities = self.fetch_entities(&ids).await?;
                all_events.extend(self.entities_to_events(entities, now));
            }
            after = next_after;
            if after.is_none() { break; }
        }

        info!(tenant = %self.tenant, count = all_events.len(), "Collected alerts");
        Ok(all_events)
    }
}