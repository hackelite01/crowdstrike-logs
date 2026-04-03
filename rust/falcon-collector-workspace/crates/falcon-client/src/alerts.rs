use std::sync::Arc;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use tracing::{debug, info, warn};

use collector_core::{CollectedEvent, Collector, CollectorError, EventSource};
use crate::auth::AuthManager;

pub struct AlertsCollector {
    tenant: String,
    auth: Arc<AuthManager>,
    http: reqwest::Client,
    base_url: String,
    batch_size: u32,
}

impl AlertsCollector {
    pub fn new(
        tenant: String,
        auth: Arc<AuthManager>,
        http: reqwest::Client,
        base_url: String,
        batch_size: u32,
    ) -> Self {
        Self { tenant, auth, http, base_url, batch_size }
    }

    /// Step 1: query alert IDs, returns (ids, next_after_cursor)
    async fn query_ids(
        &self,
        token: &str,
        since: Option<DateTime<Utc>>,
        after: Option<&str>,
    ) -> Result<(Vec<String>, Option<String>), CollectorError> {
        let url = format!("{}/alerts/queries/alerts/v2", self.base_url);

        let filter = since
            .map(|ts| format!("created_timestamp:>='{}'", ts.to_rfc3339()))
            .unwrap_or_default();

        let mut query = vec![
            ("sort",  "created_timestamp.asc".to_string()),
            ("limit", self.batch_size.to_string()),
        ];
        if !filter.is_empty() { query.push(("filter", filter)); }
        if let Some(a) = after   { query.push(("after",  a.to_string())); }

        let resp = self.http
            .get(&url)
            .bearer_auth(token)
            .query(&query)
            .send()
            .await
            .map_err(|e| CollectorError::Http(e.to_string()))?;

        self.check_status(&resp)?;

        // Deserialise as Value -- tolerant of any field type changes
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

        debug!(tenant = %self.tenant, ids = ids.len(), "Query returned IDs");
        Ok((ids, next_after))
    }

    /// Step 2: fetch full alert entities for a batch of IDs
    async fn fetch_entities(
        &self,
        token: &str,
        ids: &[String],
    ) -> Result<Vec<serde_json::Value>, CollectorError> {
        if ids.is_empty() { return Ok(vec![]); }

        let url = format!("{}/alerts/entities/alerts/v2", self.base_url);
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

        debug!(tenant = %self.tenant, entities = entities.len(), "Fetched entities");
        Ok(entities)
    }

    fn check_status(&self, resp: &reqwest::Response) -> Result<(), CollectorError> {
        match resp.status() {
            s if s == reqwest::StatusCode::UNAUTHORIZED => {
                Err(CollectorError::Auth {
                    tenant: self.tenant.clone(),
                    reason: "401 Unauthorized".to_string(),
                })
            }
            s if s == reqwest::StatusCode::TOO_MANY_REQUESTS => {
                warn!(tenant = %self.tenant, "Rate limited");
                Err(CollectorError::RateLimited)
            }
            s if !s.is_success() => {
                Err(CollectorError::Http(format!("HTTP {s}")))
            }
            _ => Ok(()),
        }
    }
}

#[async_trait]
impl Collector for AlertsCollector {
    fn name(&self) -> &str { "alerts" }

    async fn collect(
        &mut self,
        since: Option<DateTime<Utc>>,
    ) -> Result<Vec<CollectedEvent>, CollectorError> {
        let token = self.auth.bearer_token().await?;
        let mut all_events: Vec<CollectedEvent> = Vec::new();
        let mut after: Option<String> = None;
        let now = Utc::now();

        loop {
            // On 401: invalidate token cache and get a fresh token, then retry once
            let (ids, next_after) = match self.query_ids(&token, since, after.as_deref()).await {
                Err(CollectorError::Auth { .. }) => {
                    self.auth.invalidate().await;
                    let fresh = self.auth.bearer_token().await?;
                    self.query_ids(&fresh, since, after.as_deref()).await?
                }
                other => other?,
            };

            if !ids.is_empty() {
                let entities = self.fetch_entities(&token, &ids).await?;

                for entity in entities {
                    let id = entity.get("id")
                        .or_else(|| entity.get("composite_id"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown")
                        .to_string();

                    let timestamp = entity.get("created_timestamp")
                        .and_then(|v| v.as_str())
                        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or(now);

                    all_events.push(CollectedEvent {
                        tenant: self.tenant.clone(),
                        source: EventSource::Alert,
                        timestamp,
                        id,
                        payload: entity,
                    });
                }
            }

            after = next_after;
            if after.is_none() { break; }
        }

        info!(tenant = %self.tenant, count = all_events.len(), "Collected alerts");
        Ok(all_events)
    }
}