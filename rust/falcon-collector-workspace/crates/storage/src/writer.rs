use std::path::PathBuf;
use chrono::Utc;
use tokio::io::AsyncWriteExt;
use tracing::debug;

use collector_core::CollectedEvent;

/// Writes events to a daily rotated JSON-lines file per tenant:
///   {dir}/falcon_alerts_{tenant}_{YYYY-MM-DD}.json
pub struct FileWriter {
    tenant: String,
    dir: PathBuf,
}

impl FileWriter {
    pub fn new(tenant: String, dir: PathBuf) -> Self {
        Self { tenant, dir }
    }

    fn current_path(&self) -> PathBuf {
        let date = Utc::now().format("%Y-%m-%d");
        self.dir.join(format!("falcon_alerts_{}_{}.json", self.tenant, date))
    }

    /// Append a batch of events as JSON lines (one JSON object per line).
    pub async fn write_batch(&self, events: &[CollectedEvent]) -> anyhow::Result<()> {
        if events.is_empty() { return Ok(()); }

        // Use std::path::PathBuf � works on Linux and Windows
        tokio::fs::create_dir_all(&self.dir).await?;
        let path = self.current_path();

        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await?;
        let mut writer = tokio::io::BufWriter::new(file);

        for event in events {
            let line = serde_json::to_string(event)?;
            writer.write_all(line.as_bytes()).await?;
            writer.write_all(b"\n").await?;
        }
        writer.flush().await?;

        debug!(
            tenant = %self.tenant,
            path   = %path.display(),
            count  = events.len(),
            "Events written"
        );
        Ok(())
    }
}
