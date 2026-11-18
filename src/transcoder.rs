use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mc_core::{CoreError, Result};
use mc_proto::transcoder::transcoder_client::TranscoderClient as GrpcTranscoderClient;
use mc_proto::transcoder::{TranscodeChunk, TranscodeRequest};
use tonic::transport::{Channel, Endpoint};
use tonic::Streaming;

const AVAILABILITY_TTL: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_millis(750);

#[derive(Clone, Debug)]
pub struct TranscoderClient {
    endpoint: String,
    availability: Arc<Mutex<Option<(Instant, bool)>>>,
    channel: Arc<tokio::sync::Mutex<Option<Channel>>>,
}

impl TranscoderClient {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            availability: Arc::new(Mutex::new(None)),
            channel: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    pub async fn is_available(&self) -> bool {
        if let Ok(cache) = self.availability.lock() {
            if let Some((checked_at, available)) = *cache {
                if checked_at.elapsed() < AVAILABILITY_TTL {
                    return available;
                }
            }
        }

        let available = self.check_health().await;

        if let Ok(mut cache) = self.availability.lock() {
            *cache = Some((Instant::now(), available));
        }

        available
    }

    pub async fn transcode(
        &self,
        source_key: &str,
        source_path: Option<&str>,
        format: &str,
        bitrate_kbps: u32,
    ) -> Result<Streaming<TranscodeChunk>> {
        let channel = self.channel().await?;
        let mut client = GrpcTranscoderClient::new(channel);
        let response = client
            .transcode(TranscodeRequest {
                source_key: source_key.to_owned(),
                format: format.to_owned(),
                bitrate_kbps,
                source_path: source_path.unwrap_or_default().to_owned(),
                cleanup_source: source_path.is_some(),
            })
            .await;
        let response = match response {
            Ok(response) => response,
            Err(status) => {
                self.reset().await;
                return Err(CoreError::Unavailable(format!("transcoder: {status}")));
            }
        };

        Ok(response.into_inner())
    }

    async fn check_health(&self) -> bool {
        let Ok(channel) = self.channel().await else {
            return false;
        };

        let mut client = tonic_health::pb::health_client::HealthClient::new(channel);
        let request = tonic_health::pb::HealthCheckRequest {
            service: String::new(),
        };

        match tokio::time::timeout(CONNECT_TIMEOUT, client.check(request)).await {
            Ok(Ok(response)) => {
                let serving = response.into_inner().status
                    == tonic_health::pb::health_check_response::ServingStatus::Serving as i32;
                if !serving {
                    self.reset().await;
                }
                serving
            }
            _ => {
                self.reset().await;
                false
            }
        }
    }

    async fn channel(&self) -> Result<Channel> {
        let mut cached = self.channel.lock().await;
        if let Some(channel) = cached.as_ref() {
            return Ok(channel.clone());
        }

        let channel = self.connect().await?;
        *cached = Some(channel.clone());
        Ok(channel)
    }

    async fn reset(&self) {
        *self.channel.lock().await = None;
    }

    async fn connect(&self) -> Result<Channel> {
        let endpoint = Endpoint::from_shared(self.endpoint.clone())
            .map_err(|error| CoreError::Validation(format!("invalid transcoder URL: {error}")))?
            .connect_timeout(CONNECT_TIMEOUT);

        match tokio::time::timeout(CONNECT_TIMEOUT, endpoint.connect()).await {
            Ok(Ok(channel)) => Ok(channel),
            Ok(Err(error)) => Err(CoreError::Unavailable(format!("transcoder: {error}"))),
            Err(_) => Err(CoreError::Unavailable(
                "transcoder: connect timeout".to_owned(),
            )),
        }
    }
}
