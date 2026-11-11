use std::path::PathBuf;
use std::sync::Arc;

use mc_crypto::MasterKey;
use mc_db::PgPool;
use mc_scanner::Scanner;

use crate::transcoder::TranscoderClient;
use mc_runtime::StorageRegistry;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub scanner: Arc<Scanner>,
    pub registry: Arc<tokio::sync::RwLock<StorageRegistry>>,
    pub master_key: Option<MasterKey>,
    pub session_ttl_hours: i64,
    pub cookie_secure: bool,
    pub scan_lock: Arc<tokio::sync::Mutex<()>>,
    pub transcoder: Option<TranscoderClient>,
    pub metrics: Option<mc_telemetry::PrometheusHandle>,
    pub staging_path: PathBuf,
    pub max_upload_bytes: u64,
    pub upload_lock: Arc<tokio::sync::Mutex<()>>,
}
