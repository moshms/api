use anyhow::{bail, Context};
use figment::providers::{Env, Serialized};
use figment::Figment;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub bind_addr: String,
    pub database_url: String,
    pub database_max_connections: u32,
    pub log_json: bool,
    pub log_filter: String,
    pub metrics: bool,
    pub admin_user: Option<String>,
    pub admin_password: Option<String>,
    pub setup_token: Option<String>,
    pub session_ttl_hours: i64,
    pub cookie_secure: bool,
    pub library_path: String,
    pub library_name: String,
    pub library_access: String,
    pub local_storage_roots: String,
    pub scan_on_start: bool,
    pub transcoder_url: Option<String>,
    pub master_key: Option<String>,
    pub staging_path: String,
    pub max_upload_bytes: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:8080".to_owned(),
            database_url: String::new(),
            database_max_connections: 10,
            log_json: true,
            log_filter: "info".to_owned(),
            metrics: false,
            admin_user: None,
            admin_password: None,
            setup_token: None,
            session_ttl_hours: 720,
            cookie_secure: false,
            library_path: "/library".to_owned(),
            library_name: "Music".to_owned(),
            library_access: "closed".to_owned(),
            local_storage_roots: "/library".to_owned(),
            scan_on_start: false,
            transcoder_url: None,
            master_key: None,
            staging_path: "/staging".to_owned(),
            max_upload_bytes: 4 * 1024 * 1024 * 1024,
        }
    }
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let config: Self = Figment::from(Serialized::defaults(Self::default()))
            .merge(Env::prefixed("MC_"))
            .extract()
            .context("read configuration from environment")?;

        if config.database_url.trim().is_empty() {
            bail!("MC_DATABASE_URL is required");
        }

        if !matches!(config.library_access.as_str(), "closed" | "everyone") {
            bail!("MC_LIBRARY_ACCESS must be closed or everyone");
        }

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::Config;

    #[test]
    fn defaults_are_sane() {
        let config = Config::default();
        assert_eq!(config.bind_addr, "0.0.0.0:8080");
        assert_eq!(config.database_max_connections, 10);
        assert!(config.log_json);
        assert!(!config.metrics);
        assert_eq!(config.library_path, "/library");
        assert_eq!(config.library_name, "Music");
        assert_eq!(config.library_access, "closed");
        assert_eq!(config.local_storage_roots, "/library");
        assert_eq!(config.session_ttl_hours, 720);
        assert!(!config.cookie_secure);
    }
}
