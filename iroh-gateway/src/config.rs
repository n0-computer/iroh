use std::collections::HashMap;

use axum::http::header::*;

pub const DEFAULT_PORT: u16 = 9050;

#[derive(Debug, Clone)]
pub struct Config {
    /// flag to toggle whether the gateway allows writing/pushing data
    pub writeable: bool,
    /// flag to toggle whether the gateway allows fetching data from other nodes or is local only
    pub fetch: bool,
    /// flag to toggle whether the gateway enables/utilizes caching
    pub cache: bool,
    /// set of user provided headers to attach to all responses
    pub headers: HashMap<String, String>, //todo(arqu): convert to use axum::http::header
    /// default port to listen on
    pub port: u16,
}

impl Config {
    pub fn new(writeable: bool, fetch: bool, cache: bool, port: u16) -> Self {
        Self {
            writeable,
            fetch,
            cache,
            headers: HashMap::new(),
            port,
        }
    }

    pub fn set_default_headers(&mut self) {
        let mut headers = HashMap::new();
        headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN.to_string(), "*".to_string());
        headers.insert(ACCESS_CONTROL_ALLOW_HEADERS.to_string(), "*".to_string());
        headers.insert(ACCESS_CONTROL_ALLOW_METHODS.to_string(), "*".to_string());
        headers.insert(
            CACHE_CONTROL.to_string(),
            "no-cache, no-transform".to_string(),
        );
        headers.insert(ACCEPT_RANGES.to_string(), "none".to_string());
        self.headers = headers;
    }
}

impl Default for Config {
    fn default() -> Self {
        let mut t = Self {
            writeable: false,
            fetch: false,
            cache: false,
            headers: HashMap::new(),
            port: DEFAULT_PORT,
        };
        t.set_default_headers();
        t
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_headers() {
        let mut config = Config::new(false, false, false, 9050);
        config.set_default_headers();
        assert_eq!(config.headers.len(), 5);
        assert_eq!(
            config.headers.get(&ACCESS_CONTROL_ALLOW_ORIGIN.to_string()),
            Some(&"*".to_string())
        );
    }

    #[test]
    fn default_config() {
        let config = Config::default();
        assert!(!config.writeable);
        assert!(!config.fetch);
        assert!(!config.cache);
        assert_eq!(config.port, DEFAULT_PORT);
    }
}
