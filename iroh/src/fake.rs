use std::path::PathBuf;
use anyhow::Result;
use serde::{Serialize, Deserialize};
use chrono::Utc;
use serde_json;

use crate::config::iroh_config_path;

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct FakeDB {
    pub apps: Vec<Network>,
    pub docs: Vec<Space>,
    pub contacts: Vec<String>,
    pub keys: Vec<String>,
    pub tokens: Vec<Token>
}

impl FakeDB {
    pub fn new() -> Self {
        FakeDB{
            apps: vec![Network::default()],
            docs: vec![],
            contacts: vec![],
            keys: vec![],
            tokens: vec![],
        }
    }

    pub fn default_path() -> Result<PathBuf> {
        iroh_config_path("fake_db.json")
    }

    pub fn load_or_create(path: &PathBuf) -> Result<Self> {
        if path.exists() {
            let docs = Self::load(path)?;
            Ok(docs)
        } else {
            let docs = Self::new();
            docs.save(path)?;
            Ok(docs)
        }
    }

    fn load(path: &PathBuf) -> Result<Self> {
        let docs = std::fs::read_to_string(path)?;
        let docs: FakeDB = serde_json::from_str(&docs)?;
        Ok(docs)
    }

    pub fn save(&self, path: &PathBuf) -> Result<()> {
        let docs = serde_json::to_string_pretty(self)?;
        std::fs::write(path, docs)?;
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Space {
    pub network: String,
    pub label: String,
    pub id: String,
    pub private_key: String,
    pub created_at: chrono::DateTime<Utc>,
    pub updated_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Network {
    pub is_default: bool,
    pub name: String,
    pub id: String,
}

impl Default for Network {
    fn default() -> Self {
        Network{
            is_default: true,
            name: "default.iroh.network".to_string(),
            id: "netWoRkPubLiCKeY".to_string(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Contact {
    name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Token {
    id: String,
    space_id: String,
    created_at: chrono::DateTime<Utc>,
    expires_at: chrono::DateTime<Utc>,
    revoked_at: Option<chrono::DateTime<Utc>>,
}

/// SpaceRef is either a space label or a space id, cannot contain any path suffix
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SpaceRef(String);

impl From<String> for SpaceRef {
    fn from(s: String) -> Self {
        SpaceRef(s)
    }
}

impl std::fmt::Display for SpaceRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f,"{}", self.0)
    }
}

impl SpaceRef {
  pub fn as_string(self) -> String {
    self.0
  }
}

/// SpacePath is a SpaceRef + an optional suffix path (e.g. /foo/bar)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SpacePath(String);

impl From<String> for SpacePath {
  fn from(s: String) -> Self {
    SpacePath(s)
  }
}

impl std::fmt::Display for SpacePath {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
      write!(f,"{}", self.0)
  }
}

impl SpacePath {
  pub fn as_string(self) -> String {
    self.0
  }
}