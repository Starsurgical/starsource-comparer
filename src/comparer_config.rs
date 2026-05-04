use std::path::Path;

use serde::Deserialize;
use thiserror::Error;

const COMPARER_CONFIG_FILE: &str = "comparer-config.toml";

#[derive(Debug, Deserialize)]
pub struct ComparerConfig {
  pub address_offset: u64,
  pub func: Vec<FunctionDefinition>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct FunctionDefinition {
  pub name: String,
  pub addr: u64,
  pub size: Option<usize>,
}

#[derive(Debug, Error)]
pub enum ComparerConfigError {
  #[error("Failed to read config file: {0}")]
  Io(#[from] std::io::Error),

  #[error("Failed to parse config file: {0}")]
  Parse(#[from] toml::de::Error),
}

impl ComparerConfig {
  fn read_from_file(path: impl AsRef<Path>) -> Result<Self, ComparerConfigError> {
    let raw = std::fs::read_to_string(path)?;
    let config = toml::from_str(&raw)?;
    Ok(config)
  }

  pub fn read_default() -> Result<Self, ComparerConfigError> {
    let path = std::env::current_exe()?.with_file_name(COMPARER_CONFIG_FILE);
    Self::read_from_file(path)
  }
}
