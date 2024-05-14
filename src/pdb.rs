use pdb_addr2line::pdb;
use regex::Regex;
use std::collections::HashMap;
use std::fs::File;
use std::path::Path;
use thiserror::Error;

use crate::comparer_config::FunctionDefinition;

pub const PDB_SEGMENT_OFFSET: u64 = 0x0040_0C00;

#[derive(Error, Debug)]
pub enum PdbError {
  #[error("failed to find or open PDB file")]
  IoError(#[from] std::io::Error),

  #[error("failed to parse PDB data")]
  Addr2LineError(#[from] pdb_addr2line::Error),

  #[error("failed to parse PDB data")]
  PdbError(#[from] pdb_addr2line::pdb::Error),
}

#[derive(Debug)]
pub struct FunctionSymbol {
  pub name: String,
  pub offset: u64,
  pub size: usize,
}

impl FunctionSymbol {
  pub fn as_function_definition(&self) -> FunctionDefinition {
    FunctionDefinition {
      addr: self.offset + PDB_SEGMENT_OFFSET,
      name: self.name.clone(),
      size: Some(self.size),
    }
  }

  pub fn as_function_definition_pair(&self) -> (u64, FunctionDefinition) {
    let func = self.as_function_definition();
    (func.addr, func)
  }
}

fn to_function_symbol(data: pdb_addr2line::Function) -> FunctionSymbol {
  return FunctionSymbol {
    name: data.name.unwrap(),
    offset: (data.start_rva - 0xC00) as u64,
    size: (data.end_rva.unwrap_or(data.start_rva) - data.start_rva) as usize,
  };
}

fn demangle_function_name(name: String) -> String {
  return Regex::new(r"[^@(]+")
    .iter()
    .flat_map(|re| re.find(&name))
    .map(|found| found.as_str())
    .collect();
}

pub fn get_pdb_funcs(file: impl AsRef<Path>) -> Result<HashMap<String, FunctionSymbol>, PdbError> {
  let file = File::open(file)?;
  let pdb = pdb::PDB::open(file)?;

  let context_data = pdb_addr2line::ContextPdbData::try_from_pdb(pdb)?;
  let context = context_data.make_context()?;

  let mut ret = HashMap::new();
  for function in context.functions() {
    let fun = to_function_symbol(function);
    let name = demangle_function_name(fun.name.clone());
    ret.insert(name, fun);
  }

  Ok(ret)
}
