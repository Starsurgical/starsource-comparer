use std::{collections::HashMap, path::PathBuf};

use handlebars::Handlebars;
use itertools::Itertools;

use self::GenerateReportError::*;
use super::assets::*;
use super::comparer_config::*;
use super::pdb::*;

#[derive(Debug)]
pub struct GenerateReportCommandInfo {
  pub report_opts: GenerateReportOpts,
  pub disasm_opts: super::DisasmOpts,
  pub truncate_to_original: bool,
}

#[derive(Debug)]
pub struct GenerateReportOpts {
  pub orig: PathBuf,
  pub compare_file_path: PathBuf,
  pub compare_pdb_file: PathBuf,
}

#[derive(Debug)]
pub enum GenerateReportError {
  PdbError(super::pdb::PdbError),
  ConfigSymbolNotFound,
  SymbolNotFound,
  IoError(std::io::Error),
  DisasmError(super::disasm::DisasmError),
  RequiredFunctionSizeNotFoundError(String),
  TemplateError(handlebars::TemplateError),
}

pub fn print_error(e: &GenerateReportError) {
  match e {
    PdbError(e) => println!("PDB file error: {:#?}", e),
    ConfigSymbolNotFound => println!("Could not find the specified symbol in the config."),
    SymbolNotFound => println!("Could not find the symbol in the PDB, skipping the file."),
    IoError(e) => println!("IO error: {:#?}", e),
    DisasmError(e) => println!("Zydis disassembly engine error: {:#?}", e),
    RequiredFunctionSizeNotFoundError(e) => println!(
      "No size defined for the original function '{}', but truncate_to_original was specified.",
      e
    ),
    TemplateError(e) => println!("Failed to load web template. {}", e),
  }
}

#[derive(Debug, Clone)]
pub struct DualFunctionReport {
  pub name: String,
  pub file: String,
  pub new_addr: Option<u64>,
  pub new_size: Option<usize>,
  pub new_asm: String,
  pub orig_addr: Option<u64>,
  pub orig_size: Option<usize>,
  pub orig_asm: String,
  pub unified_diff: String,
  pub match_ratio: f64,
}

fn register_template(name: &str, handlebars: &mut Handlebars) -> Result<(), GenerateReportError> {
  handlebars.register_template_string(name, load_asset_text_file(format!("{name}.hbs")));
  Ok(())
}

pub fn run(info: &GenerateReportCommandInfo, cfg: &ComparerConfig) -> Result<(), GenerateReportError> {
  let mut handlebars = Handlebars::new();
  handlebars.set_strict_mode(true);

  register_template("cov_overview", &mut handlebars);
  register_template("index_partial", &mut handlebars);
  register_template("compare_partial", &mut handlebars);
  register_template("webpage", &mut handlebars);

  let report_data = create_report_data(info, cfg)?;

  Ok(())
}

fn get_orig_funcs(cfg: &ComparerConfig) -> HashMap<String, FunctionDefinition> {
  cfg.func
  .iter()
  .map(|func| (func.name.clone(), func.clone()))
  .collect()
}

fn create_report_data(info: &GenerateReportCommandInfo, cfg: &ComparerConfig) -> Result<Vec<DualFunctionReport>, GenerateReportError> {
  let orig_fn_map = get_orig_funcs(cfg);
  let pdb_funcs: HashMap<String, FunctionSymbol> = get_pdb_funcs(&info.report_opts.compare_pdb_file).map_err(PdbError)?;

  Ok(orig_fn_map.keys().chain(pdb_funcs.keys())
  .unique()
  .map(|fn_name|{
    let orig = orig_fn_map.get(fn_name);
    let pdb = pdb_funcs.get(fn_name);

    let (orig_asm, new_asm, unified_diff, match_ratio) = create_comparison_data();

    DualFunctionReport {
      name: fn_name.clone(),
      file: pdb.map_or(String::from(""), |f| f.file.clone()),
      new_addr: pdb.map(|f| f.offset),
      new_size: pdb.map(|f| f.size),
      new_asm: new_asm,
      orig_addr: orig.map(|f| f.addr),
      orig_size: orig.map(|f| f.size).flatten(),
      orig_asm: orig_asm,
      unified_diff: unified_diff,
      match_ratio: match_ratio,
    }
  }).collect())
}

fn create_comparison_data(fn_name: String, orig_fns: &HashMap<String, FunctionDefinition>, pdb_fns: &HashMap<String, FunctionSymbol>) -> (String, String, String, f64) {


  (String::from(""), String::from(""), String::from(""), 0f64)
}
