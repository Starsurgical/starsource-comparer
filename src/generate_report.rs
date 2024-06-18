use std::path::Path;
use std::{collections::HashMap, path::PathBuf};

use common_path::common_path_all;
use handlebars::Handlebars;
use itertools::Itertools;
use similar::Change;
use similar::TextDiff;

use super::compare::get_pdb_fn_map;

use self::GenerateReportError::*;
use super::assets::*;
use super::comparer_config::*;
use super::disasm::*;
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
  IoError(std::io::Error),
  DisasmError(super::disasm::DisasmError),
  RequiredFunctionSizeNotFoundError(String),
  TemplateError(handlebars::TemplateError),
  FromUtf8Error(std::string::FromUtf8Error),
}

pub fn print_error(e: &GenerateReportError) {
  match e {
    PdbError(e) => println!("PDB file error: {:#?}", e),
    IoError(e) => println!("IO error: {:#?}", e),
    DisasmError(e) => println!("Zydis disassembly engine error: {:#?}", e),
    RequiredFunctionSizeNotFoundError(e) => println!(
      "No size defined for the original function '{}', but truncate_to_original was specified.",
      e
    ),
    TemplateError(e) => println!("Failed to load web template. {}", e),
    FromUtf8Error(e) => println!("Failed to convert disassembly to UTF-8 string. {}", e),
  }
}

#[derive(Debug, Clone)]
struct CompareResult {
  pub orig_asm: String,
  pub new_asm: String,
  pub unified_diff: String,
  pub match_ratio: f32,
  pub diff_html: String,
}

#[derive(Debug, Clone)]
struct DualFunctionReport {
  pub name: String,
  pub file: String,
  pub new_addr: Option<u64>,
  pub new_size: Option<usize>,
  pub orig_addr: Option<u64>,
  pub orig_size: Option<usize>,
  pub compare_result: Option<CompareResult>,
}

struct PathReport {
  pub path: String,
  pub match_ratio: f32,
  pub nodes: Vec<ReportNode>,
}

enum ReportNode {
  Function(DualFunctionReport),
  Path(PathReport),
}

struct OrigData {
  functions: HashMap<String, FunctionDefinition>,
  fn_map: HashMap<u64, FunctionDefinition>,
  file: Vec<u8>,
  base_address: u64,
}

struct PdbData {
  functions: HashMap<String, FunctionSymbol>,
  fn_map: HashMap<u64, FunctionDefinition>,
  file: Vec<u8>,
}

fn register_template(name: &str, handlebars: &mut Handlebars) -> Result<(), GenerateReportError> {
  handlebars.register_template_string(name, load_asset_text_file(format!("{name}.hbs"))).map_err(TemplateError)?;
  Ok(())
}

pub fn run(info: &GenerateReportCommandInfo, cfg: &ComparerConfig) -> Result<(), GenerateReportError> {
  let mut handlebars = Handlebars::new();
  handlebars.set_strict_mode(true);

  register_template("cov_overview", &mut handlebars)?;
  register_template("index_partial", &mut handlebars)?;
  register_template("compare_partial", &mut handlebars)?;
  register_template("webpage", &mut handlebars)?;

  let report_data = create_report_data(info, cfg)?;

  // TODO

  Ok(())
}

fn structure_report_data(fns: &Vec<DualFunctionReport>) {
  let common_path = common_path_all(fns.iter().map(|f|Path::new(&f.file))).unwrap_or_default();

  // TODO think about implementation
  // 1. group by path, removing the common path
  // 2. convert to ReportNode for tree structure, iterating the Path pieces (recursive calls?)
}

fn get_orig_funcs(cfg: &ComparerConfig) -> HashMap<String, FunctionDefinition> {
  cfg.func
  .iter()
  .map(|func| (func.name.clone(), func.clone()))
  .collect()
}

fn create_report_data(info: &GenerateReportCommandInfo, cfg: &ComparerConfig) -> Result<Vec<DualFunctionReport>, GenerateReportError> {
  let orig_functions = get_orig_funcs(cfg);
  let orig_fn_map = orig_functions.values().map(|f| (f.addr, f.clone())).collect::<HashMap<_,_>>();
  
  let pdb_functions = get_pdb_funcs(&info.report_opts.compare_pdb_file).map_err(PdbError)?;
  let pdb_fn_map = get_pdb_fn_map(&pdb_functions);

  let orig = OrigData {
    functions: orig_functions,
    fn_map: orig_fn_map,
    file: std::fs::read(&info.report_opts.orig).map_err(IoError)?,
    base_address: cfg.address_offset,
  };

  let pdb = PdbData {
    functions: pdb_functions,
    fn_map: pdb_fn_map,
    file: std::fs::read(&info.report_opts.compare_file_path).map_err(IoError)?,
  };

  Ok(orig.functions.keys().chain(pdb.functions.keys())
  .unique()
  .map(|fn_name|{
    let orig_fn = orig.functions.get(fn_name);
    let pdb_fn = pdb.functions.get(fn_name);

    let compare_result = create_comparison_data(fn_name, &orig, &pdb, &info)
    .inspect_err(print_error)
    .ok();

    DualFunctionReport {
      name: fn_name.clone(),
      file: pdb_fn.map_or(String::from(""), |f| f.file.clone()),
      new_addr: pdb_fn.map(|f| f.offset),
      new_size: pdb_fn.map(|f| f.size),
      orig_addr: orig_fn.map(|f| f.addr),
      orig_size: orig_fn.map(|f| f.size).flatten(),
      compare_result: compare_result,
    }
  }).collect())
}

fn create_change_line_html(change: Change<&str>) -> String {
  match change.tag() {
    similar::ChangeTag::Equal => format!(r#"<tr><td>{change}</td><td>{change}</td></tr>"#),
    similar::ChangeTag::Delete => format!(r#"<tr><td class="code-delete">{change}</td><td></td></tr>"#),
    similar::ChangeTag::Insert => format!(r#"<tr><td></td><td class="code-insert">{change}</td></tr>"#),
  }
}

fn create_comparison_data(fn_name: &String, orig: &OrigData, pdb: &PdbData, info: &GenerateReportCommandInfo) -> Result<CompareResult, GenerateReportError> {
  let orig_fn = orig.functions.get(fn_name);
  let pdb_fn = pdb.functions.get(fn_name);

  let orig_fn_asm = match orig_fn {
    Some(f) => {
      let offset = (f.addr - orig.base_address) as usize;
      let virt_addr = f.addr;
      
      let orig_fn_size = f.size
      .or(pdb_fn.map(|f|f.size))
      .ok_or(RequiredFunctionSizeNotFoundError(String::from("No function size provided")))?;

      let mut buf = Vec::new();
      write_disasm(&mut buf, &orig.file[offset..offset+orig_fn_size], &info.disasm_opts, virt_addr, &orig.fn_map).map_err(DisasmError)?;
      String::from_utf8(buf).map_err(FromUtf8Error)?
    }
    None => String::from("")
  };

  let pdb_fn_asm = match pdb_fn {
    Some(f) => {
      let offset = f.offset as usize;
      let virt_addr = f.offset + PDB_SEGMENT_OFFSET;

      let mut buf = Vec::new();
      write_disasm(&mut buf, &pdb.file[offset..offset+f.size], &info.disasm_opts, virt_addr, &pdb.fn_map).map_err(DisasmError)?;
      String::from_utf8(buf).map_err(FromUtf8Error)?
    }
    None => String::from("")
  };

  let patch = TextDiff::from_lines(&orig_fn_asm, &pdb_fn_asm);

  Ok(CompareResult {
    orig_asm: orig_fn_asm.clone(),
    new_asm: pdb_fn_asm.clone(),
    unified_diff: patch.unified_diff().to_string(),
    match_ratio: patch.ratio(),
    diff_html: patch.iter_all_changes().map(create_change_line_html).join("\n"),
  })
}
