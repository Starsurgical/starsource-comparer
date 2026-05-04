use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;

use thiserror::Error;

use self::GenerateFullCommandError::*;
use super::comparer_config::*;
use super::disasm::*;
use super::pdb::*;

#[derive(Debug)]
pub struct GenerateFullCommandInfo {
  pub file_path: PathBuf,
  pub orig_file: bool,
  pub disasm_opts: super::DisasmOpts,
  pub truncate_to_original: bool,
}

#[derive(Debug, Error)]
pub enum GenerateFullCommandError {
  #[error("PDB file error: {0:#?}")]
  Pdb(#[from] super::pdb::PdbError),

  #[error("IO error: {0}")]
  Io(#[from] std::io::Error),

  #[error("Zydis disassembly error: {0:#?}")]
  Disasm(#[from] super::disasm::DisasmError),

  #[error("Error: The function offset/size of {0} are outside of the bounds of the input file.")]
  FunctionDefSizeWrong(String),
}

pub fn run(info: GenerateFullCommandInfo, cfg: &ComparerConfig) -> Result<(), GenerateFullCommandError> {
  if info.orig_file {
    generate_full_orig(info, cfg)
  } else {
    generate_full_pdb(info, cfg)
  }
}

fn generate_full_orig(info: GenerateFullCommandInfo, cfg: &ComparerConfig) -> Result<(), GenerateFullCommandError> {
  let mut path = std::env::current_dir()?;
  path.push("orig_full.asm");

  let bytes = std::fs::read(&info.file_path)?;

  let stdout = std::io::stdout();
  let mut stdout_lock = stdout.lock();

  let orig_fn_map = cfg
    .func
    .iter()
    .map(|func| (func.addr, func.clone()))
    .collect::<HashMap<_, _>>();

  let mut writer = File::create(path).map(BufWriter::new)?;

  for func in &cfg.func {
    let size = match func.size {
      None => {
        writeln!(
          stdout_lock,
          "Note: Skipping '{}' because no size was defined.",
          func.name
        )?;
        continue;
      }
      Some(size) => size,
    };

    write_function_head(&mut writer, size, func.name.as_ref())?;

    let offset = (func.addr - cfg.address_offset) as usize;
    let offset_end = offset + size;

    let func_bytes = bytes
      .get(offset..offset_end)
      .ok_or_else(|| FunctionDefSizeWrong(func.name.clone()))?;

    write_disasm(&mut writer, func_bytes, &info.disasm_opts, func.addr, &orig_fn_map)?;
  }

  Ok(())
}

fn generate_full_pdb(info: GenerateFullCommandInfo, cfg: &ComparerConfig) -> Result<(), GenerateFullCommandError> {
  let mut pdb_path = info.file_path.clone();
  pdb_path.set_extension("pdb");

  let mut pdb_funcs: HashMap<String, FunctionSymbol> = get_pdb_funcs(pdb_path)?;
  let pdb_fn_map = pdb_funcs
    .values()
    .map(|func| func.as_function_definition_pair())
    .collect::<HashMap<_, _>>();

  let mut path = std::env::current_dir()?;
  path.push("compare_full.asm");

  // println!("{}", path.to_str().unwrap());

  let bytes = std::fs::read(&info.file_path)?;

  let stdout = std::io::stdout();
  let mut stdout_lock = stdout.lock();

  let mut writer = File::create(path).map(BufWriter::new)?;

  for func in &cfg.func {
    if let Some(pdb_func) = pdb_funcs.remove::<str>(&func.name) {
      write_function_head(&mut writer, pdb_func.size, &func.name)?;

      let offset = pdb_func.offset as usize;
      let size = if info.truncate_to_original {
        if let Some(size) = func.size {
          size
        } else {
          println!(
            "WARN: No size defined for the original function '{}', using the PDB function size instead.",
            func.name
          );
          pdb_func.size
        }
      } else {
        pdb_func.size
      };
      let offset_end = offset + size;

      let func_bytes = bytes
        .get(offset..offset_end)
        .ok_or_else(|| FunctionDefSizeWrong(func.name.clone()))?;

      write_disasm(
        &mut writer,
        func_bytes,
        &info.disasm_opts,
        pdb_func.offset + PDB_SEGMENT_OFFSET,
        &pdb_fn_map,
      )?;
    } else {
      writeln!(stdout_lock, "WARN: Function '{}' was not found in the PDB.", func.name)?;
    }
  }
  for func in pdb_funcs {
    writeln!(
      stdout_lock,
      "WARN: Function '{}' was not found in the config.",
      func.1.name
    )?;
  }
  writer.flush()?;

  Ok(())
}

fn write_function_head(writer: &mut impl Write, size: usize, name: &str) -> Result<(), GenerateFullCommandError> {
  // (blank line)
  // ;
  // ; <function>
  // ; size: 0xDEADBEEF
  // ;
  // (blank line)
  writeln!(writer, "\n;\n; {}\n; size: {:#X}\n;\n", name, size)?;
  Ok(())
}
