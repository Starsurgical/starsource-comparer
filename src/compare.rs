use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::mpsc::channel;
use std::time::Duration;

use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};

use self::CompareError::*;
use super::comparer_config::*;
use super::disasm::*;
use super::pdb::*;
use super::CustomUpperHexFormat;

#[derive(Debug)]
pub struct CompareCommandInfo {
  pub compare_opts: CompareOpts,
  pub disasm_opts: super::DisasmOpts,
  pub last_offset_size: Option<(u64, usize)>,
  pub enable_watcher: bool,
  pub truncate_to_original: bool,
}

#[derive(Debug)]
pub struct CompareOpts {
  pub orig: PathBuf,
  pub compare_file_path: PathBuf,
  pub compare_pdb_file: PathBuf,
  pub debug_symbol: String,
}

#[derive(Debug)]
pub enum CompareError {
  PdbError(super::pdb::PdbError),
  ConfigSymbolNotFound,
  SymbolNotFound,
  IoError(std::io::Error),
  DisasmError(super::disasm::DisasmError),
  NotifyError(notify::Error),
  RequiredFunctionSizeNotFoundError(String),
}

pub fn print_error(e: &CompareError) {
  match e {
    PdbError(e) => println!("PDB file error: {:#?}", e),
    ConfigSymbolNotFound => println!("Could not find the specified symbol in the config."),
    SymbolNotFound => println!("Could not find the symbol in the PDB, skipping the file."),
    IoError(e) => println!("IO error: {:#?}", e),
    DisasmError(e) => println!("Zydis disassembly engine error: {:#?}", e),
    NotifyError(e) => println!("Watcher error: {:#?}", e),
    RequiredFunctionSizeNotFoundError(e) => println!(
      "No size defined for the original function '{}', but truncate_to_original was specified.",
      e
    ),
  }
}

pub fn run(mut info: CompareCommandInfo, cfg: &ComparerConfig) -> Result<(), CompareError> {
  let orig_fn_map = cfg
    .func
    .iter()
    .map(|func| (func.addr, func.clone()))
    .collect::<HashMap<_, _>>();
  let orig_fn = cfg
    .func
    .iter()
    .find(|s| s.name == info.compare_opts.debug_symbol)
    .ok_or(ConfigSymbolNotFound)?;

  if orig_fn.size.is_none() {
    if info.truncate_to_original {
      return Err(RequiredFunctionSizeNotFoundError(orig_fn.name.clone()));
    } else {
      println!("WARN: No size defined for the original function, using the PDB function size instead.");
    }
  }

  // initial run
  run_disassemble(&mut info, cfg.address_offset, orig_fn, &orig_fn_map)?;

  if !info.enable_watcher {
    return Ok(());
  }

  let (tx, rx) = channel();

  let mut watcher: RecommendedWatcher =
    Watcher::new(tx, Config::default().with_poll_interval(Duration::from_secs(2))).map_err(NotifyError)?;

  watcher
    .watch(&info.compare_opts.compare_pdb_file, RecursiveMode::NonRecursive)
    .map_err(NotifyError)?;

  println!(
    "Started watching {} for changes. CTRL+C to quit.",
    info.compare_opts.compare_pdb_file.to_string_lossy()
  );

  loop {
    match rx.recv() {
      Ok(Ok(evt)) => match evt.kind {
        EventKind::Create(_) | EventKind::Modify(_) => {
          if let Err(e) = run_disassemble(&mut info, cfg.address_offset, orig_fn, &orig_fn_map) {
            print_error(&e);
          }
        }
        _ => {}
      },
      Err(e) => {
        println!("Watcher error: {:#?}", e);
        std::process::exit(1);
      }
      Ok(Err(e)) => {
        println!("Watcher error: {:#?}", e);
        std::process::exit(1);
      }
    }
  }
}

fn run_disassemble(
  info: &mut CompareCommandInfo,
  orig_addr_offset: u64,
  orig_fn: &FunctionDefinition,
  orig_fn_map: &HashMap<u64, FunctionDefinition>,
) -> Result<(), CompareError> {
  match write_compare(info, orig_addr_offset, orig_fn, orig_fn_map) {
    Ok(FunctionSymbol { file, offset, size, .. }) => {
      if let Some((old_addr, old_size)) = info.last_offset_size {
        print!(
          "Found {} in {} at {:#X} ({:+#X}), size: {:#X} ({:+#X})",
          &info.compare_opts.debug_symbol,
          file,
          offset,
          CustomUpperHexFormat((offset as i64) - (old_addr as i64)),
          size,
          CustomUpperHexFormat((size as i64) - (old_size as i64)),
        );
      } else {
        print!(
          "Found {} in {} at {:#X}, size: {:#X}",
          &info.compare_opts.debug_symbol, file, offset, size,
        );
      }

      if let Some(orig_size) = orig_fn.size {
        print!("; orig size: {:#X}", orig_size);
      }
      println!();

      info.last_offset_size = Some((offset, size));
      Ok(())
    }
    Err(e) => Err(e),
  }
}

fn write_compare(
  info: &mut CompareCommandInfo,
  orig_addr_offset: u64,
  orig_fn: &FunctionDefinition,
  orig_fn_map: &HashMap<u64, FunctionDefinition>,
) -> Result<FunctionSymbol, CompareError> {
  let pdb_funcs = get_pdb_funcs(&info.compare_opts.compare_pdb_file).map_err(PdbError)?;
  let fn_sym = pdb_funcs.get(&info.compare_opts.debug_symbol).ok_or(SymbolNotFound)?;
  let pdb_fn_map = get_pdb_fn_map(&info.compare_opts.compare_file_path, &pdb_funcs);

  let mut orig_function_bytes = if let Some(orig_size) = orig_fn.size {
    vec![0; orig_size]
  } else {
    vec![0; fn_sym.size]
  };

  let mut compare_function_bytes = if info.truncate_to_original {
    vec![
      0;
      orig_fn
        .size
        .expect("orig size is None even though truncate_to_original is set. Initial check was wrong!")
    ]
  } else {
    vec![0; fn_sym.size]
  };

  let orig_offset = orig_fn.addr - orig_addr_offset;

  read_file_into(&mut orig_function_bytes, &info.compare_opts.orig, orig_offset)?;
  read_file_into(
    &mut compare_function_bytes,
    &info.compare_opts.compare_file_path,
    fn_sym.offset,
  )?;

  write_disassembly("orig.asm", &orig_function_bytes, info, orig_fn.addr, orig_fn_map)?;

  let addr = fn_sym.offset + PDB_SEGMENT_OFFSET;
  write_disassembly("compare.asm", &compare_function_bytes, info, addr, &pdb_fn_map)?;

  Ok(fn_sym.clone())
}

pub fn get_pdb_fn_map(
  _path: impl AsRef<Path>,
  pdb_funcs: &HashMap<String, FunctionSymbol>,
) -> HashMap<u64, FunctionDefinition> {
  pdb_funcs
    .values()
    .map(|func| func.as_function_definition_pair())
    .collect::<HashMap<_, _>>()
}

fn write_disassembly(
  filename: &str,
  function_bytes: &[u8],
  info: &mut CompareCommandInfo,
  addr: u64,
  fn_map: &HashMap<u64, FunctionDefinition>,
) -> Result<(), CompareError> {
  let mut path = std::env::current_dir().map_err(IoError)?;
  path.push(filename);

  File::create(path)
    .map(BufWriter::new)
    .map_err(IoError)
    .and_then(|mut buf_writer| {
      write_disasm(&mut buf_writer, function_bytes, &info.disasm_opts, addr, fn_map).map_err(DisasmError)?;

      Ok(())
    })?;

  Ok(())
}

fn read_file_into(buffer: &mut [u8], path: impl AsRef<Path>, offset: u64) -> Result<(), CompareError> {
  File::open(path)
    .and_then(|mut f| f.seek(SeekFrom::Start(offset)).map(|_| f))
    .and_then(|mut f| f.read_exact(buffer))
    .map_err(IoError)
}
