use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

use super::{Command, CompareCommandInfo, CompareOpts, DisasmOpts, GenerateFullCommandInfo};

/// Generates orig.asm and compare.asm in the current working directory.
/// Finds the function specified in the starsource binary, disassembles it,
/// then disassembles the original binary with the same length at the specified offset.
/// The disassembled original code will be written into orig.asm, the starsource code
/// into compare.asm.\n\nNote that the disassembler will use the function offset read
/// from the PDB for both decompilations in order to align the addresses in the output files
/// (including relative jumps).
#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
  /// Shows leading addresses in the output.
  #[arg(short = 'i', long = "show-ip")]
  show_ip: bool,

  /// Hide memory displacements and indirect calls. This cleans up the output tremendously,
  /// but can cause you to miss wrong stack variables or globals. Use only with caution.
  #[arg(long = "no-mem-disp")]
  no_mem_disp: bool,

  /// Hides all immediate values. Use with caution.
  #[arg(long = "no-imms")]
  no_imms: bool,

  /// Truncate the number bytes disassembled in the compared binary to the length of the
  /// original function instead of the reported length in the pdb file.
  #[arg(long = "truncate-to-original")]
  truncate_to_original: bool,

  #[command(subcommand)]
  command: Commands,
}

impl Cli {
  fn parse_generate_full_args(&self, args: &GenerateFullArgs) -> GenerateFullCommandInfo {
    GenerateFullCommandInfo {
      file_path: args.file.clone().into(),
      orig_file: args.orig_file,
      disasm_opts: self.parse_disasm_opts(),
      truncate_to_original: self.truncate_to_original,
    }
  }

  fn parse_disasm_opts(&self) -> DisasmOpts {
    DisasmOpts {
      print_adresses: self.show_ip,
      show_mem_disp: !self.no_mem_disp,
      show_imms: !self.no_imms,
    }
  }

  fn parse_compare_args(&self, args: &CompareArgs) -> CompareCommandInfo {
    let compare_file_path: PathBuf = PathBuf::from(&args.starsource_file);
    let compare_pdb_file = compare_file_path.with_extension("pdb");

    CompareCommandInfo {
      compare_opts: CompareOpts {
        orig: PathBuf::from(&args.starcraft_file),
        compare_file_path,
        compare_pdb_file,
        debug_symbol: args.debug_symbol.clone(),
      },
      disasm_opts: self.parse_disasm_opts(),
      enable_watcher: args.watch,
      last_offset_size: None,
      truncate_to_original: self.truncate_to_original,
    }
  }
}

#[derive(Args)]
struct CompareArgs {
  /// Path to the original Starcraft.exe to use
  starcraft_file: String,

  /// Sets the debug binary file to use.
  /// The respective .pdb file needs to exist in the same folder as well.
  starsource_file: String,

  /// Function name/debug symbol to compare. This has to be defined for the original
  /// binary in the comparer-config.toml. Is the size attribute missing, starsource-comparer
  /// will use the size of the starsource function for the original binary as well.
  debug_symbol: String,

  /// Enable watching for changes to the PDB file, updating the output files on change.
  #[arg(short, long)]
  watch: bool,
}

#[derive(Args)]
struct GenerateFullArgs {
  /// The file to generate the disassembly output for.
  file: String,

  /// Generate the file for the original binary for all functions defined within
  /// comparer-config.toml, skipping functions without defined sizes.
  #[arg(long = "orig-file")]
  orig_file: bool,
}

#[derive(Subcommand)]
enum Commands {
  /// Generates two disassembly files to compare a function between the original exe and new exe.
  #[command(arg_required_else_help = true)]
  Compare(CompareArgs),
  /// Generates a disassembly file with all functions defined in comparer-config.toml.
  #[command(arg_required_else_help = true)]
  GenerateFull(GenerateFullArgs),
}

pub fn parse_cmdline() -> Command {
  let cli = Cli::parse();

  match &cli.command {
    Commands::GenerateFull(args) => Command::GenerateFull(cli.parse_generate_full_args(args)),
    Commands::Compare(args) => Command::Compare(cli.parse_compare_args(args)),
  }
}
