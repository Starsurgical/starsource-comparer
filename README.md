# Starsource-comparer

Small binary comparison helper tool for starsource.

Generates an orig.asm and a compare.asm in the current directory and can watch the respective *.pdb for changes.

It can also generate a full disassembly of all specified functions in the config file (see the subcommand `generate-full`) for that.

Use `--help` for parameter info.

Example call:

```plain
starsource-comparer compare path\to\Starcraft_orig.exe starsource\bld\WinRel\Starcraft.exe read_gametype_templates -w
```

## Requirements

This uses Rust in the 2018 edition (so currently nightly only). In order to generate bindings to the [Zydis](https://github.com/zyantific/zydis-rs) library, you will also need clang/llvm to generate those.

## The config file

The config file contains a mapping from function name/symbol to its offset (and optionally its size).
It has to reside in the path of the starsource-comparer.

It is specified in the [TOML](https://github.com/toml-lang/toml) format, version 0.5.

The `size` element in the function definitions is optional, but is needed for some functions like the full export
of the original file.

## `--help`

```plain
Generates orig.asm and compare.asm in the current working directory. Finds the function specified in the starsource binary, disassembles it, then disassembles the original binary with the same length at the specified
offset. The disassembled original code will be written into orig.asm, the starsource code into compare.asm.\n\nNote that the disassembler will use the function offset read from the PDB for both decompilations in order
 to align the addresses in the output files (including relative jumps)

Usage: starsource-comparer.exe [OPTIONS] <COMMAND>

Commands:
  compare        Generates two disassembly files to compare a function between the original exe and new exe
  generate-full  Generates a disassembly file with all functions defined in comparer-config.toml
  help           Print this message or the help of the given subcommand(s)

Options:
  -i, --show-ip               Shows leading addresses in the output
      --no-mem-disp           Hide memory displacements and indirect calls. This cleans up the output tremendously, but can cause you to miss wrong stack variables or globals. Use only with caution
      --no-imms               Hides all immediate values. Use with caution
      --truncate-to-original  Truncate the number bytes disassembled in the compared binary to the length of the original function instead of the reported length in the pdb file
  -h, --help                  Print help
  -V, --version               Print version
```

### `compare --help`

```plain
Generates two disassembly files to compare a function between the original exe and new exe

Usage: starsource-comparer.exe compare [OPTIONS] <STARCRAFT_FILE> <STARSOURCE_FILE> <DEBUG_SYMBOL>

Arguments:
  <STARCRAFT_FILE>   Path to the original Starcraft.exe to use
  <STARSOURCE_FILE>  Sets the debug binary file to use. The respective .pdb file needs to exist in the same folder as well
  <DEBUG_SYMBOL>     Function name/debug symbol to compare. This has to be defined for the original binary in the comparer-config.toml. Is the size attribute missing, starsource-comparer will use the size of the stars
ource function for the original binary as well

Options:
  -w, --watch  Enable watching for changes to the PDB file, updating the output files on change
  -h, --help   Print help
```

### `generate-full --help`

```plain
Generates a disassembly file with all functions defined in comparer-config.toml

Usage: starsource-comparer.exe generate-full [OPTIONS] <FILE>

Arguments:
  <FILE>  The file to generate the disassembly output for

Options:
      --orig-file  Generate the file for the original binary for all functions defined within comparer-config.toml, skipping functions without defined sizes
  -h, --help       Print help
```


## Compiling
```
cargo build
```

