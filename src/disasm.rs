use std::collections::HashMap;
use std::fmt::Debug;
use std::io::{Error as IoError, Write};

use thiserror::Error;
use zydis::ffi::{DecodedOperandKind, FormatterBuffer, FormatterContext, ImmediateInfo};
use zydis::{Decoder, Formatter, FormatterStyle, OutputBuffer, Result as ZydisResult, Status, VisibleOperands};

use super::comparer_config::FunctionDefinition;
use super::hexformat::*;

#[derive(Debug, Clone)]
pub struct DisasmOpts {
  pub print_addresses: bool,
  pub show_mem_disp: bool,
  pub show_imms: bool,
}

#[derive(Debug, Clone)]
struct DisasmExtra {
  #[allow(dead_code)]
  pub opts: DisasmOpts,
  pub fn_map: HashMap<u64, FunctionDefinition>,
  pub offset: u64,
}

#[derive(Debug, Error)]
pub enum DisasmError {
  #[error("IO error: {0}")]
  Io(#[from] IoError),

  #[error("Zydis disassembly error: {0:?}")]
  Zydis(#[from] Status),
}

pub fn write_disasm(
  writer: &mut impl Write,
  bytes: &[u8],
  disasm_opts: &DisasmOpts,
  offset: u64,
  fn_map: &HashMap<u64, FunctionDefinition>,
) -> Result<(), DisasmError> {
  let mut buf = [0u8; 255];
  let mut buf = OutputBuffer::new(&mut buf);

  let mut formatter = Formatter::<DisasmExtra>::new_custom_userdata(FormatterStyle::INTEL_MASM);
  formatter.set_print_address_abs(Box::new(format_addrs))?;

  if !disasm_opts.show_mem_disp {
    formatter.set_print_disp(Box::new(void_format_disp))?;
  }

  if !disasm_opts.show_imms {
    formatter.set_print_imm(Box::new(void_format_imms))?;
  }

  let decoder = Decoder::new32();

  let mut disasm_extra = DisasmExtra {
    opts: disasm_opts.clone(),
    fn_map: fn_map.clone(),
    offset,
  };

  for insn_info in decoder.decode_all::<VisibleOperands>(bytes, offset) {
    if insn_info.is_err() {
      break;
    }

    let (ip, _, insn) = insn_info.unwrap();

    disasm_extra.offset = ip; // BUG: Formatter is not propagating the instruction pointer
    formatter.format_ex(Some(ip), &insn, &mut buf, Some(&mut disasm_extra))?;

    let insn_str = buf.as_str().expect("not utf8");

    if disasm_opts.print_addresses {
      writeln!(writer, "{:X}: {}", ip, insn_str)?;
    } else {
      writeln!(writer, "{}", insn_str)?;
    }
  }

  Ok(())
}

fn cleanup_name(func: &FunctionDefinition) -> String {
  func.name.split('(').next().unwrap_or(&func.name).to_string()
}

fn process_address(target_addr: u64, imm: &ImmediateInfo) -> String {
  let prefix = if imm.is_relative { "$" } else { "" };

  if imm.is_signed {
    let hexformat = CustomUpperHexFormat(imm.value as i64);
    format!("{prefix}{hexformat:+#X}")
  } else {
    format!("{:+#X}", imm.value)
  }
}

fn format_addrs(
  _: &Formatter<DisasmExtra>,
  buf: &mut FormatterBuffer,
  ctx: &mut FormatterContext,
  disasm_opts: Option<&mut DisasmExtra>,
) -> ZydisResult<()> {
  unsafe {
    let opts = disasm_opts.unwrap();
    let op = &*ctx.operand;
    let insn = &*ctx.instruction;

    match &op.kind {
      DecodedOperandKind::Mem(mem) => {
        if mem.disp.has_displacement {
          if insn.opcode == 0xFF && [2, 3].contains(&insn.raw.modrm.reg) {
            buf.append_str("<indir_fn>")? // hide function call addresses, 0xFF /3 = CALL m16:32)
          } else {
            buf.append_str(&format!("{:#X}", mem.disp.displacement))?
          }
        } else {
          buf.append_str("<indir_addr>")?
        }
      }
      DecodedOperandKind::Imm(imm) => {
        let target_addr = insn.calc_absolute_address(opts.offset, op)?;
        let func = opts.fn_map.get(&target_addr);
        buf.append_str(&func.map_or_else(|| process_address(target_addr, imm), cleanup_name))?
      }
      _ => {}
    }
  }

  Ok(())
}

fn void_format_disp(
  _: &Formatter<DisasmExtra>,
  buf: &mut FormatterBuffer,
  ctx: &mut FormatterContext,
  _: Option<&mut DisasmExtra>,
) -> ZydisResult<()> {
  unsafe {
    let op = &*ctx.operand;

    match &op.kind {
      DecodedOperandKind::Mem(mem) if mem.disp.has_displacement => {
        // only write the displacement if it's actually displacing
        // not the case for something like `mov bl, [eax]`, i.e. `mov bl, [eax+0x0]`
        buf.append_str(if mem.disp.displacement < 0 { "-" } else { "+" })?;
        buf.append_str(&format!("<disp{}>", op.size))?;
      }
      _ => {}
    }
  }
  Ok(())
}

fn void_format_imms(
  _: &Formatter<DisasmExtra>,
  buf: &mut FormatterBuffer,
  ctx: &mut FormatterContext,
  _: Option<&mut DisasmExtra>,
) -> ZydisResult<()> {
  unsafe {
    let op = &*ctx.operand;
    buf.append_str(&format!("<imm{}>", op.size))?;
  }
  Ok(())
}

trait Compat {
  fn append_str<S: AsRef<str> + ?Sized>(&mut self, s: &S) -> ZydisResult<()>;
}

impl Compat for FormatterBuffer {
  /// Compat function to not have to change all of the code above
  fn append_str<S: AsRef<str> + ?Sized>(&mut self, s: &S) -> ZydisResult<()> {
    self.get_string().expect("not utf8").append(s)
  }
}
