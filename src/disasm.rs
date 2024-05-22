use std::collections::HashMap;
use std::fmt::Debug;
use std::io::{Error as IoError, Write};

use zydis::ffi::{DecodedOperandKind, FormatterBuffer, FormatterContext};
use zydis::{Decoder, Formatter, FormatterStyle, OutputBuffer, Result as ZydisResult, Status, VisibleOperands};

use super::comparer_config::FunctionDefinition;
use super::hexformat::*;

#[derive(Debug, Clone)]
pub struct DisasmOpts {
  pub print_adresses: bool,
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

#[derive(Debug)]
pub enum DisasmError {
  IoError(IoError),
  ZydisError(Status),
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
  formatter
    .set_print_address_abs(Box::new(format_addrs))
    .map_err(DisasmError::ZydisError)?;

  if !disasm_opts.show_mem_disp {
    formatter
      .set_print_disp(Box::new(void_format_disp))
      .map_err(DisasmError::ZydisError)?;
  }

  if !disasm_opts.show_imms {
    formatter
      .set_print_imm(Box::new(void_format_imms))
      .map_err(DisasmError::ZydisError)?;
  }

  let decoder = Decoder::new32();

  /*
  // TODO: We can't access other functions because bytes are only for our current function
  let decoder = Decoder::new32();
  for insn_info in decoder.decode_all::<VisibleOperands>(bytes, offset) {
    let (ip, _, insn) = insn_info.unwrap();

    match insn.mnemonic {
      Mnemonic::JMP | Mnemonic::CALL if insn.raw.imm.len() > 0 => {
        let target_addr = insn.calc_absolute_address(ip, &insn.operands()[0]).unwrap();
        if fn_map.contains_key(&target_addr) {
          continue;
        }

        println!("{target_addr:X}\n");

        let target_addr_pos = target_addr as usize;
        // TODO: This can't work because the bytes are ONLY for the function we are working in
        //decoder.decode_first(???);

        // TODO: finish
        // 1. Decode the new target_addr instruction.
        // 2. Check if it's a JMP.
        // 3. Get its next target address.
        // 4. Copy the new address's name mapping to the original target address.
      }
      _ => {}
    }
  }

  let mut bigger_fn_map = fn_map.clone();
  bigger_fn_map.extend(result);
  */

  let mut disasm_extra = DisasmExtra {
    opts: disasm_opts.clone(),
    fn_map: fn_map.clone(),
    offset,
  };

  for insn_info in decoder.decode_all::<VisibleOperands>(bytes, offset) {
    let (ip, _, insn) = insn_info.unwrap();

    disasm_extra.offset = ip; // BUG: Formatter is not propagating the instruction pointer
    formatter
      .format_ex(Some(ip), &insn, &mut buf, Some(&mut disasm_extra))
      .map_err(DisasmError::ZydisError)?;

    let insn_str = buf.as_str().expect("not utf8");

    if disasm_opts.print_adresses {
      writeln!(writer, "{:X}: {}", ip, insn_str).map_err(DisasmError::IoError)?;
    } else {
      writeln!(writer, "{}", insn_str).map_err(DisasmError::IoError)?;
    }
  }

  Ok(())
}

fn cleanup_name(name: &str) -> &str {
  name.split('(').next().unwrap_or(name)
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
      DecodedOperandKind::Imm(imm) => match insn.opcode {
        0xE8 => {
          let target_addr = insn.calc_absolute_address(opts.offset, op)?;
          //let target_addr = (opts.offset + ctx.runtime_address).wrapping_add(imm.value) + u64::from(insn.length);
          let func = opts.fn_map.get(&target_addr);
          // TODO Problem with calls to anonymous `jmp <addr>` which calls the actual function

          buf.append_str(func.map_or(format!("{:#X}", target_addr).as_str(), |func| {
            cleanup_name(func.name.as_str())
          }))?
        }
        _ => {
          if imm.is_relative {
            buf.append_str("$")?;
          } else {
            buf.append_str("<imm_addr>")?;
            return Ok(());
          }
          if imm.is_signed {
            buf.append_str(&format!("{:+#X}", CustomUpperHexFormat(imm.value as i64)))?;
          } else {
            buf.append_str(&format!("{:+#X}", imm.value))?;
          }
        }
      },
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
