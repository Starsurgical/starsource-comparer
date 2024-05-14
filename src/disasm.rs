use std::any::Any;
use std::collections::HashMap;
use std::io::{Error as IoError, Write};

use zydis::{
  AddressWidth, DecodedInstruction, Decoder, Formatter, FormatterBuffer, FormatterContext, FormatterStyle, MachineMode, Mnemonic, OperandType, OutputBuffer, Result as ZydisResult, Status
};

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
  pub opts: DisasmOpts,
  pub fn_map: HashMap<u64, FunctionDefinition>,
}

#[derive(Debug)]
pub enum DisasmError {
  IoError(IoError),
  ZydisError(Status),
}

fn is_imm_jmpcall(insn: &DecodedInstruction) -> bool {
  match insn.mnemonic {
    Mnemonic::JMP | Mnemonic::CALL if insn.operand_count > 0 && insn.operands[0].ty == OperandType::IMMEDIATE => true,
    _ => false
  }
}

// If the decoded instruction is an immediate call or jmp instruction,
// then return the target address.
fn get_jmpcall_address(insn: &DecodedInstruction, ip: &u64) -> Option<u64> {
  if is_imm_jmpcall(insn) {
    Some(ip.wrapping_add(insn.operands[0].imm.value) + u64::from(insn.length));
  }
  None
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

  // FIXME: Formatter:intel()
  let mut formatter = Formatter::new(FormatterStyle::INTEL).map_err(DisasmError::ZydisError)?;
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

  // FIXME: Decoder::new32()
  let decoder = Decoder::new(MachineMode::LEGACY_32, AddressWidth::_32).map_err(DisasmError::ZydisError)?;

  /*
  // TODO: not working :(
  // This mess... tries to resolve random extra jmps that can get generated with certain compiler options
  let result = decoder.instruction_iterator(bytes, offset)
  .flat_map(|(insn, ip)|
    get_jmpcall_address(&insn, &ip).map(|target_addr| {
      let target_addr_pos = target_addr as usize;
      decoder.decode(&bytes[target_addr_pos .. target_addr_pos + 5])
        .unwrap_or_default()
        .filter(|insn|insn.mnemonic == Mnemonic::JMP && is_imm_jmpcall(insn))
        .map(|insn| get_jmpcall_address(&insn, &target_addr).map(
          |real_addr| fn_map.get(&real_addr).map(|func| (target_addr,func.clone()))
        ).flatten()).flatten()
    }).flatten()
  );

  let mut bigger_fn_map = fn_map.clone();
  bigger_fn_map.extend(result);
  */

  let mut disasm_extra = DisasmExtra {
    opts: disasm_opts.clone(),
    fn_map: fn_map.clone(),
  };

  for (insn, ip) in decoder.instruction_iterator(bytes, offset) {
    formatter
      .format_instruction(&insn, &mut buf, Some(ip), Some(&mut disasm_extra))
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

fn format_addrs(
  _: &Formatter,
  buf: &mut FormatterBuffer,
  ctx: &mut FormatterContext,
  disasm_opts: Option<&mut dyn Any>,
) -> ZydisResult<()> {
  let extra = disasm_opts.unwrap().downcast_ref::<DisasmExtra>().unwrap();

  unsafe {
    let op = &*ctx.operand;
    let insn = &*ctx.instruction;

    match op.ty {
      OperandType::MEMORY => {
        if extra.opts.show_mem_disp {
          if insn.opcode == 0xFF && [2, 3].contains(&insn.raw.modrm_reg) {
            buf.append_str("<indir_fn>")? // hide function call addresses, 0xFF /3 = CALL m16:32)
          } else {
            buf.append_str(&format!("{:#X}", op.mem.disp.displacement))?
          }
        } else {
          buf.append_str("<indir_addr>")?
        }
      }
      OperandType::IMMEDIATE => match insn.opcode {
        0xE8 => {
          let target_addr = ctx.runtime_address.wrapping_add(op.imm.value) + u64::from(insn.length);
          let func = extra.fn_map.get(&target_addr);
          // TODO Problem with calls to anonymous `jmp <addr>` which calls the actual function

          buf.append_str(
            func.map_or(format!("{:#X}", target_addr).as_str(), |func| func.name.as_str()),
          )?
        },
        _ => {
          if op.imm.is_relative {
            buf.append_str("$")?;
          } else {
            buf.append_str("<imm_addr>")?;
            return Ok(());
          }
          if op.imm.is_signed {
            buf.append_str(&format!("{:+#X}", CustomUpperHexFormat(op.imm.value as i64)))?;
          } else {
            buf.append_str(&format!("{:+#X}", op.imm.value))?;
          }
        }
      },
      _ => {}
    }
  }

  Ok(())
}

fn void_format_disp(
  _: &Formatter,
  buf: &mut FormatterBuffer,
  ctx: &mut FormatterContext,
  _: Option<&mut dyn Any>,
) -> ZydisResult<()> {
  unsafe {
    let op = &*ctx.operand;
    if op.mem.disp.has_displacement {
      // only write the displacement if it's actually displacing
      // not the case for something like `mov bl, [eax]`, i.e. `mov bl, [eax+0x0]`
      buf.append_str(if op.mem.disp.displacement < 0 { "-" } else { "+" })?;
      buf.append_str(&format!("<disp{}>", op.size))?;
    }
  }
  Ok(())
}

fn void_format_imms(
  _: &Formatter,
  buf: &mut FormatterBuffer,
  ctx: &mut FormatterContext,
  _: Option<&mut dyn Any>,
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
