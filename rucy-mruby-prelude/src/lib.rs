extern crate mrusty;

use mrusty::mruby_ffi as ffi;
use mrusty::{MrValue, Mruby, MrubyImpl, Value};

#[allow(dead_code)]
pub mod bpf;
pub mod bytecode;
pub mod chunk;

pub trait MrustyValueExt<'a> {
    fn as_mrb_value(&'a self) -> &'a MrValue;
}

impl<'a> MrustyValueExt<'a> for Value {
    fn as_mrb_value(&'a self) -> &'a MrValue {
        &self.value
    }
}

pub fn display_lv(code: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mruby = Mruby::new();

    let val: Value = mruby.run(code)?;

    unsafe {
        if val.as_mrb_value().typ == ffi::MrType::MRB_TT_PROC {
            let rproc = ffi::mrb_ext_proc_ptr(mruby.borrow().mrb, *val.as_mrb_value());
            let value: MrValue = ffi::mrb_ext_get_locals_from_proc(mruby.borrow().mrb, rproc);
            let value = Value::new(mruby.clone(), value);

            for (i, v) in value.to_vec()?.iter().enumerate() {
                eprintln!("LV: Reg=R{}, value={:?}", i + 1, v.to_str()?);
            }
        } else {
            eprintln!("Not a proc");
        }
    }

    Ok(())
}

pub fn display_bytecodes(code: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mruby = Mruby::new();

    let val: Value = mruby.run(code)?;

    unsafe {
        if val.as_mrb_value().typ == ffi::MrType::MRB_TT_PROC {
            let rproc = ffi::mrb_ext_proc_ptr(mruby.borrow().mrb, *val.as_mrb_value());

            let syms = ffi::mrb_ext_get_syms_from_proc(mruby.borrow().mrb, rproc);
            let syms = Value::new(mruby.clone(), syms).to_vec()?;
            eprintln!("syms: {:?}", syms);

            let p = ffi::mrb_ext_get_insns_from_proc(rproc);
            let len = ffi::mrb_ext_get_insns_len_from_proc(rproc);
            let insns: &[u8] = std::slice::from_raw_parts(p, len);

            let ops = bytecode::process(insns);

            eprintln!("INSNs:");
            for (i, v) in insns.to_vec().iter().enumerate() {
                eprint!("{:02x} ", v);
                if (i + 1) % 8 == 0 {
                    eprintln!("");
                }
            }
            eprintln!("");

            eprintln!("Parsed Ops:");
            for op in ops.iter() {
                eprintln!("{}", op);
                if op.code == rucy_mruby_sys_consts::MRB_INSN_OP_SEND {
                    let sym = syms.get(op.b2.unwrap() as usize).unwrap();
                    eprintln!("symbol B2({})=:{}", op.b2.unwrap(), sym.to_str()?);
                }
            }
        } else {
            eprintln!("Not a proc");
        }
    }

    Ok(())
}

pub fn display_insn(code: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mruby = Mruby::new();

    let val: Value = mruby.run(code)?;
    //println!("{:?}", val);

    unsafe {
        if val.as_mrb_value().typ == ffi::MrType::MRB_TT_PROC {
            let rproc = ffi::mrb_ext_proc_ptr(mruby.borrow().mrb, *val.as_mrb_value());
            ffi::mrb_codedump_all(mruby.borrow().mrb, rproc);
        } else {
            eprintln!("Not a proc");
        }
    }

    Ok(())
}

pub fn display_insn_nstring(code: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mruby = Mruby::new();

    unsafe {
        let len = code.len() as i32;
        let ptr = code.as_ptr();
        let rproc = ffi::mrb_ext_parse_nstring_as_proc(mruby.borrow().mrb, ptr, len);
        ffi::mrb_codedump_all(mruby.borrow().mrb, rproc);
    }

    Ok(())
}

pub fn get_debug_proc_nstring(
    mruby: mrusty::MrubyType,
    code: &str,
) -> Result<*const ffi::MrProc, Box<dyn std::error::Error>> {
    let rproc = unsafe {
        let len = code.len() as i32;
        let ptr = code.as_ptr();
        ffi::mrb_ext_parse_nstring_as_proc(mruby.borrow().mrb, ptr, len)
    };

    Ok(rproc)
}
