#[macro_use]
extern crate mrusty;

use mrusty::mruby_ffi as ffi;
use mrusty::{MrValue, Mruby, MrubyError, MrubyImpl, Value};

pub trait MrustyValueExt<'a> {
    fn as_mrb_value(&'a self) -> &'a MrValue;
}

impl<'a> MrustyValueExt<'a> for Value {
    fn as_mrb_value(&'a self) -> &'a MrValue {
        &self.value
    }
}

pub fn display_insn(code: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mruby = Mruby::new();

    let val: Value = mruby.run(code)?;
    //println!("{:?}", val);

    unsafe {
        if val.as_mrb_value().typ == ffi::MrType::MRB_TT_PROC {
            let rproc = ffi::mrb_ext_proc_ptr(mruby.borrow().mrb, *val.as_mrb_value());
            ffi::mrb_codedump_all(mruby.borrow().mrb, rproc);
        }
    }

    Ok(())
}
