use std::path::Path;

use rucy_libelf_sys::consts::*;
use rucy_mruby_prelude::*;

use crate::models::*;

use mrusty::{self};
use mrusty::{MrValue, Mruby, MrubyError, MrubyImpl, MrubyType, Value};

pub fn eval_elf_dsl(mruby: &MrubyType, script: &Path) -> Result<Value, Box<dyn std::error::Error>> {
    let prelude = include_str!("mrblib/models.rb");
    mruby.run(prelude)?;

    let v = mruby.execute(script)?;
    Ok(v)
}
