use std::ffi::CStr;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use rucy_libelf_sys::consts::*;
use rucy_mruby_prelude::chunk::Chunk;
use rucy_mruby_prelude::*;

use crate::models::*;

use mrusty::Mruby;
use mrusty::{MrValue, MrubyError, MrubyImpl, MrubyType, Value};

pub fn make_chunk_from_snippet(
    mruby: &MrubyType,
    script: &Path,
) -> Result<chunk::Chunk, Box<dyn std::error::Error>> {
    let mut f = File::open(script)?;
    let mut code = String::default();
    f.read_to_string(&mut code)?;

    let p = rucy_mruby_prelude::get_debug_proc_nstring(mruby.clone(), &code)?;
    Ok(Chunk::new(mruby.clone(), p))
}

pub fn make_mruby_chunk(
    mruby: MrubyType,
    section_name: &CStr,
    prog_name: &CStr,
    license: &CStr,
    bpf: &[u8],
) -> Value {
    let value = mruby.run("Rucy::Chunk.new").unwrap();
    value.set_var(
        "@section",
        mruby_cstr_to_string(mruby.clone(), section_name),
    );
    value.set_var("@funcname", mruby_cstr_to_string(mruby.clone(), prog_name));
    value.set_var("@license", mruby_cstr_to_string(mruby.clone(), license));
    value.set_var(
        "@data",
        crate::mrb_binary::value_from_binary(mruby.clone(), bpf),
    );

    value
}

pub fn mruby_cstr_to_string(mruby: MrubyType, cstr: &CStr) -> Value {
    mruby.string(cstr.to_str().unwrap())
}
