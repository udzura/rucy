use mrusty::mruby_ffi as ffi;
use mrusty::{self, MrubyImpl, MrubyType, Value};
use rucy_mruby_prelude::bpf;
use rucy_mruby_prelude::chunk::Chunk;

pub fn value_from_binary(mruby: MrubyType, value: &[u8]) -> mrusty::Value {
    let mrvalue = unsafe { ffi::mrb_str_new(mruby.borrow().mrb, value.as_ptr(), value.len()) };
    mrusty::Value::new(mruby, mrvalue)
}

pub fn register_chunk(mruby: MrubyType, chunk: Value) -> Result<(), Box<dyn std::error::Error>> {
    let klass = mruby.run("Rucy::ELFFile")?;
    klass.set_var("@dsl", chunk);
    Ok(())
}
