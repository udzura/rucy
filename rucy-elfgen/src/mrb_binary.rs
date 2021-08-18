use mrusty::mruby_ffi as ffi;
use mrusty::{self, MrubyImpl, MrubyType, Value};
use rucy_mruby_prelude::bpf;
use rucy_mruby_prelude::chunk::MrubyChunk;

pub fn value_from_binary(mruby: MrubyType, value: &[u8]) -> mrusty::Value {
    let mrvalue = unsafe { ffi::mrb_str_new(mruby.borrow().mrb, value.as_ptr(), value.len()) };
    mrusty::Value::new(mruby, mrvalue)
}

pub fn compile_and_set_prog(mruby: MrubyType) -> Result<(), Box<dyn std::error::Error>> {
    let prog = mruby.run("Rucy::ELFFile.program")?;
    match prog.value.typ {
        ffi::MrType::MRB_TT_PROC => {
            let chunk = MrubyChunk::new(mruby.clone(), prog);
            let mut bins: Vec<Vec<u8>> = vec![];
            for insn in chunk.translate()?.iter() {
                let bin: &[u8] = insn.as_bin();
                bins.push(bin.to_owned())
            }
            let bin: Vec<u8> = bins.concat();
            let cont = value_from_binary(mruby.clone(), &bin);

            let klass = mruby.run("Rucy::ELFFile")?;
            klass.call("reset_program", vec![cont])?;
        }
        /// already compiled...?
        ffi::MrType::MRB_TT_STRING => {}
        _ => {
            panic!("BPF program is unset or invalidly typed");
        }
    }
    Ok(())
}
