extern crate mrusty;
extern crate rucy_mruby_prelude;

use mrusty::{Mruby, MrubyImpl, Value};
use rucy_mruby_prelude::chunk::MrubyChunk;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mruby = Mruby::new();
    let code = "
lambda {
  return 0
}
";

    let proc: Value = mruby.run(code)?;

    eprintln!("Ruby code:");
    eprintln!("{}", code);
    let chunk = MrubyChunk::new(mruby.clone(), proc);
    eprintln!("eBPF insn:");
    for insn in chunk.translate()?.iter() {
        eprintln!("{:?}", insn);
    }

    let code = "
lambda {
  return 1
}
";

    let proc: Value = mruby.run(code)?;

    eprintln!("Ruby code:");
    eprintln!("{}", code);
    let chunk = MrubyChunk::new(mruby.clone(), proc);
    eprintln!("eBPF insn:");
    for insn in chunk.translate()?.iter() {
        eprintln!("{:?}", insn);
    }

    Ok(())
}
