extern crate mrusty;
extern crate rucy_mruby_prelude;

use mrusty::{Mruby, MrubyImpl, MrubyType, Value};
use rucy_mruby_prelude::chunk::MrubyChunk;

fn compile(mruby: MrubyType, code: &str) -> Result<(), Box<dyn std::error::Error>> {
    let proc: Value = mruby.run(code)?;

    eprintln!("Ruby code:");
    eprintln!("{}", code);
    rucy_mruby_prelude::display_insn(code)?;
    let chunk = MrubyChunk::new(mruby.clone(), proc);
    eprintln!("eBPF insn:");
    for insn in chunk.translate()?.iter() {
        eprintln!("{:?}", insn);
    }
    eprintln!("Bytecode:");
    for insn in chunk.translate()?.iter() {
        let bin: &[u8] = insn.as_bin();
        for c in bin.iter() {
            eprint!("{:02x} ", c);
        }
        eprintln!("");
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mruby = Mruby::new();
    let code = "
lambda do |ctx|
  if ctx.minor == 9
    return 0
  else
    return 1
  end
end
";
    compile(mruby.clone(), code)?;

    let code = "
lambda {
  return 1
}
";

    compile(mruby.clone(), code)?;

    Ok(())
}
