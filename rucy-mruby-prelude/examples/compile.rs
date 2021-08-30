extern crate mrusty;
extern crate rucy_mruby_prelude;

use mrusty::{Mruby, MrubyImpl, MrubyType, Value};
use rucy_mruby_prelude::chunk::*;

fn compile(mruby: MrubyType, code: &str) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("Ruby code:");
    eprintln!("{}", code);

    rucy_mruby_prelude::display_insn_nstring(code)?;

    let p = rucy_mruby_prelude::get_debug_proc_nstring(mruby.clone(), code)?;
    let chunk = Chunk::new(mruby.clone(), p);
    let args = chunk.args();
    let prog = chunk.prog_def.unwrap();

    let insns = prog.translate(args.into_boxed_slice())?;

    eprintln!("eBPF insn:");
    for insn in insns.iter() {
        eprintln!("{:?}", insn);
    }
    eprintln!("Bytecode:");
    for insn in insns.iter() {
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
license! \"GPL\"
section! \"dev/cgroup\"

class Ctx
  attr :access_type, :u32
  attr :major, :u32
  attr :minor, :u32
end

def prog(ctx)
  return 0
end
";
    //compile(mruby.clone(), code)?;

    let code = "
license! \"GPL\"
section! \"dev/cgroup\"

class Ctx
  attr :access_type, :u32
  attr :major, :u32
  attr :minor, :u32
end

def prog(ctx)
  if ctx.minor == 9
    return 0
  else
    return 1
  end
end
";
    compile(mruby.clone(), code)?;

    let code = "
license! \"GPL\"
section! \"dev/cgroup\"

class Ctx
  attr :access_type, :u32
  attr :major, :u32
  attr :minor, :u32
end

def prog(ctx)
  pid = bpf_get_current_pid_pgid()
  bpf_trace_printk(\"Access to character device detected. minor: %d\", pid)
  return 1
end
";

    //compile(mruby.clone(), code)?;

    let code = "
license! \"GPL\"
section! \"dev/cgroup\"

class Ctx
  attr :access_type, :u32
  attr :major, :u32
  attr :minor, :u32
end

def prog(ctx)
  if ctx.major == 1
    bpf_trace_printk(\"Access to character device detected. R/W: %d\", ctx.access_type)
  end
  return 1
end
";

    compile(mruby.clone(), code)?;

    Ok(())
}
