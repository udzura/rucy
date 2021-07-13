//#[macro_use]
extern crate mrusty;

extern crate rucy_mruby_prelude;

// use mrusty::{Mruby, MrubyError, MrubyImpl};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    //rucy_mruby_prelude::display_insn("1 + 1")?;

    println!("Ruby Code:\n{}", include_str!("proc.rb"));

    rucy_mruby_prelude::display_insn(include_str!("proc.rb"))?;

    println!("Ruby Code:\n{}", include_str!("proc2.rb"));

    rucy_mruby_prelude::display_insn(include_str!("proc2.rb"))?;

    Ok(())
}
