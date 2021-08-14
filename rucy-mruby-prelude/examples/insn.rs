//#[macro_use]
extern crate mrusty;

extern crate rucy_mruby_prelude;

// use mrusty::{Mruby, MrubyError, MrubyImpl};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    //rucy_mruby_prelude::display_insn("1 + 1")?;

    let code = include_str!("cg2.rb");
    println!("Ruby Code:\n{}", code);

    rucy_mruby_prelude::display_lv(code)?;
    rucy_mruby_prelude::display_bytecodes(code)?;
    rucy_mruby_prelude::display_insn(code)?;

    // println!("Ruby Code:\n{}", include_str!("proc2.rb"));

    // rucy_mruby_prelude::display_lv(include_str!("proc2.rb"))?;
    // rucy_mruby_prelude::display_bytecodes(include_str!("proc2.rb"))?;
    // rucy_mruby_prelude::display_insn(include_str!("proc2.rb"))?;

    Ok(())
}
