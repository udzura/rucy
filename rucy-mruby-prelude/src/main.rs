#[macro_use]
extern crate mrusty;

use mrusty::{Mruby, MrubyError, MrubyImpl};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mruby = Mruby::new();

    mruby_class!(mruby, "Prelude", {
        def_self!("puts", |mruby, _rbself: Value, msg: (&str)| {
            println!("{}", msg);
            mruby.nil()
        });
    });

    mruby.run(
        "
      module Kernel
        def puts(arg)
          Prelude.puts arg
        end
      end
    ",
    )?;

    mruby.run("puts \"Hola! Mundo\"")?;

    Ok(())
}
