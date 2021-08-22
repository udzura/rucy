extern crate rucy_elfgen;

use std::path::Path;

use mrusty::{self};
//use mrusty::{MrValue, Mruby, MrubyError, MrubyImpl, MrubyType, Value};
use mrusty::{MrubyImpl, MrubyType};
use structopt::*;

#[derive(StructOpt, Debug)]
#[structopt(about = "Pure Ruby DSL for BPF tools")]
enum Cmd {
    Object {
        /// Enable debug output
        #[structopt(short = "v")]
        debug: bool,
        /// Destination path to create BPF object into
        #[structopt(short, long)]
        dest: String,
        #[structopt()]
        file: String,
    },
    Build {
        /// Enable debug output
        #[structopt(short = "v")]
        debug: bool,
        #[structopt()]
        file: String,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Cmd::from_args() {
        Cmd::Object {
            debug: _,
            dest,
            file,
        } => {
            let mruby: MrubyType = rucy_elfgen::new_mruby_env()?;
            mruby.run("Rucy.object_create_mode!")?;

            mruby.execute(&Path::new(&file))?;
            mruby.run("Rucy::Internal.register_dsl")?;
            rucy_elfgen::compile_and_set_prog(mruby.clone())?;

            let source = rucy_elfgen::copy_definition_to_rust(&mruby)?;

            rucy_elfgen::generate(&dest, source)?;
        }
        Cmd::Build { debug: _, file: _ } => {
            todo!("Whole build process in the future");
        }
    }
    Ok(())
}
