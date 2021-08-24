extern crate rucy_elfgen;

use std::path::PathBuf;

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
        file: PathBuf,
    },
    Build {
        /// Enable debug output
        #[structopt(short = "v")]
        debug: bool,
        #[structopt()]
        file: PathBuf,
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
            let chunk = rucy_elfgen::make_chunk_from_snippet(mruby.clone(), &file)?;
            let args = chunk.args();
            let prog = chunk.prog_def.unwrap();
            let insns = prog.translate(args.into_boxed_slice())?;

            let chunk = rucy_elfgen::make_mruby_chunk(
                mruby.clone(),
                &chunk.section_name,
                &chunk.prog_name,
                &chunk.license,
                &rucy_mruby_prelude::bpf::EbpfInsn::concat_bin(&insns),
            );
            rucy_elfgen::register_chunk(mruby.clone(), chunk)?;
            mruby.run("Rucy::Internal.register_dsl")?;

            let source = rucy_elfgen::copy_definition_to_rust(&mruby)?;

            rucy_elfgen::generate(&dest, source)?;
        }
        Cmd::Build { debug: _, file: _ } => {
            todo!("Whole build process in the future");
        }
    }
    Ok(())
}
