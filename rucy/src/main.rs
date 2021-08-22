use structopt::*;

#[derive(StructOpt, Debug)]
#[structopt(about = "Pure Ruby DSL for BPF tools")]
enum Cmd {
    Object {
        /// Enable debug output
        #[structopt(short)]
        debug: bool,
        #[structopt()]
        file: String,
    },
    Build {
        /// Enable debug output
        #[structopt(short)]
        debug: bool,
        #[structopt()]
        file: String,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Cmd::from_args() {
        Cmd::Object { debug: _, file } => {
            println!("file: {}", file);
        }
        Cmd::Build { debug, file } => {
            todo!("Whole build process in the future");
        }
    }
    Ok(())
}
