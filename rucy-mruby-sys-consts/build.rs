extern crate bindgen;

use regex::Regex;
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=include/wrapper.h");

    let out_path = PathBuf::from("./bindgen");

    let bindings = bindgen::Builder::default()
        .header("include/wrapper.h")
        // .allowlist_function(".*")
        // .allowlist_var("^([a-z]|Elf).*")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    let dsl = include_str!("include/ops.h");
    let re = Regex::new(r"OPCODE\(([A-Z0-9_]+), +([A-Z]+)\)").unwrap();

    let mut f = File::create(out_path.join("match.rs"))?;

    f.write_all(
        b"
pub fn resolve_operand(insn: MRB_INSN) -> u32 {
    match insn {
",
    )?;

    for cap in re.captures_iter(dsl) {
        f.write_all(format!("MRB_INSN_OP_{} => {},\n", &cap[1], &cap[2]).as_bytes())?
    }

    f.write_all(
        b"
        _ => 0,
    }
}
",
    )?;

    Ok(())
}
