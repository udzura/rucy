extern crate bindgen;

use std::path::PathBuf;

fn main() {
    println!("cargo:rustc-link-lib=elf");
    println!("cargo:rerun-if-changed=include/wrapper.h");

    let bindings = bindgen::Builder::default()
        .header("include/wrapper.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from("./bindgen");
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
