extern crate bindgen;

use std::path::PathBuf;

fn main() {
    println!("cargo:rustc-link-lib=elf");
    println!("cargo:rerun-if-changed=include/wrapper.h");

    let out_path = PathBuf::from("./bindgen");

    let bindings = bindgen::Builder::default()
        .header("include/wrapper.h")
        .allowlist_function(".*")
        .allowlist_var("^([a-z]|Elf).*")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    let bindings = bindgen::Builder::default()
        .header("include/wrapper.h")
        .blocklist_function(".*")
        .allowlist_type("^Elf_Type$")
        .allowlist_var("^[A-Z_]+")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file(out_path.join("bindings_consts.rs"))
        .expect("Couldn't write bindings!");
}
