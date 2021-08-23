//#[macro_use]
extern crate mrusty;

extern crate rucy_mruby_prelude;

use rucy_mruby_prelude::chunk::*;

// use mrusty::{Mruby, MrubyError, MrubyImpl};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // use mrusty::mruby_ffi as ffi;

    //rucy_mruby_prelude::display_insn("1 + 1")?;

    let code = include_str!("cg2.rb");
    println!("Ruby Code:\n{}", code);

    //rucy_mruby_prelude::display_lv(code)?;
    //rucy_mruby_prelude::display_bytecodes(code)?;
    rucy_mruby_prelude::display_insn_nstring(code)?;

    let mruby = mrusty::Mruby::new();
    let p = rucy_mruby_prelude::get_debug_proc_nstring(mruby.clone(), code)?;

    let chunk = Chunk::new(mruby.clone(), p);
    println!("{:?}", &chunk.root.syms);

    println!(
        "STRING(0) = {}",
        &chunk.root.get_string_instance(0).to_str()?
    );
    println!(
        "STRING(1) = {}",
        &chunk.root.get_string_instance(1).to_str()?
    );

    for op in chunk.root.ops.into_iter() {
        println!("{}", op);
    }
    println!("");

    let def = chunk.struct_def.unwrap();

    for op in def.ops.iter() {
        println!("{}", op);
    }
    println!("");
    println!("as_arg: {:?}", def.as_args());

    for op in chunk.prog_def.unwrap().ops.into_iter() {
        println!("{}", op);
    }

    // let p = unsafe {
    //     let len = code.len() as i32;
    //     let ptr = code.as_ptr();
    //     ffi::mrb_ext_parse_nstring_as_proc(mruby.borrow().mrb, ptr, len)
    // };
    // eprintln!("rproc: {:?}", p);

    // // let reps: &[*const std::ffi::c_void] =
    // //     unsafe { std::slice::from_raw_parts(irep.reps, irep.rlen as usize) };
    // // eprintln!("{:?}", reps);
    // unsafe {
    //     let rep0 = ffi::mrb_ext_irep_from_rproc(p);
    //     eprintln!("rep0: {:?}", rep0);

    //     let rep0 = std::mem::transmute::<*const ffi::MrIrep, &ffi::MrIrep>(rep0);
    //     eprintln!("{:?}", rep0);

    //     let reps: &[*const ffi::MrIrep] = std::slice::from_raw_parts(rep0.reps, rep0.rlen as usize);
    //     eprintln!("{:?}", reps);

    //     let reps = reps
    //         .to_vec()
    //         .iter()
    //         .map(|p| std::mem::transmute::<*const ffi::MrIrep, &ffi::MrIrep>(*p))
    //         .collect::<Vec<&ffi::MrIrep>>();
    //     eprintln!("{:?}", reps);
    // }

    // unsafe {
    //     let rep1 = ffi::mrb_ext_subirep_from_rproc(p, 0);
    //     eprintln!("rep1: {:?}", rep1);

    //     let rep1 = std::mem::transmute::<*const ffi::MrIrep, &ffi::MrIrep>(rep1);
    //     eprintln!("{:?}", rep1);
    // }

    // println!("Ruby Code:\n{}", include_str!("proc2.rb"));

    // let code = concat!("lambda {", include_str!("cg2.rb"), "}");
    // rucy_mruby_prelude::display_insn(code)?;
    // rucy_mruby_prelude::display_lv(include_str!("proc2.rb"))?;
    // rucy_mruby_prelude::display_bytecodes(include_str!("proc2.rb"))?;
    // rucy_mruby_prelude::display_insn(include_str!("proc2.rb"))?;

    Ok(())
}
