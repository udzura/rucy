use rucy_mruby_prelude::*;

use crate::models::*;

use mrusty::{self};
use mrusty::{MrValue, Mruby, MrubyError, MrubyImpl, MrubyType, Value};

pub fn copy_definition_to_rust(mruby: MrubyType) -> Result<Elf, Box<dyn std::error::Error>> {
    let model = mruby.run("Rucy::ELFFile.current_model")?;
    let mut source = Elf {
        ehdr: ElfHeader::default(),
        phdr: None,
        scns: vec![],
    };

    let ehdr = model.get_var("@ehdr").unwrap();
    source.ehdr.r#type = ehdr.get_var("@type").unwrap().to_i32()? as u16;
    source.ehdr.machine = ehdr.get_var("@machine").unwrap().to_i32()? as u16;
    source.ehdr.shstridx = ehdr.get_var("@shstridx").unwrap().to_i32()? as u16;

    Ok(source)
}
