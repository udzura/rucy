use std::convert::TryInto;

use rucy_libelf_sys::consts::*;
use rucy_mruby_prelude::*;

use crate::models::*;

use mrusty::{self};
use mrusty::{MrValue, Mruby, MrubyError, MrubyImpl, MrubyType, Value};

pub fn copy_definition_to_rust(mruby: &MrubyType) -> Result<Elf, Box<dyn std::error::Error>> {
    let model = mruby.run("Rucy::ELFFile.current_model")?;
    let mut source = Elf {
        ehdr: ElfHeader::default(),
        phdr: None,
        scns: vec![],
    };
    let mut symbols: Vec<Symbol> = vec![];
    let mut index_of_strtab: usize = 0;
    let mut index_of_symtab: usize = 0;

    // ehdr: class EHdrValue
    let ehdr = model.get_var("@ehdr").unwrap();
    source.ehdr.r#type = ehdr.get_var("@type").unwrap().to_i32()? as u16;
    source.ehdr.machine = ehdr.get_var("@machine").unwrap().to_i32()? as u16;

    // scn: class ScnValue
    for (i, scn) in ehdr.get_var("@scns").unwrap().to_vec()?.iter().enumerate() {
        let mut shdr = SectionHeader::default();
        let mut data = SectionHeaderData::Unset;
        let scn_type = scn.get_var("@type").unwrap().to_i32()?;
        let scn_type = SectionType::from_i32(scn_type);

        match scn_type {
            SectionType::StrTab => {
                shdr.name = scn.get_var("@name").unwrap().to_str()?.to_owned();
                shdr.r#type = SHT_STRTAB;
                shdr.flags = 0;
                shdr.align = 1;
                shdr.link = 0;
                shdr.info = 0;

                index_of_strtab = i + 1;
            }
            SectionType::License => {
                shdr.name = scn.get_var("@name").unwrap().to_str()?.to_owned();
                shdr.r#type = SHT_PROGBITS;
                shdr.flags = (SHF_ALLOC | SHF_WRITE) as u64;
                shdr.align = 1;
                shdr.link = 0;
                shdr.info = 0;

                let data_bin = scn.get_var("@data").unwrap().to_bytes()?.to_owned();
                let len = data_bin.len() as u64;
                data = SectionHeaderData::Data(data_bin.to_vec());

                let sym = Symbol {
                    name: scn.get_var("@symname").unwrap().to_str()?.to_owned(),
                    shndx: (i + 1) as u16,
                    info: ((STB_GLOBAL << 4) | STT_OBJECT) as u8,
                    value: 0,
                    size: len,
                };
                symbols.push(sym);
            }
            SectionType::Prog => {
                shdr.name = scn.get_var("@name").unwrap().to_str()?.to_owned();
                shdr.r#type = SHT_PROGBITS;
                shdr.flags = (SHF_ALLOC | SHF_EXECINSTR) as u64;
                shdr.align = 8;
                shdr.link = 0;
                shdr.info = 0;

                let data_bin = scn.get_var("@data").unwrap().to_bytes()?.to_owned();
                let len = data_bin.len() as u64;
                data = SectionHeaderData::Data(data_bin.to_vec());

                let sym = Symbol {
                    name: scn.get_var("@symname").unwrap().to_str()?.to_owned(),
                    shndx: (i + 1) as u16,
                    info: ((STB_GLOBAL << 4) | STT_FUNC) as u8,
                    value: 0,
                    size: len,
                };
                symbols.push(sym);
            }
            SectionType::SymTab => {
                shdr.name = scn.get_var("@name").unwrap().to_str()?.to_owned();
                shdr.r#type = SHT_SYMTAB;
                shdr.flags = 0;
                shdr.align = 8;
                shdr.link = 0;
                shdr.info = 1;

                index_of_symtab = i + 1;
            }
            SectionType::Null => todo!(),
        }
        let scn_ = Section {
            r#type: scn_type,
            header: shdr,
            data: data,
        };

        source.scns.push(scn_);
    }

    source.ehdr.shstridx = index_of_strtab as u16;

    if index_of_symtab > 0 {
        let mut symtab = source.scns.get_mut(index_of_symtab - 1).unwrap();
        symtab.data = SectionHeaderData::SymTab(symbols);

        symtab.header.link = index_of_strtab as u32;
    }

    Ok(source)
}
