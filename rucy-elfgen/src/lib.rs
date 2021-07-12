use rucy_libelf_sys::*;
use std::ffi::c_void;
use std::fs::File;
use std::os::unix::io::IntoRawFd;

use errno::errno;

//use std::mem::MaybeUninit;
use std::path::Path;

mod models {
    use std::collections::HashMap;

    #[derive(Debug, Clone)]
    pub struct Elf {
        pub ehdr: ElfHeader,
        pub phdr: Option<ProgHeader>,
        pub scns: Vec<Section>,
    }

    #[derive(Debug, Clone)]
    #[non_exhaustive]
    pub struct ElfHeader {
        pub r#type: u16,
        pub machine: u16,
        pub shstridx: u16,
    }

    #[derive(Debug, Clone)]
    #[non_exhaustive]
    pub struct ProgHeader {
        // TBA
    }

    #[derive(Debug, Clone)]
    #[non_exhaustive]
    pub struct Section {
        pub r#type: SectionType,
        pub header: SectionHeader,
        pub data: SectionHeaderData,
    }

    #[derive(Debug, Clone)]
    #[non_exhaustive]
    pub struct SectionHeader {
        pub name: String,
        pub r#type: u32,
        pub flags: u64,
        pub align: u64,
        pub link: u64,
    }

    #[derive(Debug, Clone)]
    #[non_exhaustive]
    pub enum SectionHeaderData {
        Unset,
        Data(Vec<u8>),
        SymTab(Vec<Symbol>),
    }

    #[derive(Debug, Clone)]
    #[non_exhaustive]
    pub struct Symbol {
        pub name: String,
        pub info: u64,
        pub shndx: u16,
        pub value: u64,
    }

    #[derive(Debug, Clone, Default)]
    pub struct StringTable {
        pub table: String,
        pub index_cache: HashMap<String, u32>,
    }

    #[derive(Debug, Copy, Clone, Eq, PartialEq)]
    #[non_exhaustive]
    #[allow(dead_code)]
    pub enum SectionType {
        Null,
        StrTab,
        Prog,
        License,
        SymTab,
    }
}

const DUMMY_BPF_PROG: &[u8] = b"\xb7\x00\x00\x00\x01\x00\x00\x00\x95\x00\x00\x00\x00\x00\x00\x00";

pub fn generate(path: impl AsRef<Path>) -> Result<(), Box<dyn std::error::Error>> {
    let mut table = models::StringTable::default();

    let symbols = vec![
        models::Symbol {
            name: "_license".to_string(),
            shndx: 2,
            info: ((STB_GLOBAL << 4) | STT_OBJECT) as u64,
            value: 0,
        },
        models::Symbol {
            name: "my_prog_1".to_string(),
            shndx: 3,
            info: ((STB_GLOBAL << 4) | STT_FUNC) as u64,
            value: 0,
        },
    ];

    let source = models::Elf {
        ehdr: models::ElfHeader {
            r#type: ET_REL as u16,
            machine: EM_BPF as u16,
            shstridx: 1,
        },
        phdr: None,
        scns: vec![
            models::Section {
                r#type: models::SectionType::StrTab,
                header: models::SectionHeader {
                    name: ".strtab".to_string(),
                    r#type: SHT_STRTAB,
                    flags: 0,
                    align: 1,
                    link: 0,
                },
                data: models::SectionHeaderData::Unset,
            },
            models::Section {
                r#type: models::SectionType::License,
                header: models::SectionHeader {
                    name: "license".to_string(),
                    r#type: SHT_PROGBITS,
                    flags: (SHF_ALLOC | SHF_WRITE) as u64,
                    align: 1,
                    link: 0,
                },
                data: models::SectionHeaderData::Data(b"GPL\0".to_vec()),
            },
            models::Section {
                r#type: models::SectionType::Prog,
                header: models::SectionHeader {
                    name: "cgroup/dev".to_string(),
                    r#type: SHT_PROGBITS,
                    flags: (SHF_ALLOC | SHF_EXECINSTR) as u64,
                    align: 8,
                    link: 0,
                },
                data: models::SectionHeaderData::Data(DUMMY_BPF_PROG.to_vec()),
            },
            models::Section {
                r#type: models::SectionType::SymTab,
                header: models::SectionHeader {
                    name: ".symtab".to_string(),
                    r#type: SHT_SYMTAB,
                    flags: 0,
                    align: 8,
                    link: 1,
                },
                data: models::SectionHeaderData::SymTab(symbols),
            },
        ],
    };

    table.table.push('\0');

    for scn in source.scns.iter() {
        table
            .index_cache
            .insert(scn.header.name.to_owned(), table.table.len() as u32);
        table.table.push_str(&scn.header.name);
        table.table.push('\0');
    }

    let symbol = source
        .scns
        .iter()
        .find(|&x| x.r#type == models::SectionType::SymTab)
        .unwrap();
    if let models::SectionHeaderData::SymTab(symbols) = symbol.data.clone() {
        for sym in symbols.iter() {
            table
                .index_cache
                .insert(sym.name.to_owned(), table.table.len() as u32);
            table.table.push_str(&sym.name);
            table.table.push('\0');
        }
    }

    unsafe {
        elf_version(EV_CURRENT);
        let file = File::create(path)?;
        let elf = elf_begin(
            file.into_raw_fd(),
            Elf_Cmd_ELF_C_WRITE,
            std::ptr::null_mut::<Elf>(),
        );
        if elf.is_null() {
            return Err(Box::new(errno()));
        }

        let mut ehdr = elf64_newehdr(elf);
        (*ehdr).e_type = source.ehdr.r#type;
        (*ehdr).e_machine = source.ehdr.machine;
        (*ehdr).e_shstrndx = source.ehdr.shstridx;

        if gelf_update_ehdr(elf, ehdr) == 0 {
            return Err(Box::new(errno()));
        }

        // skip phdr

        for scn in source.scns.iter() {
            let scn_ = elf_newscn(elf);
            let sh = elf64_getshdr(scn_);
            let data_ = elf_newdata(scn_);

            use models::SectionType;
            let ty = scn.r#type;
            match ty {
                SectionType::StrTab => {
                    let mut buf = vec![0u8; table.table.len()].into_boxed_slice();
                    buf.copy_from_slice(table.table.as_bytes());
                    let len = buf.len() as u64;
                    (*data_).d_buf = Box::into_raw(buf) as *mut c_void;
                    (*data_).d_size = len;
                    (*data_).d_align = scn.header.align;

                    (*sh).sh_size = len;
                    (*sh).sh_entsize = 0;
                }
                SectionType::License | SectionType::Prog => {
                    if let models::SectionHeaderData::Data(data) = &scn.data {
                        let mut buf = vec![0u8; data.len()].into_boxed_slice();
                        buf.copy_from_slice(data);
                        let len = buf.len() as u64;
                        (*data_).d_buf = Box::into_raw(buf) as *mut c_void;
                        (*data_).d_size = len;
                        (*data_).d_align = scn.header.align;

                        (*sh).sh_size = len;
                        (*sh).sh_entsize = 0;
                    } else {
                        panic!("invalid data: {:?}", scn.data);
                    }
                }
                _ => {
                    panic!("unsupported: {:?}", ty);
                }
            }

            (*sh).sh_type = scn.header.r#type;
            (*sh).sh_addralign = scn.header.align;
            (*sh).sh_flags = scn.header.flags;
            (*sh).sh_name = *table.index_cache.get(&scn.header.name).unwrap_or(&0u32);

            if gelf_update_shdr(scn_, sh) == 0 {
                return Err(Box::new(errno()));
            }
        }

        if elf_update(elf, Elf_Cmd_ELF_C_WRITE) == -1 {
            return Err(Box::new(errno()));
        }

        if elf_end(elf) == -1 {
            return Err(Box::new(errno()));
        }
    }
    println!("¡Hola!");
    Ok(())
}
