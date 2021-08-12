use rucy_libelf_sys::*;
use std::ffi::c_void;
use std::fs::File;
use std::os::unix::io::IntoRawFd;

use errno::errno;

//use std::mem::MaybeUninit;
use std::path::Path;

pub mod mrb_models;

pub mod models {
    use std::collections::HashMap;

    #[derive(Debug, Clone)]
    pub struct Elf {
        pub ehdr: ElfHeader,
        pub phdr: Option<ProgHeader>,
        pub scns: Vec<Section>,
    }

    impl Elf {
        pub fn generate_strtab_data(&self) -> StringTable {
            let mut table = StringTable::default();
            table.table.push('\0');

            for scn in self.scns.iter() {
                table
                    .index_cache
                    .insert(scn.header.name.to_owned(), table.table.len() as u32);
                table.table.push_str(&scn.header.name);
                table.table.push('\0');
            }

            let symbol = self
                .scns
                .iter()
                .find(|&x| x.r#type == SectionType::SymTab)
                .unwrap();
            if let SectionHeaderData::SymTab(symbols) = symbol.data.clone() {
                for sym in symbols.iter() {
                    table
                        .index_cache
                        .insert(sym.name.to_owned(), table.table.len() as u32);
                    table.table.push_str(&sym.name);
                    table.table.push('\0');
                }
            }

            table
        }
    }

    #[derive(Debug, Clone, Default)]
    pub struct ElfHeader {
        pub r#type: u16,
        pub machine: u16,
        pub shstridx: u16,
    }

    #[derive(Debug, Clone)]
    pub struct ProgHeader {
        // TBA
    }

    #[derive(Debug, Clone)]
    pub struct Section {
        pub r#type: SectionType,
        pub header: SectionHeader,
        pub data: SectionHeaderData,
    }

    #[derive(Debug, Clone, Default)]
    pub struct SectionHeader {
        pub name: String,
        pub r#type: u32,
        pub flags: u64,
        pub align: u64,
        pub link: u32,
        pub info: u32,
    }

    #[derive(Debug, Clone)]
    #[non_exhaustive]
    pub enum SectionHeaderData {
        Unset,
        Data(Vec<u8>),
        SymTab(Vec<Symbol>),
    }

    #[derive(Debug, Clone)]
    pub struct Symbol {
        pub name: String,
        pub info: u8,
        pub shndx: u16,
        pub value: u64,
        pub size: u64,
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

    impl SectionType {
        pub fn from_i32(from: i32) -> Self {
            match from {
                0 => Self::Null,
                1 => Self::StrTab,
                2 => Self::Prog,
                3 => Self::License,
                4 => Self::SymTab,
                _ => panic!("Unsupported: {}", from),
            }
        }
    }
}

pub fn generate(
    path: impl AsRef<Path>,
    source: models::Elf,
) -> Result<(), Box<dyn std::error::Error>> {
    let table = source.generate_strtab_data();

    unsafe {
        elf_version(consts::EV_CURRENT);
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
                SectionType::SymTab => {
                    if let models::SectionHeaderData::SymTab(data) = &scn.data {
                        let entsize = ::std::mem::size_of::<Elf64_Sym>();
                        let mut buf = vec![
                            Elf64_Sym {
                                st_name: 0,
                                st_info: 0,
                                st_other: 0,
                                st_shndx: 0,
                                st_value: 0,
                                st_size: 0,
                            };
                            data.len() + 1
                        ]
                        .into_boxed_slice();

                        for (i, sym) in data.iter().enumerate() {
                            let idx = i + 1;
                            buf[idx].st_name = *table.index_cache.get(&sym.name).unwrap_or(&0u32);
                            buf[idx].st_info = sym.info;
                            buf[idx].st_other = 0;
                            buf[idx].st_shndx = sym.shndx;
                            buf[idx].st_value = sym.value;
                            buf[idx].st_size = sym.size;
                        }

                        let len = (entsize * (data.len() + 1)) as u64;
                        (*data_).d_buf = Box::into_raw(buf) as *mut c_void;
                        (*data_).d_size = len;
                        (*data_).d_align = scn.header.align;

                        (*sh).sh_size = len;
                        (*sh).sh_link = scn.header.link;
                        (*sh).sh_info = scn.header.info;
                        (*sh).sh_entsize = entsize as u64;
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
    println!("Successful");
    Ok(())
}
