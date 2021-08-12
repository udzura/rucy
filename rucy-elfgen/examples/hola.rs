extern crate rucy_elfgen;
use rucy_elfgen::models::*;
use rucy_libelf_sys::consts::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let data_gpl = b"GPL\0".to_vec();
    const DUMMY_BPF_PROG: &[u8] =
        b"\xb7\x00\x00\x00\x01\x00\x00\x00\x95\x00\x00\x00\x00\x00\x00\x00";

    let arg = std::env::args()
        .nth(1)
        .expect("Usage: cargo run --example hola -- [ELF_FILE_PATH]");
    println!("Generate elf file: {}", arg);

    let symbols = vec![
        Symbol {
            name: "_license".to_string(),
            shndx: 2,
            info: ((STB_GLOBAL << 4) | STT_OBJECT) as u8,
            value: 0,
            size: data_gpl.len() as u64,
        },
        Symbol {
            name: "my_prog_orig_1".to_string(),
            shndx: 3,
            info: ((STB_GLOBAL << 4) | STT_FUNC) as u8,
            value: 0,
            size: DUMMY_BPF_PROG.len() as u64,
        },
    ];

    let source = Elf {
        ehdr: ElfHeader {
            r#type: ET_REL as u16,
            machine: EM_BPF as u16,
            shstridx: 1,
        },
        phdr: None,
        scns: vec![
            Section {
                r#type: SectionType::StrTab,
                header: SectionHeader {
                    name: ".strtab".to_string(),
                    r#type: SHT_STRTAB,
                    flags: 0,
                    align: 1,
                    link: 0,
                    info: 0,
                },
                data: SectionHeaderData::Unset,
            },
            Section {
                r#type: SectionType::License,
                header: SectionHeader {
                    name: "license".to_string(),
                    r#type: SHT_PROGBITS,
                    flags: (SHF_ALLOC | SHF_WRITE) as u64,
                    align: 1,
                    link: 0,
                    info: 0,
                },
                data: SectionHeaderData::Data(data_gpl),
            },
            Section {
                r#type: SectionType::Prog,
                header: SectionHeader {
                    name: "cgroup/dev".to_string(),
                    r#type: SHT_PROGBITS,
                    flags: (SHF_ALLOC | SHF_EXECINSTR) as u64,
                    align: 8,
                    link: 0,
                    info: 0,
                },
                data: SectionHeaderData::Data(DUMMY_BPF_PROG.to_vec()),
            },
            Section {
                r#type: SectionType::SymTab,
                header: SectionHeader {
                    name: ".symtab".to_string(),
                    r#type: SHT_SYMTAB,
                    flags: 0,
                    align: 8,
                    link: 1,
                    info: 1,
                },
                data: SectionHeaderData::SymTab(symbols),
            },
        ],
    };

    rucy_elfgen::generate(arg, source)
}
