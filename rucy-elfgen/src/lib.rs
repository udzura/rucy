use rucy_libelf_sys::*;
//extern crate rucy_mruby_prelude;
use std::fs::File;
use std::os::unix::io::AsRawFd;

use errno::errno;

//use std::mem::MaybeUninit;
use std::path::Path;

pub fn generate(path: impl AsRef<Path>) -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        elf_version(EV_CURRENT);
        let file = File::create(path)?;
        let elf = elf_begin(
            file.as_raw_fd(),
            Elf_Cmd_ELF_C_WRITE,
            std::ptr::null_mut::<Elf>(),
        );
        if elf.is_null() {
            return Err(Box::new(errno()));
        }

        let mut ehdr = elf64_newehdr(elf);
        (*ehdr).e_type = ET_REL as u16;
        (*ehdr).e_machine = EM_BPF as u16;
        (*ehdr).e_shentsize = 1;

        if (gelf_update_ehdr(elf, ehdr) == 0) {
            return Err(Box::new(errno()));
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
