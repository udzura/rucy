pub const BPF_LD: u8 = 0x00;
pub const BPF_LDX: u8 = 0x01;
pub const BPF_ST: u8 = 0x02;
pub const BPF_STX: u8 = 0x03;
pub const BPF_ALU: u8 = 0x04;
pub const BPF_JMP: u8 = 0x05;
pub const BPF_RET: u8 = 0x06;
pub const BPF_MISC: u8 = 0x07;
pub const BPF_JMP32: u8 = 0x06;
pub const BPF_ALU64: u8 = 0x07;

/* ld/ldx size */
pub const BPF_W: u8 = 0x00;
pub const BPF_H: u8 = 0x08;
pub const BPF_B: u8 = 0x10;
pub const BPF_DW: u8 = 0x18;

/* ld/ldx mode */
pub const BPF_IMM: u8 = 0x00;
pub const BPF_ABS: u8 = 0x20;
pub const BPF_IND: u8 = 0x40;
pub const BPF_MEM: u8 = 0x60;
pub const BPF_LEN: u8 = 0x80;
pub const BPF_MSH: u8 = 0xa0;
pub const BPF_ATOMIC: u8 = 0xc0;

/* alu/jmp src */
pub const BPF_K: u8 = 0x00; // imm
pub const BPF_X: u8 = 0x08; // src

/* alu/jmp fields */
pub const BPF_ADD: u8 = 0x00;
pub const BPF_SUB: u8 = 0x10;
pub const BPF_MUL: u8 = 0x20;
pub const BPF_DIV: u8 = 0x30;
pub const BPF_OR: u8 = 0x40;
pub const BPF_AND: u8 = 0x50;
pub const BPF_LSH: u8 = 0x60;
pub const BPF_RSH: u8 = 0x70;
pub const BPF_NEG: u8 = 0x80;
pub const BPF_MOD: u8 = 0x90;
pub const BPF_XOR: u8 = 0xa0;
pub const BPF_MOV: u8 = 0xb0;
pub const BPF_ARSH: u8 = 0xc0;

/* change endianness of a register */
pub const BPF_END: u8 = 0xd0;
pub const BPF_TO_LE: u8 = 0x00;
pub const BPF_TO_BE: u8 = 0x08;

/* jmp encodings */
pub const BPF_JA: u8 = 0x00;
pub const BPF_JEQ: u8 = 0x10;
pub const BPF_JGT: u8 = 0x20;
pub const BPF_JGE: u8 = 0x30;
pub const BPF_JSET: u8 = 0x40;
pub const BPF_JNE: u8 = 0x50;
pub const BPF_JLT: u8 = 0xa0;
pub const BPF_JLE: u8 = 0xb0;
pub const BPF_JSGT: u8 = 0x60;
pub const BPF_JSGE: u8 = 0x70;
pub const BPF_JSLT: u8 = 0xc0;
pub const BPF_JSLE: u8 = 0xd0;

/* jmp special */
pub const BPF_CALL: u8 = 0x80; // call imm
pub const BPF_EXIT: u8 = 0x90; // exit

pub const BPF_FETCH: u8 = 0x01;
pub const BPF_XCHG: u8 = 0xe0 | BPF_FETCH;
pub const BPF_CMPXCHG: u8 = 0xf0 | BPF_FETCH;

#[repr(C)]
#[derive(Default, Clone)]
pub struct EbpfInsn {
    pub code: u8,
    /// u8 dst_reg:4;
    /// u8 src_reg:4;
    pub regs: u8,
    pub off: i16,
    pub imm: i32,
}

impl EbpfInsn {
    pub fn new(code: u8, dst_reg: u8, src_reg: u8, off: i16, imm: i32) -> Self {
        let regs = (dst_reg << 4) | src_reg;
        Self {
            code,
            regs,
            off,
            imm,
        }
    }

    pub fn as_bin(&self) -> &[u8] {
        unsafe {
            let bptr = self as *const Self as *const u8;
            let bsize = std::mem::size_of_val(self);
            std::slice::from_raw_parts(bptr, bsize)
        }
    }
}

use std::fmt;

impl fmt::Debug for EbpfInsn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EbpfInsn")
            .field("code", &format!("{:02x}", self.code))
            .field("regs", &format!("{:02x}", self.regs))
            .field("off", &self.off)
            .field("imm", &self.imm)
            .finish()
    }
}
