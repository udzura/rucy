extern crate rucy_mruby_sys_consts;

use rucy_mruby_sys_consts::*;

use std::{fmt, rc::Rc};

#[derive(Debug, Default, Clone)]
pub struct OpCode {
    pub syms: Rc<Vec<u32>>,

    pub code: rucy_mruby_sys_consts::MRB_INSN,
    pub bin: String,
    pub idx: usize,
    pub pc_base: usize,
    pub b1: Option<u8>,
    pub b2: Option<u8>,
    pub b3: Option<u8>,
    pub s1: Option<u16>,
    pub s2: Option<u16>,
    pub w: Option<[u8; 24]>,
}

impl fmt::Display for OpCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "<{} ", self.debug_opname())?;
        if let Some(v) = self.b1 {
            write!(f, "B1={} ", v)?;
        }
        if let Some(v) = self.b2 {
            write!(f, "B2={} ", v)?;
        }
        if let Some(v) = self.b3 {
            write!(f, "B3={} ", v)?;
        }
        if let Some(v) = self.s1 {
            write!(f, "S1={} ", v)?;
        }
        if let Some(v) = self.s2 {
            write!(f, "S2={} ", v)?;
        }
        if let Some(v) = self.w {
            write!(f, "W={:?} ", v)?;
        }
        write!(f, "pc={}", self.pc_base)?;

        write!(f, ">")
    }
}

impl OpCode {
    pub fn opname(&self) -> &'static str {
        opcode_from_u32(self.code)
    }

    pub fn operand_type(&self) -> &'static str {
        match resolve_operand(self.code) {
            Z => "Z",
            B => "B",
            BB => "BB",
            BBB => "BBB",
            BS => "BS",
            BSS => "BSS",
            S => "S",
            W => "W",
            _ => "unknown",
        }
    }

    pub fn debug_opname(&self) -> String {
        format!(
            "{:03}: {}({}:{})",
            self.idx,
            self.opname(),
            self.operand_type(),
            self.bin
        )
    }
}

pub fn process(insns: &[u8]) -> Vec<OpCode> {
    let mut ret: Vec<OpCode> = vec![];
    let mut i: usize = 0;
    let end = insns.len();

    while i < end {
        let insn = insns[i] as MRB_INSN;

        let mut op = OpCode {
            code: insn,
            idx: i,
            ..Default::default()
        };
        i += 1;
        let operand = resolve_operand(insn);
        match operand {
            Z => {
                op.bin = format!("{:02x}", insn);
            }
            B => {
                op.bin = format!("{:02x} {:02x}", insn, insns[i]);
                op.b1 = insns[i].into();
                i += 1;
            }
            BB => {
                op.bin = format!("{:02x} {:02x} {:02x}", insn, insns[i], insns[i + 1]);
                op.b1 = insns[i].into();
                op.b2 = insns[i + 1].into();
                i += 2;
            }
            BBB => {
                op.bin = format!(
                    "{:02x} {:02x} {:02x} {:02x}",
                    insn,
                    insns[i],
                    insns[i + 1],
                    insns[i + 2]
                );
                op.b1 = insns[i].into();
                op.b2 = insns[i + 1].into();
                op.b3 = insns[i + 2].into();
                i += 3;
            }
            BS => {
                op.bin = format!(
                    "{:02x} {:02x} {:02x} {:02x}",
                    insn,
                    insns[i],
                    insns[i + 1],
                    insns[i + 2]
                );
                op.b1 = insns[i].into();
                op.s1 = (insns[i + 2] as u16 | (insns[i + 1] as u16) << 8).into();
                i += 3;
            }
            BSS => {
                op.bin = format!(
                    "{:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
                    insn,
                    insns[i],
                    insns[i + 1],
                    insns[i + 2],
                    insns[i + 3],
                    insns[i + 4]
                );
                op.b1 = insns[i].into();
                op.s1 = (insns[i + 2] as u16 | (insns[i + 1] as u16) << 8).into();
                op.s2 = (insns[i + 4] as u16 | (insns[i + 3] as u16) << 8).into();
                i += 5;
            }
            S => {
                op.bin = format!("{:02x} {:02x} {:02x}", insn, insns[i], insns[i + 1]);
                op.s1 = (insns[i + 1] as u16 | (insns[i] as u16) << 8).into();
                i += 2;
            }
            W => {
                op.bin = format!(
                    "{:02x} {:02x} {:02x} {:02x}",
                    insn,
                    insns[i],
                    insns[i + 1],
                    insns[i + 2]
                );
                let mut w: [u8; 24] = Default::default();
                for j in 0..3 {
                    w[j] = (insns[i] >> (3 - j)) & 1;
                    w[j + 4] = (insns[i + 1] >> (3 - j)) & 1;
                    w[j + 8] = (insns[i + 2] >> (3 - j)) & 1;
                }

                op.w = Some(w);
                i += 3;
            }
            _ => {
                panic!("invalid operand code: {:?}", operand);
            }
        }
        op.pc_base = i;

        ret.push(op);
    }

    ret
}
