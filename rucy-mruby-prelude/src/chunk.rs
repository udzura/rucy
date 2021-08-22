use std::collections::HashMap;
use std::convert::TryInto;

use mrusty::mruby_ffi as ffi;
use mrusty::{MrubyType, Value};

use rucy_mruby_sys_consts::*;

use crate::bpf::*;
use crate::bytecode::{self, OpCode};
use crate::MrustyValueExt;

#[derive(Debug)]
pub struct Label {
    pub mruby_target_pc: u16,
    pub bpf_src_pc: usize,
    pub bpf_target_pc: Option<usize>,
}

pub struct MrubyChunk {
    pub lv: Vec<Value>,
    pub syms: Vec<Value>,
    pub ops: Vec<OpCode>,
}

impl MrubyChunk {
    pub fn new(mruby: MrubyType, proc: Value) -> Self {
        if proc.as_mrb_value().typ != ffi::MrType::MRB_TT_PROC {
            panic!("Require Proc value");
        }
        unsafe {
            let rproc = ffi::mrb_ext_proc_ptr(mruby.borrow().mrb, *proc.as_mrb_value());

            let lv = ffi::mrb_ext_get_locals_from_proc(mruby.borrow().mrb, rproc);
            let lv = Value::new(mruby.clone(), lv).to_vec().unwrap();

            let syms = ffi::mrb_ext_get_syms_from_proc(mruby.borrow().mrb, rproc);
            let syms = Value::new(mruby.clone(), syms).to_vec().unwrap();

            let p = ffi::mrb_ext_get_insns_from_proc(rproc);
            let len = ffi::mrb_ext_get_insns_len_from_proc(rproc);
            let insns: &[u8] = std::slice::from_raw_parts(p, len);
            let ops = bytecode::process(insns);

            Self { lv, syms, ops }
        }
    }

    // fn bpf_reg(&self, mreg: Option<u8>) -> u8 {
    //     *self.regs_maps.get(&mreg.unwrap()).unwrap()
    // }

    pub fn translate(&self) -> Result<Vec<EbpfInsn>, Box<dyn std::error::Error>> {
        let mut ret = vec![];
        let return_reg = 0;
        let len = self.ops.len();
        let mut i = 0usize;

        let mut lv_maps: HashMap<u8, String> = HashMap::new();

        let mut labels: Vec<Label> = vec![];

        for (i, v) in self.lv.iter().enumerate() {
            if v.to_str().unwrap() != "&" {
                lv_maps.insert((i + 1) as u8, v.to_str()?.to_owned());
                dbg!(&lv_maps);
            }
        }

        while i < len {
            let op = &self.ops[i];
            let bpf_pc = (&ret).len();

            if let Some(label) = labels
                .iter_mut()
                .find(|l| (*l).mruby_target_pc == (op.idx as u16))
            {
                label.bpf_target_pc = Some(bpf_pc);
            }

            match op.code {
                MRB_INSN_OP_ENTER => { /* skip, TODO get var size */ }
                MRB_INSN_OP_LOADI_0 => {
                    let code = BPF_ALU64 | BPF_K | BPF_MOV;
                    let imm = 0;
                    let bpf = EbpfInsn::new(code, op.b1.unwrap(), 0, 0, imm);
                    ret.push(bpf);
                }
                MRB_INSN_OP_LOADI_1 => {
                    let code = BPF_ALU64 | BPF_K | BPF_MOV;
                    let imm = 1;
                    let bpf = EbpfInsn::new(code, op.b1.unwrap(), 0, 0, imm);
                    ret.push(bpf);
                }
                // ...
                MRB_INSN_OP_RETURN_BLK => { /* skip */ }
                MRB_INSN_OP_RETURN => {
                    let code = BPF_ALU64 | BPF_X | BPF_MOV;
                    let bpf = EbpfInsn::new(code, return_reg, op.b1.unwrap(), 0, 0);
                    ret.push(bpf);

                    let code = BPF_JMP | BPF_EXIT;
                    let bpf = EbpfInsn::new(code, 0, 0, 0, 0);
                    ret.push(bpf);
                }
                MRB_INSN_OP_MOVE => {
                    if lv_maps.keys().any(|k| *k == (op.b2.unwrap())) {
                        let lname = lv_maps.get(&op.b2.unwrap()).unwrap().to_owned();
                        lv_maps.insert(op.b1.unwrap(), lname);
                        dbg!(&lv_maps);
                    }

                    let code = BPF_ALU64 | BPF_X | BPF_MOV;
                    let bpf = EbpfInsn::new(code, op.b1.unwrap(), op.b2.unwrap(), 0, 0);
                    ret.push(bpf);
                }
                MRB_INSN_OP_LOADI => {
                    let code = BPF_ALU64 | BPF_K | BPF_MOV;
                    let imm = op.b2.unwrap() as i32;
                    let bpf = EbpfInsn::new(code, op.b1.unwrap(), 0, 0, imm);
                    ret.push(bpf);
                }
                MRB_INSN_OP_LOADI16 => {
                    let code = BPF_ALU64 | BPF_K | BPF_MOV;
                    let imm = op.s1.unwrap() as i32;
                    let bpf = EbpfInsn::new(code, op.b1.unwrap(), 0, 0, imm);
                    ret.push(bpf);
                }
                MRB_INSN_OP_EQ => {
                    // rB1 = rB1 - r(B1+1)
                    // Then judge rB1 either 0 or not
                    let code = BPF_ALU64 | BPF_X | BPF_SUB;
                    let bpf = EbpfInsn::new(code, op.b1.unwrap(), op.b1.unwrap() + 1, 0, 0);
                    ret.push(bpf);
                }
                MRB_INSN_OP_JMPIF => {
                    let label = Label {
                        mruby_target_pc: op.s1.unwrap() + (op.pc_base as u16),
                        bpf_src_pc: bpf_pc,
                        bpf_target_pc: None,
                    };
                    labels.push(label);

                    // if rX == 0 goto L1
                    let code = BPF_JMP | BPF_K | BPF_JEQ;
                    let imm = 0;
                    let bpf = EbpfInsn::new(code, op.b1.unwrap(), 0, 0, imm);
                    ret.push(bpf);
                }
                MRB_INSN_OP_JMPNOT => {
                    let label = Label {
                        mruby_target_pc: op.s1.unwrap() + (op.pc_base as u16),
                        bpf_src_pc: bpf_pc,
                        bpf_target_pc: None,
                    };
                    labels.push(label);

                    // if rX != 0 goto L1
                    let code = BPF_JMP | BPF_K | BPF_JNE;
                    let imm = 0;
                    let bpf = EbpfInsn::new(code, op.b1.unwrap(), 0, 0, imm);
                    ret.push(bpf);
                }
                MRB_INSN_OP_JMP => {
                    let label = Label {
                        mruby_target_pc: op.s1.unwrap() + (op.pc_base as u16),
                        bpf_src_pc: bpf_pc,
                        bpf_target_pc: None,
                    };
                    labels.push(label);
                    // if true goto L2
                    let code = BPF_JMP | BPF_K | BPF_JA;
                    // TODO: calc offset

                    let bpf = EbpfInsn::new(code, 0, 0, 0, 0);
                    ret.push(bpf);
                }
                MRB_INSN_OP_SEND => {
                    // TODO: define and calc strust offset
                    let varname = lv_maps.get(&op.b1.unwrap()).unwrap().to_owned();
                    let symname = self.syms.get(op.b2.unwrap() as usize).unwrap();
                    let symname = symname.to_str()?.to_owned();
                    dbg!(&varname, &symname);

                    lv_maps.remove(&op.b1.unwrap());
                    dbg!(&lv_maps);

                    let off = self.calculate_struct_offset(&varname, &symname);
                    let code = BPF_LDX | BPF_W | BPF_MEM;
                    let bpf = EbpfInsn::new(code, op.b1.unwrap(), op.b1.unwrap(), off, 0);
                    ret.push(bpf);
                }
                _ => {
                    unimplemented!("Not yet supported");
                }
            }
            i += 1;
        }
        dbg!(&labels);

        for label in labels.into_iter() {
            let bpf = ret.get_mut(label.bpf_src_pc).unwrap();
            let src = label.bpf_src_pc as i16;
            let dest = label.bpf_target_pc.unwrap() as i16;
            bpf.off = dest - src - 1;
        }

        Ok(ret)
    }

    fn calculate_struct_offset(&self, varname: &str, symname: &str) -> i16 {
        if varname == "ctx" && symname == "minor" {
            8
        } else if varname == "ctx" && symname == "major" {
            4
        } else {
            unimplemented!("TODO: parse struct info from mruby and store it")
        }
    }
}
