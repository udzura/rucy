use std::collections::HashMap;
use std::convert::TryInto;

use mrusty::mruby_ffi as ffi;
use mrusty::{MrubyType, Value};

use rucy_mruby_sys_consts::*;

use crate::bpf::*;
use crate::bytecode::{self, OpCode};
use crate::MrustyValueExt;

pub struct MrubyChunk {
    pub lv: Vec<Value>,
    pub syms: Vec<Value>,
    pub ops: Vec<OpCode>,

    pub regs_maps: HashMap<u8, u8>,
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

            let mut regs_maps = HashMap::new();

            // let lv_len = lv.len() as u8;
            // regs_maps.insert(lv_len + 1, 0);
            // for r in 0..lv_len {
            //     regs_maps.insert(r + 1, r + 1);
            // }

            Self {
                lv,
                syms,
                ops,
                regs_maps,
            }
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

        while i < len {
            let op = &self.ops[i];
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
                    i += 1;
                    let nextop = &self.ops[i];
                    match nextop.code {
                        MRB_INSN_OP_JMPIF => {
                            // if rX == rY goto L1
                            let code = BPF_JMP | BPF_K | BPF_JEQ;
                            // TODO: calc offset
                            let bpf = EbpfInsn::new(code, op.b1.unwrap(), op.b2.unwrap(), 0 + 2, 0);
                            ret.push(bpf);
                        }
                        MRB_INSN_OP_JMPNOT => {
                            // if rX != rY goto L1
                            let code = BPF_JMP | BPF_K | BPF_JNE;
                            // TODO: calc offset
                            let bpf = EbpfInsn::new(code, op.b1.unwrap(), op.b2.unwrap(), 0 + 2, 0);
                            ret.push(bpf);
                        }
                        _ => {
                            unimplemented!("Not yet supported");
                        }
                    }
                }
                MRB_INSN_OP_JMP => {
                    // if true goto L2
                    let code = BPF_JMP | BPF_K | BPF_JA;
                    // TODO: calc offset
                    let bpf = EbpfInsn::new(code, 0, 0, 0 + 1, 0);
                    ret.push(bpf);
                }
                MRB_INSN_OP_SEND => {
                    // TODO: define and calc strust offset
                    let off = 8;
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

        Ok(ret)
    }
}
