use std::collections::HashMap;

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

            let lv_len = lv.len() as u8;
            regs_maps.insert(lv_len + 1, 0);
            for r in 0..lv_len {
                regs_maps.insert(r + 1, r + 1);
            }

            Self {
                lv,
                syms,
                ops,
                regs_maps,
            }
        }
    }

    fn bpf_reg(&self, mreg: Option<u8>) -> u8 {
        *self.regs_maps.get(&mreg.unwrap()).unwrap()
    }

    pub fn translate(&self) -> Result<Vec<EbpfInsn>, Box<dyn std::error::Error>> {
        let mut ret = vec![];

        for op in self.ops.iter() {
            match op.code {
                MRB_INSN_OP_ENTER => { /* skip, TODO get var size */ }
                MRB_INSN_OP_LOADI_0 => {
                    let code = BPF_ALU64 | BPF_K | BPF_MOV;
                    let imm = 0;
                    let bpf = EbpfInsn::new(code, self.bpf_reg(op.b1), 0, 0, imm);
                    ret.push(bpf);
                }
                MRB_INSN_OP_LOADI_1 => {
                    let code = BPF_ALU64 | BPF_K | BPF_MOV;
                    let imm = 1;
                    let bpf = EbpfInsn::new(code, self.bpf_reg(op.b1), 0, 0, imm);
                    ret.push(bpf);
                }
                // ...
                MRB_INSN_OP_RETURN_BLK => { /* skip */ }
                MRB_INSN_OP_RETURN => {
                    let code = BPF_JMP | BPF_EXIT;
                    let bpf = EbpfInsn::new(code, 0, 0, 0, 0);
                    ret.push(bpf);
                }
                _ => {
                    unimplemented!("Not yet supported");
                }
            }
        }

        Ok(ret)
    }
}
