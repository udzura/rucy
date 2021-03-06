use std::collections::HashMap;
use std::convert::TryInto;
use std::ffi::CStr;
use std::ffi::CString;

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

pub struct Chunk {
    mruby: MrubyType,
    // rproc: *const ffi::MrProc,
    pub root: Irep,
    pub struct_def: Option<Irep>,
    pub prog_def: Option<Irep>,

    pub section_name: CString,
    pub prog_name: CString,
    pub license: CString,
}

#[derive(Debug)]
pub struct Irep {
    irep: *const ffi::MrIrep,

    pub subreps: Vec<*const ffi::MrIrep>,
    pub lv: Vec<CString>,
    pub syms: Vec<CString>,
    pub insns: Vec<u8>,
    pub ops: Vec<OpCode>,
    pub nregs: u16,
}

impl Chunk {
    pub fn new(mruby: MrubyType, rproc: *const ffi::MrProc) -> Self {
        let irep = unsafe { ffi::mrb_ext_irep_from_rproc(rproc) };
        let root = unsafe { Irep::new(mruby.clone(), irep) };

        let mut ret = Self {
            mruby,
            // rproc,
            root,
            struct_def: None,
            prog_def: None,
            section_name: CString::new("").unwrap(),
            prog_name: CString::new("").unwrap(),
            license: CString::new("").unwrap(),
        };
        ret.walk_root_insn();

        ret
    }

    pub fn args(&self) -> Vec<Box<[ProgArg]>> {
        match &self.struct_def {
            Some(def) => {
                let args = def.as_args().unwrap().into_boxed_slice();
                vec![args]
            }
            None => {
                vec![]
            }
        }
    }

    pub fn walk_root_insn(&mut self) {
        let oplen = self.root.ops.len();
        let mut i = 0;
        while i < oplen {
            let op = &self.root.ops[i];
            match op.code {
                MRB_INSN_OP_STRING => {
                    let strval = self.root.get_string_instance(op.b2.unwrap());

                    i += 1;
                    let nop = &self.root.ops[i];
                    if nop.code == MRB_INSN_OP_SEND {
                        let meth = &self.root.syms[nop.b2.unwrap() as usize];
                        match meth.to_str().unwrap() {
                            "license!" => {
                                self.license = strval;
                            }
                            "section!" => {
                                self.section_name = strval;
                            }
                            _ => {
                                panic!("Invalid DSL: {:?}", meth);
                            }
                        }
                    }
                }
                MRB_INSN_OP_EXEC => {
                    let rep = self.root.subreps[op.b2.unwrap() as usize];
                    let rep = unsafe { Irep::new(self.mruby.clone(), rep) };
                    self.struct_def = Some(rep);
                }
                MRB_INSN_OP_METHOD => {
                    let rep = self.root.subreps[op.b2.unwrap() as usize];
                    let rep = unsafe { Irep::new(self.mruby.clone(), rep) };
                    self.prog_def = Some(rep);
                }
                MRB_INSN_OP_DEF => {
                    let strval = &self.root.syms[op.b2.unwrap() as usize];
                    self.prog_name = strval.to_owned();
                }
                _ => {}
            }
            i += 1;
        }
    }
}

impl Irep {
    pub unsafe fn new(mruby: MrubyType, irep: *const ffi::MrIrep) -> Self {
        let irep_ = std::mem::transmute::<*const ffi::MrIrep, &ffi::MrIrep>(irep);

        let subreps = std::slice::from_raw_parts(irep_.reps, irep_.rlen as usize).to_vec();
        let lv = std::slice::from_raw_parts(irep_.lv, (irep_.nlocals - 1) as usize).to_vec();
        let lv = lv
            .into_iter()
            .map(|sym| CStr::from_ptr(ffi::mrb_sym_dump(mruby.borrow().mrb, sym)).into())
            .collect();
        let syms = std::slice::from_raw_parts(irep_.syms, irep_.slen as usize).to_vec();
        let syms = syms
            .into_iter()
            .map(|sym| CStr::from_ptr(ffi::mrb_sym_dump(mruby.borrow().mrb, sym)).into())
            .collect();
        let insns = std::slice::from_raw_parts(irep_.iseq, irep_.ilen as usize).to_vec();

        let nregs = irep_.nregs;

        let ops = crate::bytecode::process(&insns);
        Self {
            irep,
            subreps,
            lv,
            syms,
            insns,
            ops,
            nregs,
        }
    }

    pub fn get_string_instance(&self, index: u8) -> CString {
        unsafe { CStr::from_ptr(ffi::mrb_ext_str_from_pool(self.irep, index as usize)) }.to_owned()
    }

    pub fn as_args(&self) -> Result<Vec<ProgArg>, Box<dyn std::error::Error>> {
        let mut ret = vec![];
        let len = self.ops.len();
        let mut off: i16 = 0;
        let mut i = 0usize;

        while i < len {
            let op = &self.ops[i];
            match op.code {
                MRB_INSN_OP_LOADSYM => {
                    let op2 = &self.ops[i + 1];
                    if op2.code != MRB_INSN_OP_LOADSYM {
                        continue;
                    }
                    i += 1;
                    let op3 = &self.ops[i + 1];
                    if op3.code != MRB_INSN_OP_SEND {
                        continue;
                    }
                    if (&self.syms[op3.b2.unwrap() as usize]).to_str().unwrap() != "attr" {
                        continue;
                    }
                    i += 1;

                    let member_name = &self.syms[op.b2.unwrap() as usize];
                    let member_type = &self.syms[op2.b2.unwrap() as usize];

                    let arg = ProgArg::new(
                        off,
                        member_name.to_str().unwrap().to_string(),
                        member_type.to_str().unwrap(),
                    );
                    off = (&arg).next_offset;
                    ret.push(arg);
                }
                _ => {}
            }

            i += 1;
        }
        Ok(ret)
    }

    pub fn translate(
        &self,
        args: Box<[Box<[ProgArg]>]>,
    ) -> Result<Vec<EbpfInsn>, Box<dyn std::error::Error>> {
        let mut ret = vec![];
        let return_reg = 0;
        let nregs = self.nregs;
        let len = self.ops.len();
        let mut i = 0usize;

        let mut lv_maps: HashMap<u8, String> = HashMap::new();

        let mut labels: Vec<Label> = vec![];

        for (i, v) in self.lv.iter().enumerate() {
            if v.to_str().unwrap() != "&" {
                lv_maps.insert((i + 1) as u8, v.to_str()?.to_owned());
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
                    // eval only on final op_return
                    if i + 1 == len {
                        let code = BPF_ALU64 | BPF_X | BPF_MOV;
                        let bpf = EbpfInsn::new(code, return_reg, op.b1.unwrap(), 0, 0);
                        ret.push(bpf);

                        let code = BPF_JMP | BPF_EXIT;
                        let bpf = EbpfInsn::new(code, 0, 0, 0, 0);
                        ret.push(bpf);
                    }
                }
                MRB_INSN_OP_MOVE => {
                    if lv_maps.keys().any(|k| *k == (op.b2.unwrap())) {
                        let lname = lv_maps.get(&op.b2.unwrap()).unwrap().to_owned();
                        lv_maps.insert(op.b1.unwrap(), lname);
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
                MRB_INSN_OP_LOADSELF => { /* TODO: mark self register */ }
                MRB_INSN_OP_STRING => {
                    // generate bytearray
                    let mut chars = self.get_string_instance(op.b2.unwrap());
                    let mut padlen = chars.as_bytes().len() % 8;
                    if padlen != 0 {
                        padlen = 8 - padlen;
                    }
                    let mut chars = chars.as_bytes().to_vec();
                    let len = chars.len();
                    chars.resize_with(len + padlen, || 0u8);

                    let len = chars.len();
                    let mut i = 0;
                    let mut charreps: Vec<u64> = vec![];
                    while i < len {
                        let mut charrep = 0u64;
                        for j in 0..8 {
                            charrep = charrep | (chars[i] as u64) << (j * 8);
                            i += 1;
                        }
                        charreps.push(charrep);
                    }
                    dbg!(&charreps);

                    let mut memoff = 0i16;
                    for crep in charreps.iter().rev() {
                        let code = BPF_LD | BPF_DW;
                        let imm = (*crep) as i64;
                        // r(B1) = imm as ll
                        let lddw = EbpfInsn::new64(code, op.b1.unwrap(), 0, 0, imm);
                        ret.push(lddw.0);
                        ret.push(lddw.1);

                        memoff -= 8;
                        let off = memoff;
                        let code = BPF_STX | BPF_DW | BPF_MEM;
                        // frame pointer
                        let dst_reg = 10;
                        // *(u64 *)(r10 - memoff) = r(B1)
                        let bpf = EbpfInsn::new(code, dst_reg, op.b1.unwrap(), off, 0);
                        ret.push(bpf);
                    }
                    // r(B1) = r10
                    let code = BPF_ALU64 | BPF_X | BPF_MOV;
                    let dst = op.b1.unwrap();
                    let src = 10;
                    let bpf = EbpfInsn::new(code, dst, src, 0, 0);
                    ret.push(bpf);

                    // r(B1) -= current_memoff
                    let code = BPF_ALU64 | BPF_K | BPF_ADD;
                    let dst = op.b1.unwrap();
                    let src = 0;
                    let off = memoff as i32;
                    let bpf = EbpfInsn::new(code, dst, src, 0, off);
                    ret.push(bpf);
                }
                MRB_INSN_OP_SEND => {
                    let symname = self.syms.get(op.b2.unwrap() as usize).unwrap();
                    let symname = symname.to_str()?.to_owned();

                    if let Some(idx) = bpf_helper_to_u32(&symname) {
                        let argsize = op.b3.unwrap();
                        let maxreg = (self.nregs - 2) as u8;
                        let mut dst = maxreg + 1;
                        for i in 0..argsize {
                            // Skip becatse R2 is not used on mruby..
                            if i == 1 {
                                continue;
                            };
                            // R(maxreg + i + 1) = R(i + 1)
                            let code = BPF_ALU64 | BPF_X | BPF_MOV;
                            let src = i + 1;
                            let bpf = EbpfInsn::new(code, dst, src, 0, 0);
                            ret.push(bpf);
                            dst += 1;
                        }

                        for i in 0..argsize {
                            // R(i + 1) = R(b1 + i + 1)
                            let code = BPF_ALU64 | BPF_X | BPF_MOV;
                            let dst = i + 1;
                            let src = op.b1.unwrap() + i + 1;
                            let bpf = EbpfInsn::new(code, dst, src, 0, 0);
                            ret.push(bpf);
                        }

                        let code = BPF_JMP | BPF_CALL;
                        let imm = idx as i32;
                        let bpf = EbpfInsn::new(code, 0, 0, 0, imm);
                        ret.push(bpf);

                        let mut src = maxreg + 1;
                        for i in 0..argsize {
                            if i == 1 {
                                continue;
                            };
                            // R(i + 1) = R(maxreg + i + 1)
                            let code = BPF_ALU64 | BPF_X | BPF_MOV;
                            let dst = i + 1;
                            let bpf = EbpfInsn::new(code, dst, src, 0, 0);
                            ret.push(bpf);
                            src += 1;
                        }
                    } else {
                        let varname = lv_maps.get(&op.b1.unwrap()).unwrap().to_owned();

                        lv_maps.remove(&op.b1.unwrap());

                        let (n, _) = self
                            .lv
                            .iter()
                            .enumerate()
                            .find(|(_, name)| (*name).to_str().unwrap() == varname.as_str())
                            .unwrap();
                        let off = self.calculate_struct_offset(&args, n, &symname);
                        let code = BPF_LDX | BPF_W | BPF_MEM;
                        let bpf = EbpfInsn::new(code, op.b1.unwrap(), op.b1.unwrap(), off, 0);
                        ret.push(bpf);
                    }
                }
                _ => {
                    unimplemented!("Not yet supported");
                }
            }
            i += 1;
        }

        for label in labels.into_iter() {
            let bpf = ret.get_mut(label.bpf_src_pc).unwrap();
            let src = label.bpf_src_pc as i16;
            let dest = label.bpf_target_pc.unwrap() as i16;
            bpf.off = dest - src - 1;
        }

        Ok(ret)
    }

    fn calculate_struct_offset(
        &self,
        args: &Box<[Box<[ProgArg]>]>,
        n: usize,
        symname: &str,
    ) -> i16 {
        let arg = args.get(n).expect("invalid local var");
        let off = arg
            .iter()
            .find(|a| a.name == symname)
            .expect("invalid member name");
        off.offset
    }
}
