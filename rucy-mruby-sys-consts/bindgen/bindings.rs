/* automatically generated by rust-bindgen 0.58.1 */

pub const Z: u32 = 0;
pub const B: u32 = 1;
pub const BB: u32 = 2;
pub const BBB: u32 = 3;
pub const BS: u32 = 4;
pub const BSS: u32 = 5;
pub const S: u32 = 6;
pub const W: u32 = 7;
pub const MRB_INSN_OP_NOP: MRB_INSN = 0;
pub const MRB_INSN_OP_MOVE: MRB_INSN = 1;
pub const MRB_INSN_OP_LOADL: MRB_INSN = 2;
pub const MRB_INSN_OP_LOADL16: MRB_INSN = 3;
pub const MRB_INSN_OP_LOADI: MRB_INSN = 4;
pub const MRB_INSN_OP_LOADINEG: MRB_INSN = 5;
pub const MRB_INSN_OP_LOADI__1: MRB_INSN = 6;
pub const MRB_INSN_OP_LOADI_0: MRB_INSN = 7;
pub const MRB_INSN_OP_LOADI_1: MRB_INSN = 8;
pub const MRB_INSN_OP_LOADI_2: MRB_INSN = 9;
pub const MRB_INSN_OP_LOADI_3: MRB_INSN = 10;
pub const MRB_INSN_OP_LOADI_4: MRB_INSN = 11;
pub const MRB_INSN_OP_LOADI_5: MRB_INSN = 12;
pub const MRB_INSN_OP_LOADI_6: MRB_INSN = 13;
pub const MRB_INSN_OP_LOADI_7: MRB_INSN = 14;
pub const MRB_INSN_OP_LOADI16: MRB_INSN = 15;
pub const MRB_INSN_OP_LOADI32: MRB_INSN = 16;
pub const MRB_INSN_OP_LOADSYM: MRB_INSN = 17;
pub const MRB_INSN_OP_LOADSYM16: MRB_INSN = 18;
pub const MRB_INSN_OP_LOADNIL: MRB_INSN = 19;
pub const MRB_INSN_OP_LOADSELF: MRB_INSN = 20;
pub const MRB_INSN_OP_LOADT: MRB_INSN = 21;
pub const MRB_INSN_OP_LOADF: MRB_INSN = 22;
pub const MRB_INSN_OP_GETGV: MRB_INSN = 23;
pub const MRB_INSN_OP_SETGV: MRB_INSN = 24;
pub const MRB_INSN_OP_GETSV: MRB_INSN = 25;
pub const MRB_INSN_OP_SETSV: MRB_INSN = 26;
pub const MRB_INSN_OP_GETIV: MRB_INSN = 27;
pub const MRB_INSN_OP_SETIV: MRB_INSN = 28;
pub const MRB_INSN_OP_GETCV: MRB_INSN = 29;
pub const MRB_INSN_OP_SETCV: MRB_INSN = 30;
pub const MRB_INSN_OP_GETCONST: MRB_INSN = 31;
pub const MRB_INSN_OP_SETCONST: MRB_INSN = 32;
pub const MRB_INSN_OP_GETMCNST: MRB_INSN = 33;
pub const MRB_INSN_OP_SETMCNST: MRB_INSN = 34;
pub const MRB_INSN_OP_GETUPVAR: MRB_INSN = 35;
pub const MRB_INSN_OP_SETUPVAR: MRB_INSN = 36;
pub const MRB_INSN_OP_JMP: MRB_INSN = 37;
pub const MRB_INSN_OP_JMPIF: MRB_INSN = 38;
pub const MRB_INSN_OP_JMPNOT: MRB_INSN = 39;
pub const MRB_INSN_OP_JMPNIL: MRB_INSN = 40;
pub const MRB_INSN_OP_JMPUW: MRB_INSN = 41;
pub const MRB_INSN_OP_EXCEPT: MRB_INSN = 42;
pub const MRB_INSN_OP_RESCUE: MRB_INSN = 43;
pub const MRB_INSN_OP_RAISEIF: MRB_INSN = 44;
pub const MRB_INSN_OP_SENDV: MRB_INSN = 45;
pub const MRB_INSN_OP_SENDVB: MRB_INSN = 46;
pub const MRB_INSN_OP_SEND: MRB_INSN = 47;
pub const MRB_INSN_OP_SENDB: MRB_INSN = 48;
pub const MRB_INSN_OP_SENDVK: MRB_INSN = 49;
pub const MRB_INSN_OP_CALL: MRB_INSN = 50;
pub const MRB_INSN_OP_SUPER: MRB_INSN = 51;
pub const MRB_INSN_OP_ARGARY: MRB_INSN = 52;
pub const MRB_INSN_OP_ENTER: MRB_INSN = 53;
pub const MRB_INSN_OP_KEY_P: MRB_INSN = 54;
pub const MRB_INSN_OP_KEYEND: MRB_INSN = 55;
pub const MRB_INSN_OP_KARG: MRB_INSN = 56;
pub const MRB_INSN_OP_RETURN: MRB_INSN = 57;
pub const MRB_INSN_OP_RETURN_BLK: MRB_INSN = 58;
pub const MRB_INSN_OP_BREAK: MRB_INSN = 59;
pub const MRB_INSN_OP_BLKPUSH: MRB_INSN = 60;
pub const MRB_INSN_OP_ADD: MRB_INSN = 61;
pub const MRB_INSN_OP_ADDI: MRB_INSN = 62;
pub const MRB_INSN_OP_SUB: MRB_INSN = 63;
pub const MRB_INSN_OP_SUBI: MRB_INSN = 64;
pub const MRB_INSN_OP_MUL: MRB_INSN = 65;
pub const MRB_INSN_OP_DIV: MRB_INSN = 66;
pub const MRB_INSN_OP_EQ: MRB_INSN = 67;
pub const MRB_INSN_OP_LT: MRB_INSN = 68;
pub const MRB_INSN_OP_LE: MRB_INSN = 69;
pub const MRB_INSN_OP_GT: MRB_INSN = 70;
pub const MRB_INSN_OP_GE: MRB_INSN = 71;
pub const MRB_INSN_OP_ARRAY: MRB_INSN = 72;
pub const MRB_INSN_OP_ARRAY2: MRB_INSN = 73;
pub const MRB_INSN_OP_ARYCAT: MRB_INSN = 74;
pub const MRB_INSN_OP_ARYPUSH: MRB_INSN = 75;
pub const MRB_INSN_OP_ARYDUP: MRB_INSN = 76;
pub const MRB_INSN_OP_AREF: MRB_INSN = 77;
pub const MRB_INSN_OP_ASET: MRB_INSN = 78;
pub const MRB_INSN_OP_APOST: MRB_INSN = 79;
pub const MRB_INSN_OP_INTERN: MRB_INSN = 80;
pub const MRB_INSN_OP_STRING: MRB_INSN = 81;
pub const MRB_INSN_OP_STRING16: MRB_INSN = 82;
pub const MRB_INSN_OP_STRCAT: MRB_INSN = 83;
pub const MRB_INSN_OP_HASH: MRB_INSN = 84;
pub const MRB_INSN_OP_HASHADD: MRB_INSN = 85;
pub const MRB_INSN_OP_HASHCAT: MRB_INSN = 86;
pub const MRB_INSN_OP_LAMBDA: MRB_INSN = 87;
pub const MRB_INSN_OP_LAMBDA16: MRB_INSN = 88;
pub const MRB_INSN_OP_BLOCK: MRB_INSN = 89;
pub const MRB_INSN_OP_BLOCK16: MRB_INSN = 90;
pub const MRB_INSN_OP_METHOD: MRB_INSN = 91;
pub const MRB_INSN_OP_METHOD16: MRB_INSN = 92;
pub const MRB_INSN_OP_RANGE_INC: MRB_INSN = 93;
pub const MRB_INSN_OP_RANGE_EXC: MRB_INSN = 94;
pub const MRB_INSN_OP_OCLASS: MRB_INSN = 95;
pub const MRB_INSN_OP_CLASS: MRB_INSN = 96;
pub const MRB_INSN_OP_MODULE: MRB_INSN = 97;
pub const MRB_INSN_OP_EXEC: MRB_INSN = 98;
pub const MRB_INSN_OP_EXEC16: MRB_INSN = 99;
pub const MRB_INSN_OP_DEF: MRB_INSN = 100;
pub const MRB_INSN_OP_ALIAS: MRB_INSN = 101;
pub const MRB_INSN_OP_UNDEF: MRB_INSN = 102;
pub const MRB_INSN_OP_SCLASS: MRB_INSN = 103;
pub const MRB_INSN_OP_TCLASS: MRB_INSN = 104;
pub const MRB_INSN_OP_DEBUG: MRB_INSN = 105;
pub const MRB_INSN_OP_ERR: MRB_INSN = 106;
pub const MRB_INSN_OP_STOP: MRB_INSN = 107;
pub type MRB_INSN = ::std::os::raw::c_uint;
