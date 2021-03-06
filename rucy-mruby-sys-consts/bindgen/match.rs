
pub fn resolve_operand(insn: MRB_INSN) -> u32 {
    match insn {
MRB_INSN_OP_NOP => Z,
MRB_INSN_OP_MOVE => BB,
MRB_INSN_OP_LOADL => BB,
MRB_INSN_OP_LOADL16 => BS,
MRB_INSN_OP_LOADI => BB,
MRB_INSN_OP_LOADINEG => BB,
MRB_INSN_OP_LOADI__1 => B,
MRB_INSN_OP_LOADI_0 => B,
MRB_INSN_OP_LOADI_1 => B,
MRB_INSN_OP_LOADI_2 => B,
MRB_INSN_OP_LOADI_3 => B,
MRB_INSN_OP_LOADI_4 => B,
MRB_INSN_OP_LOADI_5 => B,
MRB_INSN_OP_LOADI_6 => B,
MRB_INSN_OP_LOADI_7 => B,
MRB_INSN_OP_LOADI16 => BS,
MRB_INSN_OP_LOADI32 => BSS,
MRB_INSN_OP_LOADSYM => BB,
MRB_INSN_OP_LOADSYM16 => BS,
MRB_INSN_OP_LOADNIL => B,
MRB_INSN_OP_LOADSELF => B,
MRB_INSN_OP_LOADT => B,
MRB_INSN_OP_LOADF => B,
MRB_INSN_OP_GETGV => BB,
MRB_INSN_OP_SETGV => BB,
MRB_INSN_OP_GETSV => BB,
MRB_INSN_OP_SETSV => BB,
MRB_INSN_OP_GETIV => BB,
MRB_INSN_OP_SETIV => BB,
MRB_INSN_OP_GETCV => BB,
MRB_INSN_OP_SETCV => BB,
MRB_INSN_OP_GETCONST => BB,
MRB_INSN_OP_SETCONST => BB,
MRB_INSN_OP_GETMCNST => BB,
MRB_INSN_OP_SETMCNST => BB,
MRB_INSN_OP_GETUPVAR => BBB,
MRB_INSN_OP_SETUPVAR => BBB,
MRB_INSN_OP_JMP => S,
MRB_INSN_OP_JMPIF => BS,
MRB_INSN_OP_JMPNOT => BS,
MRB_INSN_OP_JMPNIL => BS,
MRB_INSN_OP_JMPUW => S,
MRB_INSN_OP_EXCEPT => B,
MRB_INSN_OP_RESCUE => BB,
MRB_INSN_OP_RAISEIF => B,
MRB_INSN_OP_SENDV => BB,
MRB_INSN_OP_SENDVB => BB,
MRB_INSN_OP_SEND => BBB,
MRB_INSN_OP_SENDB => BBB,
MRB_INSN_OP_SENDVK => BB,
MRB_INSN_OP_CALL => Z,
MRB_INSN_OP_SUPER => BB,
MRB_INSN_OP_ARGARY => BS,
MRB_INSN_OP_ENTER => W,
MRB_INSN_OP_KEY_P => BB,
MRB_INSN_OP_KEYEND => Z,
MRB_INSN_OP_KARG => BB,
MRB_INSN_OP_RETURN => B,
MRB_INSN_OP_RETURN_BLK => B,
MRB_INSN_OP_BREAK => B,
MRB_INSN_OP_BLKPUSH => BS,
MRB_INSN_OP_ADD => B,
MRB_INSN_OP_ADDI => BB,
MRB_INSN_OP_SUB => B,
MRB_INSN_OP_SUBI => BB,
MRB_INSN_OP_MUL => B,
MRB_INSN_OP_DIV => B,
MRB_INSN_OP_EQ => B,
MRB_INSN_OP_LT => B,
MRB_INSN_OP_LE => B,
MRB_INSN_OP_GT => B,
MRB_INSN_OP_GE => B,
MRB_INSN_OP_ARRAY => BB,
MRB_INSN_OP_ARRAY2 => BBB,
MRB_INSN_OP_ARYCAT => B,
MRB_INSN_OP_ARYPUSH => B,
MRB_INSN_OP_ARYDUP => B,
MRB_INSN_OP_AREF => BBB,
MRB_INSN_OP_ASET => BBB,
MRB_INSN_OP_APOST => BBB,
MRB_INSN_OP_INTERN => B,
MRB_INSN_OP_STRING => BB,
MRB_INSN_OP_STRING16 => BS,
MRB_INSN_OP_STRCAT => B,
MRB_INSN_OP_HASH => BB,
MRB_INSN_OP_HASHADD => BB,
MRB_INSN_OP_HASHCAT => B,
MRB_INSN_OP_LAMBDA => BB,
MRB_INSN_OP_LAMBDA16 => BS,
MRB_INSN_OP_BLOCK => BB,
MRB_INSN_OP_BLOCK16 => BS,
MRB_INSN_OP_METHOD => BB,
MRB_INSN_OP_METHOD16 => BS,
MRB_INSN_OP_RANGE_INC => B,
MRB_INSN_OP_RANGE_EXC => B,
MRB_INSN_OP_OCLASS => B,
MRB_INSN_OP_CLASS => BB,
MRB_INSN_OP_MODULE => BB,
MRB_INSN_OP_EXEC => BB,
MRB_INSN_OP_EXEC16 => BS,
MRB_INSN_OP_DEF => BB,
MRB_INSN_OP_ALIAS => BB,
MRB_INSN_OP_UNDEF => B,
MRB_INSN_OP_SCLASS => B,
MRB_INSN_OP_TCLASS => B,
MRB_INSN_OP_DEBUG => BBB,
MRB_INSN_OP_ERR => B,
MRB_INSN_OP_STOP => Z,

        _ => 0,
    }
}

pub fn opcode_from_u32(insn: MRB_INSN) -> &'static str {
    match insn {
MRB_INSN_OP_NOP => "OP_NOP",
MRB_INSN_OP_MOVE => "OP_MOVE",
MRB_INSN_OP_LOADL => "OP_LOADL",
MRB_INSN_OP_LOADL16 => "OP_LOADL16",
MRB_INSN_OP_LOADI => "OP_LOADI",
MRB_INSN_OP_LOADINEG => "OP_LOADINEG",
MRB_INSN_OP_LOADI__1 => "OP_LOADI__1",
MRB_INSN_OP_LOADI_0 => "OP_LOADI_0",
MRB_INSN_OP_LOADI_1 => "OP_LOADI_1",
MRB_INSN_OP_LOADI_2 => "OP_LOADI_2",
MRB_INSN_OP_LOADI_3 => "OP_LOADI_3",
MRB_INSN_OP_LOADI_4 => "OP_LOADI_4",
MRB_INSN_OP_LOADI_5 => "OP_LOADI_5",
MRB_INSN_OP_LOADI_6 => "OP_LOADI_6",
MRB_INSN_OP_LOADI_7 => "OP_LOADI_7",
MRB_INSN_OP_LOADI16 => "OP_LOADI16",
MRB_INSN_OP_LOADI32 => "OP_LOADI32",
MRB_INSN_OP_LOADSYM => "OP_LOADSYM",
MRB_INSN_OP_LOADSYM16 => "OP_LOADSYM16",
MRB_INSN_OP_LOADNIL => "OP_LOADNIL",
MRB_INSN_OP_LOADSELF => "OP_LOADSELF",
MRB_INSN_OP_LOADT => "OP_LOADT",
MRB_INSN_OP_LOADF => "OP_LOADF",
MRB_INSN_OP_GETGV => "OP_GETGV",
MRB_INSN_OP_SETGV => "OP_SETGV",
MRB_INSN_OP_GETSV => "OP_GETSV",
MRB_INSN_OP_SETSV => "OP_SETSV",
MRB_INSN_OP_GETIV => "OP_GETIV",
MRB_INSN_OP_SETIV => "OP_SETIV",
MRB_INSN_OP_GETCV => "OP_GETCV",
MRB_INSN_OP_SETCV => "OP_SETCV",
MRB_INSN_OP_GETCONST => "OP_GETCONST",
MRB_INSN_OP_SETCONST => "OP_SETCONST",
MRB_INSN_OP_GETMCNST => "OP_GETMCNST",
MRB_INSN_OP_SETMCNST => "OP_SETMCNST",
MRB_INSN_OP_GETUPVAR => "OP_GETUPVAR",
MRB_INSN_OP_SETUPVAR => "OP_SETUPVAR",
MRB_INSN_OP_JMP => "OP_JMP",
MRB_INSN_OP_JMPIF => "OP_JMPIF",
MRB_INSN_OP_JMPNOT => "OP_JMPNOT",
MRB_INSN_OP_JMPNIL => "OP_JMPNIL",
MRB_INSN_OP_JMPUW => "OP_JMPUW",
MRB_INSN_OP_EXCEPT => "OP_EXCEPT",
MRB_INSN_OP_RESCUE => "OP_RESCUE",
MRB_INSN_OP_RAISEIF => "OP_RAISEIF",
MRB_INSN_OP_SENDV => "OP_SENDV",
MRB_INSN_OP_SENDVB => "OP_SENDVB",
MRB_INSN_OP_SEND => "OP_SEND",
MRB_INSN_OP_SENDB => "OP_SENDB",
MRB_INSN_OP_SENDVK => "OP_SENDVK",
MRB_INSN_OP_CALL => "OP_CALL",
MRB_INSN_OP_SUPER => "OP_SUPER",
MRB_INSN_OP_ARGARY => "OP_ARGARY",
MRB_INSN_OP_ENTER => "OP_ENTER",
MRB_INSN_OP_KEY_P => "OP_KEY_P",
MRB_INSN_OP_KEYEND => "OP_KEYEND",
MRB_INSN_OP_KARG => "OP_KARG",
MRB_INSN_OP_RETURN => "OP_RETURN",
MRB_INSN_OP_RETURN_BLK => "OP_RETURN_BLK",
MRB_INSN_OP_BREAK => "OP_BREAK",
MRB_INSN_OP_BLKPUSH => "OP_BLKPUSH",
MRB_INSN_OP_ADD => "OP_ADD",
MRB_INSN_OP_ADDI => "OP_ADDI",
MRB_INSN_OP_SUB => "OP_SUB",
MRB_INSN_OP_SUBI => "OP_SUBI",
MRB_INSN_OP_MUL => "OP_MUL",
MRB_INSN_OP_DIV => "OP_DIV",
MRB_INSN_OP_EQ => "OP_EQ",
MRB_INSN_OP_LT => "OP_LT",
MRB_INSN_OP_LE => "OP_LE",
MRB_INSN_OP_GT => "OP_GT",
MRB_INSN_OP_GE => "OP_GE",
MRB_INSN_OP_ARRAY => "OP_ARRAY",
MRB_INSN_OP_ARRAY2 => "OP_ARRAY2",
MRB_INSN_OP_ARYCAT => "OP_ARYCAT",
MRB_INSN_OP_ARYPUSH => "OP_ARYPUSH",
MRB_INSN_OP_ARYDUP => "OP_ARYDUP",
MRB_INSN_OP_AREF => "OP_AREF",
MRB_INSN_OP_ASET => "OP_ASET",
MRB_INSN_OP_APOST => "OP_APOST",
MRB_INSN_OP_INTERN => "OP_INTERN",
MRB_INSN_OP_STRING => "OP_STRING",
MRB_INSN_OP_STRING16 => "OP_STRING16",
MRB_INSN_OP_STRCAT => "OP_STRCAT",
MRB_INSN_OP_HASH => "OP_HASH",
MRB_INSN_OP_HASHADD => "OP_HASHADD",
MRB_INSN_OP_HASHCAT => "OP_HASHCAT",
MRB_INSN_OP_LAMBDA => "OP_LAMBDA",
MRB_INSN_OP_LAMBDA16 => "OP_LAMBDA16",
MRB_INSN_OP_BLOCK => "OP_BLOCK",
MRB_INSN_OP_BLOCK16 => "OP_BLOCK16",
MRB_INSN_OP_METHOD => "OP_METHOD",
MRB_INSN_OP_METHOD16 => "OP_METHOD16",
MRB_INSN_OP_RANGE_INC => "OP_RANGE_INC",
MRB_INSN_OP_RANGE_EXC => "OP_RANGE_EXC",
MRB_INSN_OP_OCLASS => "OP_OCLASS",
MRB_INSN_OP_CLASS => "OP_CLASS",
MRB_INSN_OP_MODULE => "OP_MODULE",
MRB_INSN_OP_EXEC => "OP_EXEC",
MRB_INSN_OP_EXEC16 => "OP_EXEC16",
MRB_INSN_OP_DEF => "OP_DEF",
MRB_INSN_OP_ALIAS => "OP_ALIAS",
MRB_INSN_OP_UNDEF => "OP_UNDEF",
MRB_INSN_OP_SCLASS => "OP_SCLASS",
MRB_INSN_OP_TCLASS => "OP_TCLASS",
MRB_INSN_OP_DEBUG => "OP_DEBUG",
MRB_INSN_OP_ERR => "OP_ERR",
MRB_INSN_OP_STOP => "OP_STOP",

        _ => "unknown",
    }
}
