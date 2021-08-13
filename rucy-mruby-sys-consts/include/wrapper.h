enum MRB_INSN {
#define OPCODE(x,_) OP_ ## x,
#include "ops.h"
#undef OPCODE
};

#define Z 0 // no operand
#define B 1 // 8bit
#define BB 2 // 8+8bit
#define BBB 3 // 8+8+8bit
#define BS 4 // 8+16bit
#define BSS 5 // 8+16+16bit
#define S 6 // 16bit
#define W 7 // 24bit
