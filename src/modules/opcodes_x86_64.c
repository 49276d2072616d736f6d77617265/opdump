#include "opdump/opcodes.h"

const OpEntry g_ops[] = {
  {OT_1, 0xC3, 0x00, OP_RET,      OF_NONE},

  {OT_1, 0xE8, 0x00, OP_CALL_REL, OF_REL32},
  {OT_1, 0xE9, 0x00, OP_JMP_REL,  OF_REL32},
  {OT_1, 0xEB, 0x00, OP_JMP_REL,  OF_REL8},

  // Jcc rel8: 70..7F
  {OT_1, 0x70, 0x00, OP_JCC_REL,  (uint16_t)(OF_REL8  | OF_CC | OF_REG_RANGE)},
  // Jcc rel32: 0F 80..8F
  {OT_2, 0x0F, 0x80, OP_JCC_REL,  (uint16_t)(OF_REL32 | OF_CC | OF_REG_RANGE)},

  // push/pop reg ranges
  {OT_1, 0x50, 0x00, OP_PUSH, (uint16_t)(OF_REG_RANGE)},
  {OT_1, 0x58, 0x00, OP_POP,  (uint16_t)(OF_REG_RANGE)},

  // ModRM ops
  {OT_1, 0x89, 0x00, OP_MOV,  (uint16_t)(OF_MODRM)},
  {OT_1, 0x8B, 0x00, OP_MOV,  (uint16_t)(OF_MODRM)},
  {OT_1, 0x8D, 0x00, OP_LEA,  (uint16_t)(OF_MODRM)},
  {OT_1, 0x31, 0x00, OP_XOR,  (uint16_t)(OF_MODRM)},

  // new: groups + test
  {OT_1, 0x81, 0x00, OP_INVALID, (uint16_t)(OF_MODRM | OF_GRP81)}, // add/sub/cmp via /0 /5 /7
  {OT_1, 0x83, 0x00, OP_INVALID, (uint16_t)(OF_MODRM | OF_GRP83)}, // add/sub/cmp via /0 /5 /7 (imm8)
  {OT_1, 0x85, 0x00, OP_TEST,    (uint16_t)(OF_MODRM)},           // test r/m, r
};

const unsigned g_ops_count = sizeof(g_ops)/sizeof(g_ops[0]);
