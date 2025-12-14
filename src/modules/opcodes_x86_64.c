#include "opdump/opcodes.h"

const OpEntry g_ops[] = {
  {OT_1, 0xC3, 0x00, OP_RET,      OF_NONE},

  {OT_1, 0xE8, 0x00, OP_CALL_REL, OF_REL32},
  {OT_1, 0xE9, 0x00, OP_JMP_REL,  OF_REL32},
  {OT_1, 0xEB, 0x00, OP_JMP_REL,  OF_REL8},

  // Jcc rel8: 70..7F (range in b1)
  {OT_1, 0x70, 0x00, OP_JCC_REL,  (uint8_t)(OF_REL8  | OF_CC | OF_REG_RANGE)},

  // Jcc rel32: 0F 80..8F (range in b2)
  {OT_2, 0x0F, 0x80, OP_JCC_REL,  (uint8_t)(OF_REL32 | OF_CC | OF_REG_RANGE)},

  // push/pop reg (range)
  {OT_1, 0x50, 0x00, OP_PUSH, (uint8_t)(OF_REG_RANGE)},
  {OT_1, 0x58, 0x00, OP_POP,  (uint8_t)(OF_REG_RANGE)},

  // ModRM ops (we'll only implement reg-reg in MVP)
  {OT_1, 0x89, 0x00, OP_MOV, (uint8_t)(OF_MODRM)},
  {OT_1, 0x8B, 0x00, OP_MOV, (uint8_t)(OF_MODRM)},
  {OT_1, 0x8D, 0x00, OP_LEA, (uint8_t)(OF_MODRM)},
  {OT_1, 0x31, 0x00, OP_XOR, (uint8_t)(OF_MODRM)},
};

const unsigned g_ops_count = sizeof(g_ops)/sizeof(g_ops[0]);
