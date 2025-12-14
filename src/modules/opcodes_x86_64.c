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

  // ModRM ops (GPR)
  {OT_1, 0x89, 0x00, OP_MOV,  (uint16_t)(OF_MODRM)},
  {OT_1, 0x8B, 0x00, OP_MOV,  (uint16_t)(OF_MODRM)},
  {OT_1, 0x8D, 0x00, OP_LEA,  (uint16_t)(OF_MODRM)},
  {OT_1, 0x31, 0x00, OP_XOR,  (uint16_t)(OF_MODRM)},
  {OT_1, 0x39, 0x00, OP_CMP,  (uint16_t)(OF_MODRM)},
  {OT_1, 0x01, 0x00, OP_ADD,  (uint16_t)(OF_MODRM)}, // add r/m, r
  {OT_1, 0x29, 0x00, OP_SUB,  (uint16_t)(OF_MODRM)}, // sub r/m, r

  // groups + test
  {OT_1, 0x81, 0x00, OP_INVALID, (uint16_t)(OF_MODRM | OF_GRP81)},
  {OT_1, 0x83, 0x00, OP_INVALID, (uint16_t)(OF_MODRM | OF_GRP83)},
  {OT_1, 0x85, 0x00, OP_TEST,    (uint16_t)(OF_MODRM)},

  // mov reg, imm
  {OT_1, 0xB8, 0x00, OP_MOV, (uint16_t)(OF_REG_RANGE | OF_MOV_IMM_REG)},

  // misc
  {OT_1, 0x90, 0x00, OP_NOP, OF_NONE},
  {OT_1, 0xFA, 0x00, OP_CLI, OF_NONE},
  {OT_2, 0x0F, 0x1F, OP_NOP, (uint16_t)(OF_MODRM)}, // multi-byte nop

  // OR r/m8, r8
  {OT_1, 0x08, 0x00, OP_OR,  (uint16_t)(OF_MODRM | OF_BYTE)},

  // C6 /0: mov r/m8, imm8
  {OT_1, 0xC6, 0x00, OP_MOV, (uint16_t)(OF_MODRM | OF_GRP_C6 | OF_BYTE)},

  // FF group: /2 CALL r/m64, /4 JMP r/m64
  {OT_1, 0xFF, 0x00, OP_INVALID, (uint16_t)(OF_MODRM | OF_GRP_FF)},

  // SETcc: 0F 90..9F /r
  {OT_2, 0x0F, 0x90, OP_SETCC, (uint16_t)(OF_MODRM | OF_CC | OF_REG_RANGE | OF_SETCC)},

  // PXOR xmm, xmm/m128 : 66 0F EF /r
  {OT_2, 0x0F, 0xEF, OP_PXOR, (uint16_t)(OF_MODRM)},

  {OT_1, 0xC9, 0x00, OP_LEAVE, OF_NONE},

  {OT_2, 0x0F, 0x40, OP_CMOVCC, (uint16_t)(OF_MODRM | OF_CC | OF_REG_RANGE)},
};

const unsigned g_ops_count = sizeof(g_ops)/sizeof(g_ops[0]);
