#pragma once
#include <stdint.h>
#include "insn.h"

typedef enum { OT_1=1, OT_2=2 } OpKind;

typedef struct {
  OpKind kind;
  uint8_t b1;
  uint8_t b2;
  Op op;
  uint16_t flags;
} OpEntry;

enum {
  OF_NONE      = 0,
  OF_REL8      = 1<<0,
  OF_REL32     = 1<<1,
  OF_CC        = 1<<2,
  OF_REG_RANGE = 1<<3,
  OF_MODRM     = 1<<4,
  OF_GRP81     = 1<<5, // opcode 0x81 (imm32)
  OF_GRP83     = 1<<6, // opcode 0x83 (imm8 sign-extended)
  OF_MOV_IMM_REG = 1<<7, // B8..BF (+ REX.B)
  OF_GRP_C7 = 1<<8,
  OF_SETCC = 1<<8,   // 0F 90..9F /r
  OF_BYTE  = 1<<9,   // forces width=8 for ModRM ops (08 /r etc.)
  OF_PFX66 = 1<<10,  // optional (se você quiser tratar 66)


};

extern const OpEntry g_ops[];
extern const unsigned g_ops_count;
