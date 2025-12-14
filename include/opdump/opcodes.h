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
  OF_NONE        = 0,
  OF_REL8        = 1<<0,
  OF_REL32       = 1<<1,
  OF_CC          = 1<<2,
  OF_REG_RANGE   = 1<<3,
  OF_MODRM       = 1<<4,

  OF_GRP81       = 1<<5,  // 0x81 imm32 (/0 /4 /5 /7)
  OF_GRP83       = 1<<6,  // 0x83 imm8  (/0 /4 /5 /7)
  OF_MOV_IMM_REG = 1<<7,  // B8..BF

  OF_SETCC       = 1<<8,  // 0F 90..9F /r
  OF_BYTE        = 1<<9,  // force width=8 for ModRM instruction
  OF_GRP_C6      = 1<<10, // C6 /0: mov r/m8, imm8

  OF_PFX66       = 1<<11,

  OF_GRP_FF      = 1<<12  // FF /2 call r/m64, /4 jmp r/m64
};

extern const OpEntry g_ops[];
extern const unsigned g_ops_count;
