#pragma once
#include <stdint.h>
#include "insn.h"

typedef enum { OT_1=1, OT_2=2 } OpKind;

typedef struct {
  OpKind kind;
  uint8_t b1;
  uint8_t b2;   // for OT_2
  Op op;
  uint8_t flags;
} OpEntry;

enum {
  OF_NONE      = 0,
  OF_REL8      = 1<<0,
  OF_REL32     = 1<<1,
  OF_CC        = 1<<2,
  OF_REG_RANGE = 1<<3, // e.g. 50..57
  OF_MODRM     = 1<<4, // /r
};

extern const OpEntry g_ops[];
extern const unsigned g_ops_count;
