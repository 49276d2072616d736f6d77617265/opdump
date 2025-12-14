#pragma once
#include <stddef.h>
#include <stdint.h>
#include "insn.h"

typedef struct {
  uint8_t is64; // 1 for x86-64
} DecodeCtx;

// returns bytes consumed; 0 = failed/invalid
size_t decode_one(const DecodeCtx *ctx, const uint8_t *p, size_t n, uint64_t addr, Insn *out);
