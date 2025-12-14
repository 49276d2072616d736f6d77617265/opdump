#include <string.h>
#include "opdump/decode.h"
#include "opdump/opcodes.h"

typedef struct {
  uint8_t rex_present;
  uint8_t rex_w, rex_r, rex_x, rex_b;
} Rex;

static uint8_t get_mod(uint8_t modrm) { return (uint8_t)(modrm >> 6); }
static uint8_t get_reg(uint8_t modrm) { return (uint8_t)((modrm >> 3) & 7); }
static uint8_t get_rm (uint8_t modrm) { return (uint8_t)(modrm & 7); }

static int64_t read_i8(const uint8_t *p) { return (int8_t)p[0]; }
static int64_t read_i32(const uint8_t *p) {
  int32_t v = (int32_t)((uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24));
  return (int64_t)v;
}

static void insn_init(Insn *o, uint64_t addr) {
  memset(o, 0, sizeof(*o));
  o->addr = addr;
}

static void set_bytes(Insn *o, const uint8_t *p, size_t len) {
  if (len > 16) len = 16;
  memcpy(o->bytes, p, len);
  o->bytes_len = (uint8_t)len;
}

static const OpEntry* match_op_1(uint8_t b1) {
  for (unsigned i = 0; i < g_ops_count; i++) {
    const OpEntry *e = &g_ops[i];
    if (e->kind != OT_1) continue;

    if (e->flags & OF_REG_RANGE) {
      // ranges supported for: 70..7F, 50..57, 58..5F
      if (e->b1 == 0x70 && b1 >= 0x70 && b1 <= 0x7F) return e;
      if (e->b1 == 0x50 && b1 >= 0x50 && b1 <= 0x57) return e;
      if (e->b1 == 0x58 && b1 >= 0x58 && b1 <= 0x5F) return e;
    } else {
      if (e->b1 == b1) return e;
    }
  }
  return NULL;
}

static const OpEntry* match_op_2(uint8_t b1, uint8_t b2) {
  for (unsigned i = 0; i < g_ops_count; i++) {
    const OpEntry *e = &g_ops[i];
    if (e->kind != OT_2) continue;
    if (e->b1 != b1) continue;

    if (e->flags & OF_REG_RANGE) {
      // range on b2: 80..8F
      if (e->b2 == 0x80 && b2 >= 0x80 && b2 <= 0x8F) return e;
    } else {
      if (e->b2 == b2) return e;
    }
  }
  return NULL;
}

size_t decode_one(const DecodeCtx *ctx, const uint8_t *p, size_t n, uint64_t addr, Insn *out) {
  if (!ctx || !p || !out || n == 0) return 0;

  insn_init(out, addr);

  size_t i = 0;

  // REX prefix (x86-64 only)
  Rex rex = {0};
  if (ctx->is64 && n >= 1) {
    uint8_t b = p[0];
    if ((b & 0xF0) == 0x40) {
      rex.rex_present = 1;
      rex.rex_w = (b >> 3) & 1;
      rex.rex_r = (b >> 2) & 1;
      rex.rex_x = (b >> 1) & 1;
      rex.rex_b = (b >> 0) & 1;
      i++;
      if (i >= n) return 0;
    }
  }

  // opcode
  uint8_t b1 = p[i++];

  // two-byte?
  const OpEntry *op = NULL;
  uint8_t b2 = 0;
  if (b1 == 0x0F) {
    if (i >= n) return 0;
    b2 = p[i++];
    op = match_op_2(b1, b2);
  } else {
    op = match_op_1(b1);
  }

  if (!op) {
    // invalid/unknown: consume 1 byte (or rex+1 already)
    out->op = OP_INVALID;
    out->size = (uint8_t)i;
    set_bytes(out, p, i);
    return i;
  }

  out->op = op->op;

  // handle Jcc condition
  if ((op->flags & OF_CC) && out->op == OP_JCC_REL) {
    out->has_cc = 1;
    if (op->kind == OT_1) {
      out->cc = (Cond)(b1 & 0x0F);      // 70..7F
    } else {
      out->cc = (Cond)(b2 & 0x0F);      // 0F 80..8F
    }
  }

  // rel immediates
  if (op->flags & OF_REL8) {
    if (i + 1 > n) return 0;
    out->has_rel = 1;
    out->rel_width = 1;
    out->rel = read_i8(p + i);
    i += 1;

    // operand: absolute target for printing
    out->op_count = 1;
    out->ops[0].kind = O_IMM;
    out->ops[0].width = 64;
    out->ops[0].imm = (int64_t)(addr + (uint64_t)i + out->rel);
  } else if (op->flags & OF_REL32) {
    if (i + 4 > n) return 0;
    out->has_rel = 1;
    out->rel_width = 4;
    out->rel = read_i32(p + i);
    i += 4;

    out->op_count = 1;
    out->ops[0].kind = O_IMM;
    out->ops[0].width = 64;
    out->ops[0].imm = (int64_t)(addr + (uint64_t)i + out->rel);
  }

  // reg-range push/pop
  if (out->op == OP_PUSH || out->op == OP_POP) {
    uint8_t low = (uint8_t)(b1 & 7);
    uint8_t reg = (uint8_t)(low | (rex.rex_b ? 8 : 0));
    out->op_count = 1;
    out->ops[0].kind = O_REG;
    out->ops[0].width = 64;
    out->ops[0].reg = reg;
  }

  // ModRM ops (MVP: only mod==3 supported)
  if (op->flags & OF_MODRM) {
    if (i >= n) return 0;
    uint8_t modrm = p[i++];

    uint8_t mod = get_mod(modrm);
    uint8_t reg = (uint8_t)(get_reg(modrm) | (rex.rex_r ? 8 : 0));
    uint8_t rm  = (uint8_t)(get_rm(modrm)  | (rex.rex_b ? 8 : 0));

    if (mod != 3) {
      // MVP: memory decoding not implemented yet
      out->op_count = 0;
    } else {
      // reg-reg forms (Intel: dest/src depends on opcode)
      Operand o_reg = {0}, o_rm = {0};
      o_reg.kind = O_REG; o_reg.width = 64; o_reg.reg = reg;
      o_rm.kind  = O_REG; o_rm.width  = 64; o_rm.reg  = rm;

      if (b1 == 0x89) {
        // mov r/m64, r64  => rm, reg
        out->op_count = 2;
        out->ops[0] = o_rm;
        out->ops[1] = o_reg;
      } else if (b1 == 0x8B) {
        // mov r64, r/m64  => reg, rm
        out->op_count = 2;
        out->ops[0] = o_reg;
        out->ops[1] = o_rm;
      } else if (b1 == 0x8D) {
        // lea r64, m  (but MVP reg-reg placeholder)
        out->op_count = 2;
        out->ops[0] = o_reg;
        out->ops[1] = o_rm;
      } else if (b1 == 0x31) {
        // xor r/m, r => rm, reg
        out->op_count = 2;
        out->ops[0] = o_rm;
        out->ops[1] = o_reg;
      }
    }
  }

  out->size = (uint8_t)i;
  set_bytes(out, p, i);
  return i;
}
