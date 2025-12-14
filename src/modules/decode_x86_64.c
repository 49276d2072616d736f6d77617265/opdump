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
      if (e->b2 == 0x80 && b2 >= 0x80 && b2 <= 0x8F) return e;
    } else {
      if (e->b2 == b2) return e;
    }
  }
  return NULL;
}

static Operand make_reg64(uint8_t r) {
  Operand o;
  memset(&o, 0, sizeof(o));
  o.kind = O_REG;
  o.width = 64;
  o.reg = r;
  return o;
}

static Operand make_mem64(uint8_t base, uint8_t index, uint8_t scale, int32_t disp) {
  Operand o;
  memset(&o, 0, sizeof(o));
  o.kind = O_MEM;
  o.width = 64;
  o.mem.base  = base;   // 0..16, or 0xFF none
  o.mem.index = index;  // 0..15, or 0xFF none
  o.mem.scale = scale;  // 1,2,4,8
  o.mem.disp  = disp;
  return o;
}

static size_t read_disp_by_mod(const uint8_t *p, size_t n, uint8_t mod, int32_t *out_disp) {
  *out_disp = 0;
  if (mod == 1) {
    if (n < 1) return 0;
    *out_disp = (int32_t)read_i8(p);
    return 1;
  }
  if (mod == 2) {
    if (n < 4) return 0;
    *out_disp = (int32_t)read_i32(p);
    return 4;
  }
  return 0; // mod 0 or 3: no disp here (handled specially when needed)
}

static Operand rm_to_operand_mvp(const Rex *rex, const uint8_t *p, size_t n, size_t *io_i,
                                 uint8_t mod, uint8_t rm_lo3, uint8_t rm_ext,
                                 int is_mem) {
  if (!is_mem) return make_reg64(rm_ext);

  // memory form
  uint8_t base  = rm_ext;
  uint8_t index = 0xFF;
  uint8_t scale = 1;
  int32_t disp  = 0;

  // SIB?
  if (rm_lo3 == 4) {
    if (*io_i >= n) return make_mem64(0xFF, 0xFF, 1, 0);

    uint8_t sib = p[(*io_i)++];
    uint8_t ss  = (uint8_t)(sib >> 6);
    uint8_t idx = (uint8_t)((sib >> 3) & 7);
    uint8_t bas = (uint8_t)(sib & 7);

    scale = (uint8_t)(1u << ss);

    // index==4 means "no index" (even in x86-64)
    if (idx == 4) {
      index = 0xFF;
    } else {
      index = (uint8_t)(idx | (rex->rex_x ? 8 : 0));
    }

    // base
    bas = (uint8_t)(bas | (rex->rex_b ? 8 : 0));

    if (mod == 0 && (sib & 7) == 5) {
      // no base, disp32 follows
      base = 0xFF;
      if (*io_i + 4 > n) return make_mem64(0xFF, index, scale, 0);
      disp = (int32_t)read_i32(p + *io_i);
      *io_i += 4;
      return make_mem64(base, index, scale, disp);
    }

    base = bas;

    // disp for mod 1/2
    size_t used = read_disp_by_mod(p + *io_i, n - *io_i, mod, &disp);
    if (mod == 1 || mod == 2) {
      if (used == 0) return make_mem64(base, index, scale, 0);
      *io_i += used;
    }

    return make_mem64(base, index, scale, disp);
  }

  // no SIB, classic ModRM addressing
  if (mod == 0 && rm_lo3 == 5) {
    // RIP-relative disp32 in x86-64
    if (*io_i + 4 > n) return make_mem64(16, 0xFF, 1, 0);
    disp = (int32_t)read_i32(p + *io_i);
    *io_i += 4;
    return make_mem64(16 /*rip*/, 0xFF, 1, disp);
  }

  // disp8/disp32 for mod 1/2
  size_t used = read_disp_by_mod(p + *io_i, n - *io_i, mod, &disp);
  if (mod == 1 || mod == 2) {
    if (used == 0) return make_mem64(base, 0xFF, 1, 0);
    *io_i += used;
  }

  return make_mem64(base, 0xFF, 1, disp);
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
    out->op = OP_INVALID;
    out->size = (uint8_t)i;
    set_bytes(out, p, i);
    return i;
  }

  out->op = op->op;

  // Jcc condition
  if ((op->flags & OF_CC) && out->op == OP_JCC_REL) {
    out->has_cc = 1;
    out->cc = (Cond)((op->kind == OT_1 ? b1 : b2) & 0x0F);
  }

  // rel immediates
  if (op->flags & OF_REL8) {
    if (i + 1 > n) return 0;
    out->has_rel = 1;
    out->rel_width = 1;
    out->rel = read_i8(p + i);
    i += 1;

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

  // push/pop reg (range)
  if (out->op == OP_PUSH || out->op == OP_POP) {
    uint8_t low = (uint8_t)(b1 & 7);
    uint8_t reg = (uint8_t)(low | (rex.rex_b ? 8 : 0));
    out->op_count = 1;
    out->ops[0] = make_reg64(reg);
  }

  // ModRM ops
  if (op->flags & OF_MODRM) {
    if (i >= n) return 0;

    uint8_t modrm = p[i++];

    uint8_t mod = get_mod(modrm);
    uint8_t reg = (uint8_t)(get_reg(modrm) | (rex.rex_r ? 8 : 0));

    uint8_t rm_lo3 = get_rm(modrm); // low 3 bits
    uint8_t rm_ext = (uint8_t)(rm_lo3 | (rex.rex_b ? 8 : 0));

    int is_mem = (mod != 3);

    Operand o_reg = make_reg64(reg);
    Operand o_rm  = rm_to_operand_mvp(&rex, p, n, &i, mod, rm_lo3, rm_ext, is_mem);

    if (b1 == 0x89) {
      // mov r/m64, r64
      out->op_count = 2;
      out->ops[0] = o_rm;
      out->ops[1] = o_reg;
    } else if (b1 == 0x8B) {
      // mov r64, r/m64
      out->op_count = 2;
      out->ops[0] = o_reg;
      out->ops[1] = o_rm;
    } else if (b1 == 0x8D) {
      // lea r64, m
      out->op_count = 2;
      out->ops[0] = o_reg;
      out->ops[1] = o_rm;
    } else if (b1 == 0x31) {
      // xor r/m, r
      out->op_count = 2;
      out->ops[0] = o_rm;
      out->ops[1] = o_reg;
    }
  }

  out->size = (uint8_t)i;
  set_bytes(out, p, i);
  return i;
}
