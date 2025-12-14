#include <string.h>
#include "opdump/decode.h"
#include "opdump/opcodes.h"

typedef struct {
  uint8_t rex_present;
  uint8_t rex_w, rex_r, rex_x, rex_b;
} Rex;

static uint8_t get_mod(uint8_t modrm) { return (uint8_t)(modrm >> 6); }
static uint8_t get_reg3(uint8_t modrm){ return (uint8_t)((modrm >> 3) & 7); }
static uint8_t get_rm3 (uint8_t modrm){ return (uint8_t)(modrm & 7); }

static int64_t read_i8(const uint8_t *p) { return (int8_t)p[0]; }
static int64_t read_i32(const uint8_t *p) {
  int32_t v = (int32_t)((uint32_t)p[0] |
                        ((uint32_t)p[1] << 8) |
                        ((uint32_t)p[2] << 16) |
                        ((uint32_t)p[3] << 24));
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
      if (e->b1 == 0xB8 && b1 >= 0xB8 && b1 <= 0xBF) return e;
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
      if (e->b2 == 0x80 && b2 >= 0x80 && b2 <= 0x8F) return e; // Jcc
      if (e->b2 == 0x90 && b2 >= 0x90 && b2 <= 0x9F) return e; // SETcc
    } else {
      if (e->b2 == b2) return e;
    }
  }
  return NULL;
}

static Operand make_reg(uint8_t width, uint8_t r) {
  Operand o;
  memset(&o, 0, sizeof(o));
  o.kind = O_REG;
  o.width = width;
  o.reg = r;
  return o;
}

static Operand make_imm(uint8_t width, int64_t v) {
  Operand o;
  memset(&o, 0, sizeof(o));
  o.kind = O_IMM;
  o.width = width;
  o.imm = v;
  return o;
}

static Operand make_mem(uint8_t width, uint8_t base, uint8_t index, uint8_t scale, int32_t disp) {
  Operand o;
  memset(&o, 0, sizeof(o));
  o.kind = O_MEM;
  o.width = width;
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
  return 0;
}

static Operand rm_to_operand(const Rex *rex, const uint8_t *p, size_t n, size_t *io_i,
                             uint8_t width,
                             uint8_t mod, uint8_t rm_lo3, uint8_t rm_ext,
                             int is_mem) {
  if (!is_mem) return make_reg(width, rm_ext);

  uint8_t base  = rm_ext;
  uint8_t index = 0xFF;
  uint8_t scale = 1;
  int32_t disp  = 0;

  // SIB?
  if (rm_lo3 == 4) {
    if (*io_i >= n) return make_mem(width, 0xFF, 0xFF, 1, 0);

    uint8_t sib = p[(*io_i)++];
    uint8_t ss  = (uint8_t)(sib >> 6);
    uint8_t idx = (uint8_t)((sib >> 3) & 7);
    uint8_t bas = (uint8_t)(sib & 7);

    scale = (uint8_t)(1u << ss);

    // index==4 => none
    if (idx == 4) index = 0xFF;
    else          index = (uint8_t)(idx | (rex->rex_x ? 8 : 0));

    bas = (uint8_t)(bas | (rex->rex_b ? 8 : 0));

    if (mod == 0 && (sib & 7) == 5) {
      // no base, disp32
      base = 0xFF;
      if (*io_i + 4 > n) return make_mem(width, base, index, scale, 0);
      disp = (int32_t)read_i32(p + *io_i);
      *io_i += 4;
      return make_mem(width, base, index, scale, disp);
    }

    base = bas;

    size_t used = read_disp_by_mod(p + *io_i, n - *io_i, mod, &disp);
    if (mod == 1 || mod == 2) {
      if (used == 0) return make_mem(width, base, index, scale, 0);
      *io_i += used;
    }

    return make_mem(width, base, index, scale, disp);
  }

  // no SIB: RIP-relative
  if (mod == 0 && rm_lo3 == 5) {
    if (*io_i + 4 > n) return make_mem(width, 16 /*rip*/, 0xFF, 1, 0);
    disp = (int32_t)read_i32(p + *io_i);
    *io_i += 4;
    return make_mem(width, 16 /*rip*/, 0xFF, 1, disp);
  }

  // disp for mod 1/2
  size_t used = read_disp_by_mod(p + *io_i, n - *io_i, mod, &disp);
  if (mod == 1 || mod == 2) {
    if (used == 0) return make_mem(width, base, 0xFF, 1, 0);
    *io_i += used;
  }

  return make_mem(width, base, 0xFF, 1, disp);
}

static Op grp_alu_op(uint8_t subop) {
  // minimal subset (expand later)
  if (subop == 0) return OP_ADD; // /0
  if (subop == 4) return OP_AND; // /4
  if (subop == 5) return OP_SUB; // /5
  if (subop == 7) return OP_CMP; // /7
  return OP_INVALID;
}

size_t decode_one(const DecodeCtx *ctx, const uint8_t *p, size_t n, uint64_t addr, Insn *out) {
  if (!ctx || !p || !out || n == 0) return 0;

  insn_init(out, addr);

  size_t i = 0;

  // ENDBR64: F3 0F 1E FA
  if (ctx->is64 && n >= 4 && p[0] == 0xF3 && p[1] == 0x0F && p[2] == 0x1E && p[3] == 0xFA) {
    out->op = OP_ENDBR;
    out->op_count = 0;
    out->size = 4;
    set_bytes(out, p, 4);
    return 4;
  }

  // legacy prefixes (skip)
  while (i < n) {
    uint8_t b = p[i];
    int is_prefix =
      (b == 0xF0) || (b == 0xF2) || (b == 0xF3) ||
      (b == 0x2E) || (b == 0x36) || (b == 0x3E) || (b == 0x26) ||
      (b == 0x64) || (b == 0x65) ||
      (b == 0x66) || (b == 0x67);
    if (!is_prefix) break;
    i++;
  }

  // REX (after prefixes)
  Rex rex = {0};
  if (ctx->is64 && i < n) {
    uint8_t b = p[i];
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
  if (i >= n) return 0;
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

  // SETcc condition (0F 90..9F)
  if ((op->flags & OF_CC) && out->op == OP_SETCC) {
    out->has_cc = 1;
    out->cc = (Cond)(b2 & 0x0F);
  }

  // rel8 / rel32 (FIXED: compute in int64_t)
  if (op->flags & OF_REL8) {
    if (i + 1 > n) return 0;
    out->has_rel = 1;
    out->rel_width = 1;
    out->rel = read_i8(p + i);
    i += 1;

    int64_t next = (int64_t)(addr + i);
    int64_t tgt  = next + out->rel;

    out->op_count = 1;
    out->ops[0] = make_imm(64, tgt);
  } else if (op->flags & OF_REL32) {
    if (i + 4 > n) return 0;
    out->has_rel = 1;
    out->rel_width = 4;
    out->rel = read_i32(p + i);
    i += 4;

    int64_t next = (int64_t)(addr + i);
    int64_t tgt  = next + out->rel;

    out->op_count = 1;
    out->ops[0] = make_imm(64, tgt);
  }

  // push/pop reg ranges
  if (out->op == OP_PUSH || out->op == OP_POP) {
    uint8_t low = (uint8_t)(b1 & 7);
    uint8_t reg = (uint8_t)(low | (rex.rex_b ? 8 : 0));
    out->op_count = 1;
    out->ops[0] = make_reg(64, reg);
  }

  // mov r32/r64, imm (B8..BF)
  if ((op->flags & OF_MOV_IMM_REG) && (op->flags & OF_REG_RANGE)) {
    uint8_t low = (uint8_t)(b1 & 7);
    uint8_t reg = (uint8_t)(low | (rex.rex_b ? 8 : 0));
    uint8_t width = rex.rex_w ? 64 : 32;

    int64_t imm = 0;
    if (width == 64) {
      if (i + 8 > n) return 0;
      uint64_t v =
        (uint64_t)p[i+0] |
        ((uint64_t)p[i+1] << 8) |
        ((uint64_t)p[i+2] << 16) |
        ((uint64_t)p[i+3] << 24) |
        ((uint64_t)p[i+4] << 32) |
        ((uint64_t)p[i+5] << 40) |
        ((uint64_t)p[i+6] << 48) |
        ((uint64_t)p[i+7] << 56);
      imm = (int64_t)v;
      i += 8;
    } else {
      if (i + 4 > n) return 0;
      imm = read_i32(p + i);
      i += 4;
    }

    out->op = OP_MOV;
    out->op_count = 2;
    out->ops[0] = make_reg(width, reg);
    out->ops[1] = make_imm(width, imm);

    out->size = (uint8_t)i;
    set_bytes(out, p, i);
    return i;
  }

  // ModRM family
  if (op->flags & OF_MODRM) {
    if (i >= n) return 0;

    uint8_t modrm = p[i++];
    uint8_t mod = get_mod(modrm);

    uint8_t subop = get_reg3(modrm); // group selector (NO rex.r extension)

    uint8_t reg_ext = (uint8_t)(get_reg3(modrm) | (rex.rex_r ? 8 : 0));
    uint8_t rm_lo3  = get_rm3(modrm);
    uint8_t rm_ext  = (uint8_t)(rm_lo3 | (rex.rex_b ? 8 : 0));

    int is_mem = (mod != 3);

    // width per opcode (MVP):
    // SETcc and OR(0x08) are 8-bit.
    uint8_t width = (b1 == 0x08 || out->op == OP_SETCC) ? 8 : (rex.rex_w ? 64 : 32);

    // group 81/83: add/sub/cmp/and
    if (op->flags & (OF_GRP81 | OF_GRP83)) {
      Op gop = grp_alu_op(subop);
      if (gop == OP_INVALID) {
        out->op = OP_INVALID;
        out->op_count = 0;
      } else {
        out->op = gop;

        Operand dst = rm_to_operand(&rex, p, n, &i, width, mod, rm_lo3, rm_ext, is_mem);

        int64_t imm = 0;
        if (op->flags & OF_GRP83) {
          if (i + 1 > n) return 0;
          imm = read_i8(p + i);
          i += 1;
        } else {
          if (i + 4 > n) return 0;
          imm = read_i32(p + i);
          i += 4;
        }

        out->op_count = 2;
        out->ops[0] = dst;
        out->ops[1] = make_imm(width, imm);
      }

      out->size = (uint8_t)i;
      set_bytes(out, p, i);
      return i;
    }

    // SETcc: 0F 90..9F /r  => setcc r/m8
    if (out->op == OP_SETCC) {
      Operand dst = rm_to_operand(&rex, p, n, &i, 8, mod, rm_lo3, rm_ext, is_mem);
      out->op_count = 1;
      out->ops[0] = dst;

      out->size = (uint8_t)i;
      set_bytes(out, p, i);
      return i;
    }

    Operand o_reg = make_reg(width, reg_ext);
    Operand o_rm  = rm_to_operand(&rex, p, n, &i, width, mod, rm_lo3, rm_ext, is_mem);

    if (b1 == 0x89) {          // mov r/m, r
      out->op = OP_MOV;
      out->op_count = 2;
      out->ops[0] = o_rm;
      out->ops[1] = o_reg;
    } else if (b1 == 0x8B) {   // mov r, r/m
      out->op = OP_MOV;
      out->op_count = 2;
      out->ops[0] = o_reg;
      out->ops[1] = o_rm;
    } else if (b1 == 0x8D) {   // lea r, m
      out->op = OP_LEA;
      out->op_count = 2;
      out->ops[0] = o_reg;
      out->ops[1] = o_rm;
    } else if (b1 == 0x31) {   // xor r/m, r
      out->op = OP_XOR;
      out->op_count = 2;
      out->ops[0] = o_rm;
      out->ops[1] = o_reg;
    } else if (b1 == 0x08) {   // or r/m8, r8   (NEW)
      out->op = OP_OR;
      out->op_count = 2;
      out->ops[0] = o_rm;
      out->ops[1] = o_reg;
    } else if (b1 == 0x39) {   // cmp r/m, r   (NEW)
      out->op = OP_CMP;
      out->op_count = 2;
      out->ops[0] = o_rm;
      out->ops[1] = o_reg;
    } else if (b1 == 0x85) {   // test r/m, r
      out->op = OP_TEST;
      out->op_count = 2;
      out->ops[0] = o_rm;
      out->ops[1] = o_reg;
    }
  }

  out->size = (uint8_t)i;
  set_bytes(out, p, i);
  return i;
}
