#include <stdio.h>
#include <stdint.h>
#include "opdump/format.h"

const char* reg_name64(uint8_t r) {
  static const char *names[17] = {
    "rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
    "r8","r9","r10","r11","r12","r13","r14","r15",
    "rip"
  };
  if (r < 17) return names[r];
  return "r?";
}

const char* cc_name(Cond cc) {
  static const char *ccs[16] = {
    "o","no","b","ae","e","ne","be","a","s","ns","p","np","l","ge","le","g"
  };
  if ((unsigned)cc < 16) return ccs[cc];
  return "?";
}

static const char* op_name(Op op) {
  switch (op) {
    case OP_RET: return "ret";
    case OP_CALL_REL: return "call";
    case OP_JMP_REL: return "jmp";
    case OP_JCC_REL: return "jcc";
    case OP_PUSH: return "push";
    case OP_POP: return "pop";
    case OP_MOV: return "mov";
    case OP_LEA: return "lea";
    case OP_XOR: return "xor";
    default: return "db";
  }
}

static void print_disp(FILE *out, int32_t disp, int wrote_any) {
  if (disp == 0) return;

  if (!wrote_any) {
    // first term: allow negative directly
    if (disp < 0) fprintf(out, "-0x%x", (unsigned)(uint32_t)(-disp));
    else          fprintf(out, "0x%x",  (unsigned)(uint32_t)disp);
    return;
  }

  if (disp < 0) fprintf(out, "-0x%x", (unsigned)(uint32_t)(-disp));
  else          fprintf(out, "+0x%x",  (unsigned)(uint32_t)disp);
}

static void print_mem(FILE *out, const Operand *o) {
  fprintf(out, "[");

  int wrote = 0;

  // base
  if (o->mem.base != 0xFF) {
    fprintf(out, "%s", reg_name64(o->mem.base));
    wrote = 1;
  }

  // index*scale
  if (o->mem.index != 0xFF) {
    if (wrote) fprintf(out, "+");
    fprintf(out, "%s", reg_name64(o->mem.index));
    if (o->mem.scale != 1) fprintf(out, "*%u", (unsigned)o->mem.scale);
    wrote = 1;
  }

  // disp
  print_disp(out, o->mem.disp, wrote);

  fprintf(out, "]");
}

static void print_operand(FILE *out, const Operand *o) {
  switch (o->kind) {
    case O_REG:
      fprintf(out, "%s", reg_name64(o->reg));
      break;
    case O_IMM:
      fprintf(out, "0x%llx", (unsigned long long)o->imm);
      break;
    case O_MEM:
      print_mem(out, o);
      break;
    default:
      fprintf(out, "?");
  }
}

void format_intel(FILE *out, const Insn *in) {
  if (in->op == OP_JCC_REL && in->has_cc) {
    fprintf(out, "j%s ", cc_name(in->cc));
  } else {
    fprintf(out, "%s ", op_name(in->op));
  }

  for (uint8_t i = 0; i < in->op_count; i++) {
    if (i) fprintf(out, ", ");
    print_operand(out, &in->ops[i]);
  }
}
