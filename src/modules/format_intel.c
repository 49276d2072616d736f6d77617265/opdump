#include <stdio.h>
#include <stdint.h>
#include "opdump/format.h"

static const char* reg64(uint8_t r) {
  static const char *names[17] = {
    "rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
    "r8","r9","r10","r11","r12","r13","r14","r15",
    "rip"
  };
  if (r < 17) return names[r];
  return "r?";
}

static const char* reg32(uint8_t r) {
  static const char *names[16] = {
    "eax","ecx","edx","ebx","esp","ebp","esi","edi",
    "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d"
  };
  if (r < 16) return names[r];
  return "r?d";
}

static const char* reg16(uint8_t r) {
  static const char *names[16] = {
    "ax","cx","dx","bx","sp","bp","si","di",
    "r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w"
  };
  if (r < 16) return names[r];
  return "r?w";
}

static const char* reg8(uint8_t r) {
  static const char *names[16] = {
    "al","cl","dl","bl","spl","bpl","sil","dil",
    "r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b"
  };
  if (r < 16) return names[r];
  return "r?b";
}

static const char* regxmm(uint8_t r) {
  static const char *names[16] = {
    "xmm0","xmm1","xmm2","xmm3","xmm4","xmm5","xmm6","xmm7",
    "xmm8","xmm9","xmm10","xmm11","xmm12","xmm13","xmm14","xmm15"
  };
  if (r < 16) return names[r];
  return "xmm?";
}

const char* reg_name64(uint8_t r) { return reg64(r); }

const char* cc_name(Cond cc) {
  static const char *ccs[16] = {
    "o","no","b","ae","e","ne","be","a","s","ns","p","np","l","ge","le","g"
  };
  if ((unsigned)cc < 16) return ccs[cc];
  return "?";
}

static const char* op_name(Op op) {
  switch (op) {
    case OP_RET:      return "ret";
    case OP_CALL_REL: return "call";
    case OP_JMP_REL:  return "jmp";
    case OP_JCC_REL:  return "jcc";

    case OP_CALL_RM:  return "call";
    case OP_JMP_RM:   return "jmp";

    case OP_PUSH: return "push";
    case OP_POP:  return "pop";

    case OP_MOV:  return "mov";
    case OP_LEA:  return "lea";
    case OP_XOR:  return "xor";
    case OP_AND:  return "and";
    case OP_OR:   return "or";
    case OP_ADD:  return "add";
    case OP_SUB:  return "sub";
    case OP_CMP:  return "cmp";
    case OP_TEST: return "test";

    case OP_NOP:   return "nop";
    case OP_CLI:   return "cli";
    case OP_ENDBR: return "endbr64";

    case OP_SETCC: return "setcc";
    case OP_PXOR:  return "pxor";

    default: return "db";
  }
}

static void print_disp(FILE *out, int32_t disp, int wrote_any) {
  if (disp == 0) return;

  if (!wrote_any) {
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

  if (o->mem.base != 0xFF) {
    fprintf(out, "%s", reg64(o->mem.base));
    wrote = 1;
  }

  if (o->mem.index != 0xFF) {
    if (wrote) fprintf(out, "+");
    fprintf(out, "%s", reg64(o->mem.index));
    if (o->mem.scale != 1) fprintf(out, "*%u", (unsigned)o->mem.scale);
    wrote = 1;
  }

  print_disp(out, o->mem.disp, wrote);
  fprintf(out, "]");
}

static void print_reg(FILE *out, uint8_t reg, uint8_t width) {
  switch (width) {
    case 8:   fprintf(out, "%s", reg8(reg));  break;
    case 16:  fprintf(out, "%s", reg16(reg)); break;
    case 32:  fprintf(out, "%s", reg32(reg)); break;
    case 128: fprintf(out, "%s", regxmm(reg)); break;
    default:  fprintf(out, "%s", reg64(reg)); break; // 64
  }
}

static void print_operand(FILE *out, const Operand *o) {
  switch (o->kind) {
    case O_REG:
      print_reg(out, o->reg, o->width);
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
  } else if (in->op == OP_SETCC && in->has_cc) {
    fprintf(out, "set%s ", cc_name(in->cc));
  } else {
    fprintf(out, "%s ", op_name(in->op));
  }

  for (uint8_t i = 0; i < in->op_count; i++) {
    if (i) fprintf(out, ", ");
    print_operand(out, &in->ops[i]);
  }
}
