#include <stdio.h>
#include "opdump/format.h"

const char* reg_name64(uint8_t r) {
  static const char *names[16] = {
    "rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
    "r8","r9","r10","r11","r12","r13","r14","r15"
  };
  if (r < 16) return names[r];
  return "r?";
}

const char* cc_name(Cond cc) {
  static const char *ccs[16] = {
    "o","no","b","ae","e","ne","be","a","s","ns","p","np","l","ge","le","g"
  };
  if ((unsigned)cc < 16) return ccs[cc];
  return "?";
}

static const char* op_name(Op op, const Insn *in) {
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

static void print_operand(FILE *out, const Operand *o) {
  switch (o->kind) {
    case O_REG:
      fprintf(out, "%s", reg_name64(o->reg));
      break;
    case O_IMM:
      fprintf(out, "0x%llx", (unsigned long long)o->imm);
      break;
    case O_MEM:
      // MVP: minimal memory print; you can expand later
      fprintf(out, "[mem]");
      break;
    default:
      fprintf(out, "?");
  }
}

void format_intel(FILE *out, const Insn *in) {
  // mnemonic
  if (in->op == OP_JCC_REL && in->has_cc) {
    fprintf(out, "j%s ", cc_name(in->cc));
  } else {
    fprintf(out, "%s ", op_name(in->op, in));
  }

  // operands
  for (uint8_t i = 0; i < in->op_count; i++) {
    if (i) fprintf(out, ", ");
    print_operand(out, &in->ops[i]);
  }
}
