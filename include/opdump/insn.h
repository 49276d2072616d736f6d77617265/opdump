#pragma once
#include <stdint.h>

typedef enum {
  OP_INVALID = 0,

  OP_RET,
  OP_CALL_REL,
  OP_JMP_REL,
  OP_JCC_REL,

  OP_PUSH,
  OP_POP,

  OP_MOV,
  OP_LEA,
  OP_XOR,
  OP_AND,   // NEW
  OP_ADD,
  OP_SUB,
  OP_CMP,
  OP_TEST,

  OP_NOP,
  OP_CLI,
  OP_ENDBR,
  OP_OR,
  OP_SETCC,
  OP_PXOR,


} Op;




typedef enum {
  CC_O=0, CC_NO, CC_B, CC_AE, CC_E, CC_NE, CC_BE, CC_A,
  CC_S, CC_NS, CC_P, CC_NP, CC_L, CC_GE, CC_LE, CC_G
} Cond;

typedef enum { O_NONE=0, O_REG, O_IMM, O_MEM } OperandKind;

typedef struct {
  OperandKind kind;
  uint8_t width; // bits: 8/16/32/64
  union {
    uint8_t reg;      // 0..15 (or 16 for RIP in our printer)
    int64_t imm;
    struct {
      uint8_t base;   // 0..16, or 0xFF none
      uint8_t index;  // 0..15, or 0xFF none
      uint8_t scale;  // 1,2,4,8
      int32_t disp;
    } mem;
  };
} Operand;

typedef struct {
  uint64_t addr;
  uint8_t size;
  uint8_t bytes[16];
  uint8_t bytes_len;

  Op op;
  uint8_t op_count;
  Operand ops[3];

  uint8_t has_cc;
  Cond cc;

  uint8_t has_rel;
  int64_t rel;
  uint8_t rel_width;
} Insn;
