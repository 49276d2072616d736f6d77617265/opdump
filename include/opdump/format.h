#pragma once
#include <stdio.h>
#include "insn.h"

void format_intel(FILE *out, const Insn *in);
const char* reg_name64(uint8_t r);
const char* cc_name(Cond cc);
