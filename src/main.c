#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "opdump/decode.h"
#include "opdump/format.h"
#include "opdump/elf_text.h"

static void usage(const char *p) {
  fprintf(stderr, "Usage: %s <elf64>\n", p);
}

static uint8_t* read_all(const char *path, size_t *out_sz) {
  *out_sz = 0;
  FILE *f = fopen(path, "rb");
  if (!f) return NULL;
  if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
  long end = ftell(f);
  if (end < 0) { fclose(f); return NULL; }
  if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }

  size_t sz = (size_t)end;
  uint8_t *buf = (uint8_t*)malloc(sz);
  if (!buf) { fclose(f); return NULL; }

  if (fread(buf, 1, sz, f) != sz) { free(buf); fclose(f); return NULL; }
  fclose(f);
  *out_sz = sz;
  return buf;
}

int main(int argc, char **argv) {
  if (argc < 2) { usage(argv[0]); return 2; }
  const char *path = argv[1];

  size_t sz = 0;
  uint8_t *data = read_all(path, &sz);
  if (!data) {
    fprintf(stderr, "Error: failed to read file\n");
    return 1;
  }

  ElfTextView tv;
  int rc = elf64_find_text(data, (uint64_t)sz, &tv);
  if (rc != 0) {
    fprintf(stderr, "Error: ELF64 .text not found / unsupported (code=%d)\n", rc);
    free(data);
    return 1;
  }

  DecodeCtx ctx = { .is64 = 1 };

  uint64_t addr = tv.text_addr;
  const uint8_t *p = tv.text;
  size_t n = (size_t)tv.text_size;

  size_t off = 0;
  while (off < n) {
    Insn ins;
    size_t used = decode_one(&ctx, p + off, n - off, addr + off, &ins);
    if (used == 0) break;

    // print: addr + bytes + asm
    printf("%016llx  ", (unsigned long long)ins.addr);
    for (unsigned i = 0; i < ins.bytes_len; i++) printf("%02x ", ins.bytes[i]);
    for (unsigned i = ins.bytes_len; i < 8; i++) printf("   "); // pad
    format_intel(stdout, &ins);
    printf("\n");

    off += used;
  }

  free(data);
  return 0;
}
