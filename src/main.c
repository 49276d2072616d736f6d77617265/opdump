#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "opdump/elf64.h"
#include "opdump/decode.h"
#include "opdump/format.h"   // format_intel(...)
#include "opdump/insn.h"

static int read_all(const char *path, uint8_t **out_buf, size_t *out_sz) {
  *out_buf = NULL; *out_sz = 0;
  FILE *f = fopen(path, "rb");
  if (!f) return 0;
  if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return 0; }
  long len = ftell(f);
  if (len < 0) { fclose(f); return 0; }
  if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return 0; }

  uint8_t *buf = (uint8_t*)malloc((size_t)len);
  if (!buf) { fclose(f); return 0; }

  size_t got = fread(buf, 1, (size_t)len, f);
  fclose(f);
  if (got != (size_t)len) { free(buf); return 0; }

  *out_buf = buf;
  *out_sz = (size_t)len;
  return 1;
}

static void dump_segment(const uint8_t *buf, size_t n, const ElfExecSeg *seg) {
  const uint64_t off0 = seg->offset;
  const uint64_t off1 = seg->offset + seg->filesz;

  DecodeCtx ctx = {0};
  ctx.is64 = 1;

  uint64_t cursor = off0;
  while (cursor < off1) {
    uint64_t addr = seg->vaddr + (cursor - off0);

    Insn ins;
    size_t remain = (size_t)(off1 - cursor);
    size_t used = decode_one(&ctx, buf + cursor, remain, addr, &ins);

    if (used == 0) {
      // fallback safe: emit db for 1 byte to avoid infinite loop
      printf("%016llx  %02x                      db\n",
        (unsigned long long)addr, (unsigned)buf[cursor]);
      cursor += 1;
      continue;
    }

    // print bytes (up to 16)
    printf("%016llx  ", (unsigned long long)ins.addr);
    for (uint8_t i = 0; i < ins.bytes_len; i++) {
      printf("%02x ", (unsigned)ins.bytes[i]);
    }
    // simple padding
    for (uint8_t i = ins.bytes_len; i < 12; i++) printf("   ");

    format_intel(stdout, &ins);
    printf("\n");

    cursor += used;
  }
}

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s <elf>\n", argv[0]);
    return 1;
  }

  uint8_t *buf = NULL;
  size_t n = 0;
  if (!read_all(argv[1], &buf, &n)) {
    fprintf(stderr, "Error: cannot read file\n");
    return 2;
  }

  ElfInfo info;
  if (!elf64_parse_info(buf, n, &info)) {
    fprintf(stderr, "Error: not supported ELF64 (LE)\n");
    free(buf);
    return 3;
  }

  ElfExecSeg segs[32];
  size_t seg_count = elf64_collect_exec_segments(buf, n, segs, 32);
  if (seg_count == 0) {
    fprintf(stderr, "Error: no executable PT_LOAD segments\n");
    free(buf);
    return 4;
  }

  for (size_t i = 0; i < seg_count && i < 32; i++) {
    dump_segment(buf, n, &segs[i]);
  }

  free(buf);
  return 0;
}
