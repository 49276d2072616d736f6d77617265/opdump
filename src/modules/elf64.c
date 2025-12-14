#include "opdump/elf64.h"
#include <string.h>

static uint16_t rd16le(const uint8_t *p) {
  return (uint16_t)( (uint16_t)p[0] | ((uint16_t)p[1] << 8) );
}
static uint32_t rd32le(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint64_t rd64le(const uint8_t *p) {
  return (uint64_t)rd32le(p) | ((uint64_t)rd32le(p+4) << 32);
}

enum { EI_CLASS=4, EI_DATA=5 };
enum { ELFCLASS64=2, ELFDATA2LSB=1 };

enum { PT_LOAD = 1 };
enum { PF_X = 1, PF_W = 2, PF_R = 4 };

int elf64_parse_info(const uint8_t *b, size_t n, ElfInfo *out) {
  if (!out) return 0;
  memset(out, 0, sizeof(*out));
  if (!b || n < 64) return 0;

  // Magic
  if (!(b[0] == 0x7F && b[1] == 'E' && b[2] == 'L' && b[3] == 'F')) return 0;

  out->is64 = (b[EI_CLASS] == ELFCLASS64);
  out->little = (b[EI_DATA] == ELFDATA2LSB);
  if (!out->is64 || !out->little) return 0;

  // Offsets are standard ELF64 layout (little-endian)
  out->e_type    = rd16le(b + 16);
  out->e_machine = rd16le(b + 18);
  out->e_entry   = rd64le(b + 24);
  out->phoff     = rd64le(b + 32);
  out->phentsz   = rd16le(b + 54);
  out->phnum     = rd16le(b + 56);

  // sanity
  if (out->phoff == 0 || out->phentsz == 0 || out->phnum == 0) return 0;
  if (out->phentsz < 56) return 0; // ELF64 Phdr size is 56
  if (out->phoff + (uint64_t)out->phentsz * (uint64_t)out->phnum > (uint64_t)n) return 0;

  out->ok = 1;
  return 1;
}

size_t elf64_collect_exec_segments(const uint8_t *b, size_t n,
                                   ElfExecSeg *out_segs, size_t cap) {
  ElfInfo inf;
  if (!elf64_parse_info(b, n, &inf)) return 0;

  size_t count = 0;

  // ELF64_Phdr layout:
  // p_type   u32 @0
  // p_flags  u32 @4
  // p_offset u64 @8
  // p_vaddr  u64 @16
  // p_paddr  u64 @24
  // p_filesz u64 @32
  // p_memsz  u64 @40
  // p_align  u64 @48
  for (uint16_t i = 0; i < inf.phnum; i++) {
    const uint8_t *ph = b + (size_t)inf.phoff + (size_t)i * (size_t)inf.phentsz;

    uint32_t p_type  = rd32le(ph + 0);
    uint32_t p_flags = rd32le(ph + 4);
    uint64_t p_off   = rd64le(ph + 8);
    uint64_t p_vaddr = rd64le(ph + 16);
    uint64_t p_filesz= rd64le(ph + 32);
    uint64_t p_memsz = rd64le(ph + 40);

    if (p_type != PT_LOAD) continue;
    if ((p_flags & PF_X) == 0) continue;
    if (p_filesz == 0) continue;
    if (p_off + p_filesz > (uint64_t)n) continue;

    if (out_segs && count < cap) {
      out_segs[count].vaddr  = p_vaddr;
      out_segs[count].offset = p_off;
      out_segs[count].filesz = p_filesz;
      out_segs[count].memsz  = p_memsz;
      out_segs[count].flags  = p_flags;
    }
    count++;
  }

  // if cap smaller, return how many were actually written? (we return total found)
  return (count <= cap || !out_segs) ? count : cap;
}
