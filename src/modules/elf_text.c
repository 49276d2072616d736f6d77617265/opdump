#include <string.h>
#include "opdump/elf_text.h"

static uint16_t rd16le(const uint8_t *p){ return (uint16_t)(p[0] | (p[1]<<8)); }
static uint32_t rd32le(const uint8_t *p){ return (uint32_t)(p[0] | (p[1]<<8) | (p[2]<<16) | (p[3]<<24)); }
static uint64_t rd64le(const uint8_t *p){
  return (uint64_t)rd32le(p) | ((uint64_t)rd32le(p+4) << 32);
}

int elf64_find_text(const uint8_t *d, uint64_t n, ElfTextView *out) {
  if (!d || !out || n < 64) return 1;
  memset(out, 0, sizeof(*out));

  if (!(d[0]==0x7F && d[1]=='E' && d[2]=='L' && d[3]=='F')) return 2;
  if (d[4] != 2) return 3; // not ELF64
  if (d[5] != 1) return 4; // only little-endian MVP

  uint64_t e_entry = rd64le(d + 24);
  uint64_t e_shoff = rd64le(d + 40);
  uint16_t e_shentsize = rd16le(d + 58);
  uint16_t e_shnum = rd16le(d + 60);
  uint16_t e_shstrndx = rd16le(d + 62);

  if (e_shoff == 0 || e_shentsize < 64 || e_shnum == 0) return 5;
  if (e_shoff + (uint64_t)e_shentsize * (uint64_t)e_shnum > n) return 6;
  if (e_shstrndx >= e_shnum) return 7;

  const uint8_t *sh_base = d + e_shoff;
  const uint8_t *sh_str  = sh_base + (uint64_t)e_shentsize * (uint64_t)e_shstrndx;

  uint64_t shstr_off  = rd64le(sh_str + 24);
  uint64_t shstr_size = rd64le(sh_str + 32);
  if (shstr_off + shstr_size > n) return 8;

  const char *strtab = (const char *)(d + shstr_off);

  for (uint16_t i = 0; i < e_shnum; i++) {
    const uint8_t *sh = sh_base + (uint64_t)e_shentsize * i;
    uint32_t sh_name = rd32le(sh + 0);
    if ((uint64_t)sh_name >= shstr_size) continue;

    const char *name = strtab + sh_name;
    if (strcmp(name, ".text") != 0) continue;

    uint64_t sh_addr   = rd64le(sh + 16);
    uint64_t sh_offset = rd64le(sh + 24);
    uint64_t sh_size   = rd64le(sh + 32);

    if (sh_offset + sh_size > n) return 9;

    out->text = d + sh_offset;
    out->text_size = sh_size;
    out->text_addr = sh_addr;
    out->file_off = sh_offset;
    out->entry = e_entry;
    return 0;
  }

  return 10; // .text not found
}
