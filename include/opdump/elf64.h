#pragma once
#include <stdint.h>
#include <stddef.h>

typedef struct {
  uint64_t vaddr;   // virtual address start
  uint64_t memsz;   // p_memsz
  uint64_t filesz;  // p_filesz
  uint64_t offset;  // file offset
  uint32_t flags;   // p_flags
} ElfExecSeg;

typedef struct {
  int ok;
  int is64;
  int little;
  uint16_t e_type;
  uint16_t e_machine;
  uint64_t e_entry;

  uint64_t phoff;
  uint16_t phentsz;
  uint16_t phnum;
} ElfInfo;

int elf64_parse_info(const uint8_t *buf, size_t n, ElfInfo *out);

/**
 * Itera segmentos executáveis (PT_LOAD + PF_X).
 * Retorna quantidade de segmentos retornados em out_segs (até cap).
 */
size_t elf64_collect_exec_segments(const uint8_t *buf, size_t n,
                                   ElfExecSeg *out_segs, size_t cap);
