#pragma once
#include <stdint.h>
#include <stddef.h>

typedef struct ElfTextView {
  const uint8_t *text;
  uint64_t text_size;
  uint64_t text_addr;   // virtual address from section header
  uint64_t file_off;    // file offset of .text
  uint64_t entry;       // e_entry
} ElfTextView;

// Return 0 on success
int elf64_find_text(const uint8_t *data, uint64_t size, ElfTextView *out);
