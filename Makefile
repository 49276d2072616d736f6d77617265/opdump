CC=cc
CFLAGS=-std=c11 -Wall -Wextra -Wpedantic -Iinclude -O2

BIN=build/opdump

SRCS= \
  src/main.c \
  src/modules/decode_x86_64.c \
  src/modules/opcodes_x86_64.c \
  src/modules/format_intel.c \
  src/modules/elf_text.c

OBJS=$(SRCS:%.c=build/obj/%.o)

all: $(BIN)

build/obj/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(BIN): $(OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

clean:
	rm -rf build/obj $(BIN)

.PHONY: all clean
