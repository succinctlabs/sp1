# hello-c — minimal C program linking against the SP1 zkEVM SDK.
#
# `_start` comes from `sp1-zkvm` (bundled into `libzkevm.a`); no separate
# crt0.o is needed.

SDK_DIR ?= ../../../sdk

CC     ?= clang
LD     ?= ld.lld

CFLAGS  = --target=riscv64-unknown-none-elf \
          -march=rv64im -mabi=lp64 \
          -ffreestanding -fno-builtin -fno-stack-protector -nostdlibinc \
          -O2 -Wall -Wextra \
          -I$(SDK_DIR)/include

LDFLAGS = -nostdlib -static \
          -T $(SDK_DIR)/zkvm.ld \
          -L$(SDK_DIR)

.PHONY: all clean
all: hello.elf

main.o: main.c
	$(CC) $(CFLAGS) -c -o $@ $<

hello.elf: main.o
	$(LD) $(LDFLAGS) -o $@ main.o -lzkevm

clean:
	rm -f main.o hello.elf
