# Minimal C guest for the SP1 zkEVM SDK.
#
# Build:
#   make SDK_DIR=/path/to/extracted/zkevm-sdk-vX.Y.Z
#
# Override `CC` / `LD` on the command line if `clang` / `ld.lld` aren't
# on PATH under their default names.

SDK_DIR ?= ../zkevm-sdk-0.1.0-pre

# `?=` won't do here: make pre-defines CC=cc and LD=ld as builtin
# defaults, so only an `origin` check distinguishes "unset" from
# "explicitly overridden on the command line / environment".
ifeq ($(origin CC),default)
CC := clang
endif
ifeq ($(origin LD),default)
LD := ld.lld
endif

CFLAGS = --target=riscv64-unknown-none-elf \
         -march=rv64im -mabi=lp64 \
         -ffreestanding -fno-builtin -fno-stack-protector -nostdlibinc \
         -O2 -Wall -Wextra \
         -I$(SDK_DIR)/include

LDFLAGS = -nostdlib -static -T$(SDK_DIR)/zkvm.ld

.PHONY: all clean
all: guest.elf

main.o: main.c
	$(CC) $(CFLAGS) -c -o $@ $<

guest.elf: main.o $(SDK_DIR)/libzkevm.a
	$(LD) $(LDFLAGS) -o $@ main.o $(SDK_DIR)/libzkevm.a

clean:
	rm -f main.o guest.elf
