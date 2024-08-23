#include <string.h>
#include <stdint.h>
#include <stdio.h>

#define MEMCPY_32 0x00000131
#define DUMMY_SIZE 1024

void *memcpy(void *restrict dest, const void *restrict src, size_t n)
{
	unsigned char *d = dest;
	const unsigned char *s = src;

#ifdef __GNUC__
#define LS >>
#define RS <<

	for (; (uintptr_t)d % 4 && n; n--) *d++ = *s++;

    for (; n % 4; n--) *(d + n) = *(s + n);

    uintptr_t s_offset = (uintptr_t)s % 4;

    for (; n>=32; s+=32, d+=32, n -=32 ) {
        asm volatile(
        "mv t0, %0\n"
        "mv a0, %1\n"
        "mv a1, %2\n"
        "li a2, 32\n"
        "mv a3, %3\n"
        "ecall"
        : // No output operands
        : "r"(MEMCPY_32), "r"(s), "r"(d), "r"(s_offset)
        : "t0", "a0", "a1", "a2", "a3" // Clobbered registers
        );
    }

    asm volatile(
        "mv t0, %0\n"
        "mv a0, %1\n"
        "mv a1, %2\n"
        "mv a2, %3\n"
        "mv a3, %4\n"
        "ecall"
        : // No output operands
        : "r"(MEMCPY_32), "r"(s), "r"(d), "r"(n), "r"(s_offset)
        : "t0", "a0", "a1", "a2", "a3" // Clobbered registers
    );

	return dest;
#endif

	for (; n; n--) *d++ = *s++;
	return dest;
}