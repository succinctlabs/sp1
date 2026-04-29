/*
 * <assert.h> — minimal freestanding shim for SP1 zkVM C guests.
 *
 * The SP1 C build is `-nostdlibinc`, so glibc/musl `<assert.h>` is
 * unavailable. This shim provides the standard glibc-shape `assert`
 * macro routed through `__assert_fail`, which libzkevm's `halt` module
 * implements as `zkvm_halt(1)`.
 */

#ifndef ZKVM_ASSERT_H
#define ZKVM_ASSERT_H

#ifdef __cplusplus
extern "C" {
#endif

extern void __assert_fail(const char *__assertion, const char *__file,
                          unsigned int __line, const char *__function)
    __attribute__((__noreturn__));

#ifdef NDEBUG
#define assert(expr) ((void)0)
#else
#define assert(expr)                                                           \
  ((expr) ? (void)0                                                            \
          : __assert_fail(#expr, __FILE__, __LINE__, __extension__ __PRETTY_FUNCTION__))
#endif

#ifdef __cplusplus
}
#endif

#endif /* ZKVM_ASSERT_H */
