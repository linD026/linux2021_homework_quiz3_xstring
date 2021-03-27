#ifndef __XSTRING_H_
#define __XSTRING_H_

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_STR_LEN_BITS (54)
#define MAX_STR_LEN ((1UL << MAX_STR_LEN_BITS) - 1)

#define LARGE_STRING_LEN 256

typedef union {
  char data[16];

  // stack
  struct {
    uint8_t filler[15], space_left : 4, is_ptr : 1, is_large_string : 1,
        sharing : 1, reclaim : 1;
  };

  /* heap allocated */
  struct {
    char *ptr;
    /* supports strings up to 2^MAX_STR_LEN_BITS - 1 bytes */
    size_t size : MAX_STR_LEN_BITS,
                  /* capacity is always a power of 2 (unsigned)-1 */
                  capacity : 6;
    /* the last 4 bits are important flags */
  };
} xs;

static inline bool xs_is_ptr(const xs *x) { return x->is_ptr; }

static inline bool xs_is_large_string(const xs *x) {
  return x->is_large_string;
}

static inline size_t xs_size(const xs *x) {
  return xs_is_ptr(x) ? x->size : 15 - x->space_left;
}

static inline char *xs_data(const xs *x) {
  if (!xs_is_ptr(x))
    return (char *)x->data;

  if (xs_is_large_string(x))
    return (char *)(x->ptr + 4);

  return (char *)x->ptr;
}

static inline size_t xs_capacity(const xs *x) {
  return xs_is_ptr(x) ? ((size_t)1 << x->capacity) - 1 : 15;
}

static inline void xs_set_refcnt(const xs *x, int val) {
  *((int *)((size_t)x->ptr)) = val;
}

static inline void xs_inc_refcnt(const xs *x) {
  if (xs_is_large_string(x))
    ++(*(int *)((size_t)x->ptr));
}

static inline int xs_dec_refcnt(const xs *x) {
  if (!xs_is_large_string(x))
    return 0;
  return --(*(int *)((size_t)x->ptr));
}

static inline int xs_get_refcnt(const xs *x) {
  if (!xs_is_large_string(x))
    return 0;
  return *(int *)((size_t)x->ptr);
}

#define xs_literal_empty()                                                     \
  (xs) { .space_left = 15 }

/* lowerbound (floor log2) */
static inline int ilog2(uint32_t n) { return 32 - __builtin_clz(n) - 1; }

#define xs_tmp(x)                                                              \
  ((void)((struct {                                                            \
     _Static_assert(sizeof(x) <= MAX_STR_LEN, "it is too big");                \
     int dummy;                                                                \
   }){1}),                                                                     \
   xs_new(&xs_literal_empty(), x))

xs *xs_new(xs *x, const void *p);
xs *xs_grow(xs *x, size_t len);
xs *xs_concat(xs *string, const xs *prefix, const xs *suffix);
xs *xs_trim(xs *x, const char *trimset);
void xs_reclaim_data(xs *x, bool fixed);

void __xs_cow_write(xs *dest);
void __xs_cow_write_end(xs *dest);

#define xs_cow_write_trim(cpy, trimeset)                                       \
  do {                                                                         \
    __xs_cow_write(cpy);                                                       \
    xs_trim(cpy, trimeset);                                                    \
    __xs_cow_write_end(cpy);                                                   \
  } while (0)

#define xs_cow_write_concat(cpy, prefix, suffix)                               \
  do {                                                                         \
    __xs_cow_write(cpy);                                                       \
    xs_concat(cpy, prefix, suffix);                                            \
  } while (0)

xs *xs_new_self(xs *x, const void *p);
bool xs_cow_copy_self(xs *dest, xs *src);
void __xs_cow_write_self(xs *dest, xs *src);

#define xs_cow_write_trim_self(cpy, trimeset, src)                                  \
  do {                                                                         \
    __xs_cow_write_self(cpy, src);                                                       \
    xs_trim(cpy, trimeset);                                                     \
  } while (0)

#define xs_cow_write_concat_self(cpy, prefix, suffix, src)                          \
  do {                                                                         \
    __xs_cow_write_self(cpy, src);                                                  \
    xs_concat(cpy, prefix, suffix);                                            \
  } while (0)

///////////////////////////////////////////////////////////////////////////

#define INTERNING_POOL_SIZE 1024

#define HASH_START_SIZE 16 /* must be power of 2 */

struct __cstr_node {
  xs str;
  uint32_t hash_size;
  struct __cstr_node *next;
};

struct __cstr_pool {
  struct __cstr_node node[INTERNING_POOL_SIZE];
};

struct __cstr_interning {
  volatile atomic_flag lock;
  int index;
  unsigned size;
  unsigned total;
  struct __cstr_node **hash;
  struct __cstr_pool *pool;
};

#define CSTR_LOCK()                                                            \
  ({                                                                           \
    while (atomic_flag_test_and_set(&(__cstr_ctx.lock))) {                     \
    }                                                                          \
  })

#define CSTR_UNLOCK() ({ atomic_flag_clear(&(__cstr_ctx.lock)); })

#endif