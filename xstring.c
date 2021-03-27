#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdatomic.h>


#include "xstring.h"

static struct __cstr_interning __cstr_ctx = {.lock = ATOMIC_FLAG_INIT};

static void xs_allocate_data(xs *x, size_t len, bool reallocate) {
  /* Medium string */
  if (len < LARGE_STRING_LEN) {
    x->ptr = reallocate ? realloc(x->ptr, (size_t)1 << x->capacity)
                        : malloc((size_t)1 << x->capacity);
    return;
  }

  /* Large string */
  x->is_large_string = 1;

  /* The extra 4 bytes are used to store the reference count */
  x->ptr = reallocate ? realloc(x->ptr, (size_t)(1 << x->capacity) + 4)
                      : malloc((size_t)(1 << x->capacity) + 4);

  xs_set_refcnt(x, 1);
}

static inline xs *xs_newempty(xs *x) {
  *x = xs_literal_empty();
  return x;
}

static inline xs *xs_free(xs *x) {
  if (x->sharing)
    return NULL;

  if (xs_is_ptr(x) && xs_dec_refcnt(x) <= 0)
    free(x->ptr);
  return xs_newempty(x);
}

//////////////////////////////////////////////////////////////////////

static void *xalloc(size_t n) {
  void *m = malloc(n);
  if (!m)
    exit(-1);
  return m;
}

static inline void insert_node(struct __cstr_node **hash, int sz,
                               struct __cstr_node *node) {
  size_t h = xs_size(&node->str);
  int index = h & (sz - 1);
  node->next = hash[index];
  hash[index] = node;
}

static void expand(struct __cstr_interning *si) {
  unsigned new_size = si->size * 2;
  if (new_size < HASH_START_SIZE)
    new_size = HASH_START_SIZE;

  struct __cstr_node **new_hash =
      xalloc(sizeof(struct __cstr_node *) * new_size);
  memset(new_hash, 0, sizeof(struct __cstr_node *) * new_size);

  for (unsigned i = 0; i < si->size; ++i) {
    struct __cstr_node *node = si->hash[i];
    while (node) {
      struct __cstr_node *tmp = node->next;
      insert_node(new_hash, new_size, node);
      node = tmp;
    }
  }

  free(si->hash);
  si->hash = new_hash;
  si->size = new_size;
}

static xs *interning(struct __cstr_interning *si, const char *cstr, size_t sz,
                     size_t hash) {
  if (!si->hash)
    return NULL;

  size_t index = (size_t)(hash & (si->size - 1));
  struct __cstr_node *n = si->hash[index];
  while (n) {
    if (n->hash_size == hash) {
      if (!strcmp(xs_data(&n->str), cstr)) {
        return &n->str;
      }
    }
    n = n->next;
  }

  // 80% (4/5) threshold
  if (si->total * 5 >= si->size * 4)
    return NULL;
  // first call
  if (!si->pool) {
    si->pool = xalloc(sizeof(struct __cstr_pool));
    si->index = 0;
  }

  // add leader in pool
  n = &si->pool->node[si->index++];
  n->hash_size = hash;
  n->str = xs_literal_empty();
  n->str.capacity = ilog2(sz) + 1;
  n->str.size = sz;
  n->str.is_ptr = true;
  n->str.sharing = false;
  n->str.reclaim = false;
  xs_allocate_data(&n->str, n->str.size, 0);
  memcpy(xs_data(&n->str), cstr, sz + 1);

  xs_reclaim_data(&n->str, 1);
  n->str.sharing = true;

  n->next = si->hash[index];
  si->hash[index] = n;

  return &n->str;
}

static xs *cstr_interning(const char *cstr, size_t sz, uint32_t hash) {
  CSTR_LOCK();
  xs *ret = NULL;
  ret = interning(&__cstr_ctx, cstr, sz, hash);
  if (!ret) {
    expand(&__cstr_ctx);
    ret = interning(&__cstr_ctx, cstr, sz, hash);
  }
  ++__cstr_ctx.total;
  CSTR_UNLOCK();
  return ret;
}

static inline uint32_t hash_blob(const char *buffer, size_t len) {
  const uint8_t *ptr = (const uint8_t *)buffer;
  size_t h = len;
  size_t step = (len >> 5) + 1;
  for (size_t i = len; i >= step; i -= step)
    h = h ^ ((h << 5) + (h >> 2) + ptr[i - 1]);
  return h == 0 ? 1 : h;
}

//////////////////////////////////////////////////////////////////////

void __xs_cow_write(xs *dest) {
  if (!xs_is_ptr(dest) && !dest->sharing)
    return;

  CSTR_LOCK();
  xs *src =
      cstr_interning(xs_data(dest), xs_size(dest), hash_blob(xs_data(dest), xs_size(dest)));
  xs_dec_refcnt(src);
  if (xs_get_refcnt(src) < 0)
    xs_set_refcnt(src, 0);
  CSTR_UNLOCK();

  dest->sharing = false;
  char *temp = xs_data(dest);
  xs_allocate_data(dest, dest->size, 0);
  memcpy(xs_data(dest), temp, xs_size(dest));
}

void __xs_cow_write_end(xs *dest) {
    xs tmp;
    xs_new(&tmp, xs_data(dest));
    dest->sharing = false;
    xs_set_refcnt(dest, 0);
    xs_free(dest);
    memcpy(dest, &tmp, sizeof(xs));
}

//////////////////////////////////////////////////////////////////////

xs *xs_new(xs *x, const void *p) {
  size_t len = strlen(p) + 1;
  if (len > 16) {
    xs *temp = cstr_interning((char *)p, len - 1, hash_blob((char *)p, len - 1));
    memcpy(x, temp, sizeof(xs));
  } else {
    *x = xs_literal_empty();
    memcpy(x->data, p, len);
    x->space_left = 15 - (len - 1);
  }
  return x;
}

/* grow up to specified size */
// fix
xs *xs_grow(xs *x, size_t len) {
  char buf[16];

  if (len <= xs_capacity(x))
    return x;

  CSTR_LOCK();
  /* Backup first */
  if (!xs_is_ptr(x))
    memcpy(buf, x->data, 16);

  x->is_ptr = true;
  x->capacity = ilog2(len) + 1;

  if (xs_is_ptr(x)) {
    xs_allocate_data(x, len, 1);
  } else {
    xs_allocate_data(x, len, 0);
    memcpy(xs_data(x), buf, 16);
  }
  CSTR_UNLOCK();
  return x;
}

void xs_reclaim_data(xs *x, bool fixed) {
  if (!xs_is_ptr(x) || x->sharing)
    return;
  
  if (fixed) {
    if (xs_is_large_string(x))
      x->ptr = realloc(x->ptr, x->size + 1 + 4);
    else 
      x->ptr = realloc(x->ptr, x->size + 1);
    x->reclaim = true;
  }
  else {
    if (xs_is_large_string(x))
      x->ptr = realloc(x->ptr, (size_t)(1 << x->capacity) + 4);
    else 
      x->ptr = realloc(x->ptr, (size_t)(1 << x->capacity));
    x->reclaim = false;
  }
}

///////////////////////////////////////////////////////////////////////////////////////////

xs *xs_concat(xs *string, const xs *prefix, const xs *suffix) {
  size_t pres = xs_size(prefix), sufs = xs_size(suffix), size = xs_size(string),
         capacity = xs_capacity(string);

  char *pre = xs_data(prefix), *suf = xs_data(suffix), *data = xs_data(string);

  if (size + pres + sufs <= capacity) {
    memmove(data + pres, data, size);
    memcpy(data, pre, pres);
    memcpy(data + pres + size, suf, sufs + 1);

    if (xs_is_ptr(string))
      string->size = size + pres + sufs;
    else
      string->space_left = 15 - (size + pres + sufs);
  } else {
    xs tmps = xs_literal_empty();
    xs_grow(&tmps, size + pres + sufs);
    char *tmpdata = xs_data(&tmps);
    memcpy(tmpdata + pres, data, size);
    memcpy(tmpdata, pre, pres);
    memcpy(tmpdata + pres + size, suf, sufs + 1);
    xs_free(string);
    *string = tmps;
    string->size = size + pres + sufs;
  }
  return string;
}

xs *xs_trim(xs *x, const char *trimset) {
  if (!trimset[0])
    return x;

  char *dataptr = xs_data(x), *orig = dataptr;

  /* similar to strspn/strpbrk but it operates on binary data */
  uint8_t mask[32] = {0};

#define check_bit(byte) (mask[(uint8_t)byte / 8] & 1 << (uint8_t)byte % 8)
#define set_bit(byte) (mask[(uint8_t)byte / 8] |= 1 << (uint8_t)byte % 8)
  size_t i, slen = xs_size(x), trimlen = strlen(trimset);

  for (i = 0; i < trimlen; i++)
    set_bit(trimset[i]);
  for (i = 0; i < slen; i++)
    if (!check_bit(dataptr[i]))
      break;
  for (; slen > 0; slen--)
    if (!check_bit(dataptr[slen - 1]))
      break;
  dataptr += i;
  slen -= i;
  memmove(orig, dataptr, slen);
  /* do not dirty memory unless it is needed */
  if (orig[slen])
    orig[slen] = 0;

  if (xs_is_ptr(x))
    x->size = slen;
  else
    x->space_left = 15 - slen;
  return x;
#undef check_bit
#undef set_bit
}

/////////////////////////////////////////////////////////////////////

xs *xs_new_self(xs *x, const void *p) {
  *x = xs_literal_empty();
  size_t len = strlen(p) + 1;
  if (len > 16) {
    x->capacity = ilog2(len) + 1;
    x->size = len - 1;
    x->is_ptr = true;
    x->sharing = false;
    x->reclaim = false;
    xs_allocate_data(x, x->size, 0);
    memcpy(xs_data(x), p, len);
  } else {
    memcpy(x->data, p, len);
    x->space_left = 15 - (len - 1);
  }
  return x;
}

bool xs_cow_copy_self(xs *dest, xs *src) {
  if (xs_is_ptr(src) && xs_is_large_string(src)) {
    if (!dest->sharing)
      xs_free(dest);
    memcpy(dest, src, sizeof(xs));
    dest->sharing = true;
    xs_set_refcnt(dest, 1);
    xs_inc_refcnt(src);
    return true;
  }
  return false;
}

// src can not dec_refcnt
void __xs_cow_write_self(xs *dest, xs *src) {
  if (!xs_is_ptr(dest) && !xs_is_ptr(src) &&
      !strncmp(xs_data(dest), xs_data(src), xs_size(src)))
    return;
  dest->sharing = false;
  char *temp = xs_data(dest);
  xs_allocate_data(dest, dest->size, 0);
  memcpy(xs_data(dest), temp, xs_size(dest));

  xs_dec_refcnt(src);
  if (xs_get_refcnt(src) < 1)
    xs_free(src);
}