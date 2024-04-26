/**
 *  @file iotsec_mem.c
 *
 *  @brief Source file for the IOTsec memory allocator
 */

#include "iotsec_mem.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

int iotsec_mem_create(iotsec_mem_t *mem, size_t num, size_t len) {
  memset(mem, 0, sizeof(iotsec_mem_t));
  if (((num & 0x7) != 0) || (len == 0)) {
    return -EINVAL;
  }
  mem->buf = (char *)malloc(num * len);
  if (mem->buf == NULL) {
    return -ENOMEM;
  }
  mem->num = num;
  mem->len = len;
  mem->active = (char *)calloc(num >> 3, 1);
  if (mem->active == NULL) {
    free(mem->buf);
    memset(mem, 0, sizeof(iotsec_mem_t));
    return -ENOMEM;
  }
  return 0;
}

void iotsec_mem_destroy(iotsec_mem_t *mem) {
  free(mem->active);
  free(mem->buf);
  memset(mem, 0, sizeof(iotsec_mem_t));
}

void *iotsec_mem_alloc(iotsec_mem_t *mem, size_t len) {
  unsigned char mask = 0;
  size_t byte = 0;
  size_t bit = 0;
  void *mem_buf = NULL;

  if (len > mem->len) {
    return NULL;
  }
  for (byte = 0; byte < iotsec_mem_get_active_len(mem); byte++) {
    for (bit = 0; bit < 8; bit++) {
      mask = (1 << bit);
      if ((mem->active[byte] & mask) == 0) {
        mem->active[byte] |= mask;
        mem_buf = &mem->buf[(8 * byte + bit) * mem->len];
        return mem_buf;
      }
    }
  }
  return NULL;
}

void iotsec_mem_free(iotsec_mem_t *mem, void *buf) {
  unsigned char mask = 0;
  size_t byte = 0;
  size_t bit = 0;
  void *mem_buf = NULL;

  for (byte = 0; byte < iotsec_mem_get_active_len(mem); byte++) {
    for (bit = 0; bit < 8; bit++) {
      mem_buf = &mem->buf[(8 * byte + bit) * mem->len];
      if (buf == mem_buf) {
        mask = ~(1 << bit);
        mem->active[byte] &= mask;
      }
    }
  }
}

/**
 *  Small memory allocator
 *
 *  This memory allocator can be used by any part of the IOTsec  library.
 */
static iotsec_mem_t iotsec_mem_small = {0};

int iotsec_mem_small_create(size_t num, size_t len) {
  return iotsec_mem_create(&iotsec_mem_small, num, len);
}

void iotsec_mem_small_destroy(void) { iotsec_mem_destroy(&iotsec_mem_small); }

char *iotsec_mem_small_get_buf(void) {
  return iotsec_mem_get_buf(&iotsec_mem_small);
}

size_t iotsec_mem_small_get_num(void) {
  return iotsec_mem_get_num(&iotsec_mem_small);
}

size_t iotsec_mem_small_get_len(void) {
  return iotsec_mem_get_len(&iotsec_mem_small);
}

size_t iotsec_mem_small_get_active_len(void) {
  return iotsec_mem_get_active_len(&iotsec_mem_small);
}

char *iotsec_mem_small_get_active(void) { return iotsec_mem_small.active; }

void *iotsec_mem_small_alloc(size_t len) {
  return iotsec_mem_alloc(&iotsec_mem_small, len);
}

void iotsec_mem_small_free(void *buf) {
  iotsec_mem_free(&iotsec_mem_small, buf);
}

/**
 *  Medium memory allocator
 *
 *  This memory allocator can be used by any part of the IOTsec library.
 */
static iotsec_mem_t iotsec_mem_medium = {0};

int iotsec_mem_medium_create(size_t num, size_t len) {
  return iotsec_mem_create(&iotsec_mem_medium, num, len);
}

void iotsec_mem_medium_destroy(void) { iotsec_mem_destroy(&iotsec_mem_medium); }

char *iotsec_mem_medium_get_buf(void) {
  return iotsec_mem_get_buf(&iotsec_mem_medium);
}

size_t iotsec_mem_medium_get_num(void) {
  return iotsec_mem_get_num(&iotsec_mem_medium);
}

size_t iotsec_mem_medium_get_len(void) {
  return iotsec_mem_get_len(&iotsec_mem_medium);
}

size_t iotsec_mem_medium_get_active_len(void) {
  return iotsec_mem_get_active_len(&iotsec_mem_medium);
}

char *iotsec_mem_medium_get_active(void) { return iotsec_mem_medium.active; }

void *iotsec_mem_medium_alloc(size_t len) {
  return iotsec_mem_alloc(&iotsec_mem_medium, len);
}

void iotsec_mem_medium_free(void *buf) {
  iotsec_mem_free(&iotsec_mem_medium, buf);
}

/**
 *  Large memory allocator
 *
 *  This memory allocator can be used by any part of the IOTsec library.
 */
static iotsec_mem_t iotsec_mem_large = {0};

int iotsec_mem_large_create(size_t num, size_t len) {
  return iotsec_mem_create(&iotsec_mem_large, num, len);
}

void iotsec_mem_large_destroy(void) { iotsec_mem_destroy(&iotsec_mem_large); }

char *iotsec_mem_large_get_buf(void) {
  return iotsec_mem_get_buf(&iotsec_mem_large);
}

size_t iotsec_mem_large_get_num(void) {
  return iotsec_mem_get_num(&iotsec_mem_large);
}

size_t iotsec_mem_large_get_len(void) {
  return iotsec_mem_get_len(&iotsec_mem_large);
}

size_t iotsec_mem_large_get_active_len(void) {
  return iotsec_mem_get_active_len(&iotsec_mem_large);
}

char *iotsec_mem_large_get_active(void) { return iotsec_mem_large.active; }

void *iotsec_mem_large_alloc(size_t len) {
  return iotsec_mem_alloc(&iotsec_mem_large, len);
}

void iotsec_mem_large_free(void *buf) {
  iotsec_mem_free(&iotsec_mem_large, buf);
}

int iotsec_mem_all_create(size_t small_num, size_t small_len, size_t medium_num,
                          size_t medium_len, size_t large_num,
                          size_t large_len) {
  int ret = 0;

  ret = iotsec_mem_small_create(small_num, small_len);
  if (ret < 0) {
    return ret;
  }
  ret = iotsec_mem_medium_create(medium_num, medium_len);
  if (ret < 0) {
    iotsec_mem_small_destroy();
    return ret;
  }
  ret = iotsec_mem_large_create(large_num, large_len);
  if (ret < 0) {
    iotsec_mem_medium_destroy();
    iotsec_mem_small_destroy();
    return ret;
  }
  return 0;
}

void iotsec_mem_all_destroy(void) {
  iotsec_mem_large_destroy();
  iotsec_mem_medium_destroy();
  iotsec_mem_small_destroy();
}
