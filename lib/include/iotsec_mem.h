/**
 *  @file iotsec_mem.h
 *
 *  @brief Include file for the IOTsec memory allocator
 */

#ifndef IOTSEC_MEM_H
#define IOTSEC_MEM_H

#include <stddef.h>

#define iotsec_mem_get_buf(mem)                                                \
  ((mem)->buf) /**< Get the array of buffers in a memory allocator */
#define iotsec_mem_get_num(mem)                                                \
  ((mem)->num) /**< Get the number of buffers in a memory allocator */
#define iotsec_mem_get_len(mem)                                                \
  ((mem)->len) /**< Get the length of each buffer in a memory allocator */
#define iotsec_mem_get_active(mem)                                             \
  ((mem)->active) /**< Get the active bitset from a memory allocator */
#define iotsec_mem_get_active_len(mem)                                         \
  ((mem)->num >>                                                               \
   3) /**< Get the length of the active bitset from a memory allocator */

/**
 *  @brief Memory allocator structure
 */
typedef struct {
  char *buf;    /**< Pointer to an array of buffers */
  size_t num;   /**< Number of buffers */
  size_t len;   /**< Length of each buffer */
  char *active; /**< Bitset marking active buffers */
} iotsec_mem_t;

/**
 *  @brief Initialise a memory allocator structure
 *
 *  @param[out] mem Pointer to a memory allocator
 *  @param[in] num Number of buffers
 *  @param[in] len Length of each buffer
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
int iotsec_mem_create(iotsec_mem_t *mem, size_t num, size_t len);

/**
 *  @brief Deinitialise a memory allocator structure
 *
 *  @param[in,out] mem Pointer to a memory allocator
 */
void iotsec_mem_destroy(iotsec_mem_t *mem);

/**
 *  @brief Allocate a buffer from a memory allocator
 *
 *  @param[in,out] mem Pointer to a memory allocator
 *  @param[in] len Length of the buffer
 *
 *  @returns Pointer to a buffer or NULL
 */
void *iotsec_mem_alloc(iotsec_mem_t *mem, size_t len);

/**
 *  @brief Return a buffer back to a memory allocator
 *
 *  @param[in,out] mem Pointer to a memory allocator
 *  @param[in] buf Pointer to a buffer
 */
void iotsec_mem_free(iotsec_mem_t *mem, void *buf);

/**
 *  @brief Initialise the small memory allocator
 *
 *  @param[in] num Number of buffers
 *  @param[in] len Length of each buffer
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
int iotsec_mem_small_create(size_t num, size_t len);

/**
 *  @brief Deinitialise the small memory allocator
 */
void iotsec_mem_small_destroy(void);

/**
 *  @brief Get the array of buffers in the small memory allocator
 *
 *  @returns Pointer to the array of buffers
 */
char *iotsec_mem_small_get_buf(void);

/**
 *  @brief Get the number of buffers in the small memory allocator
 *
 *  @returns Number of buffers
 */
size_t iotsec_mem_small_get_num(void);

/**
 *  @brief Get the length of each buffer in the small memory allocator
 *
 *  @returns Length of each buffer
 */
size_t iotsec_mem_small_get_len(void);

/**
 *  @brief Get the length of the active bitset from the small memory allocator
 *
 *  @returns Length of the active bitset from the small memory allocator
 */
size_t iotsec_mem_small_get_active_len(void);

/**
 *  @brief Get the active bitset from the small memory allocator
 *
 *  @returns the active bitset from the small memory allocator
 */
char *iotsec_mem_small_get_active(void);

/**
 *  @brief Allocate a buffer from the small memory allocator
 *
 *  @param[in] len Length of the buffer
 *
 *  @returns Pointer to a buffer or NULL
 */
void *iotsec_mem_small_alloc(size_t len);

/**
 *  @brief Return a buffer back to the small memory allocator
 *
 *  @param[in] buf Pointer to a buffer
 */
void iotsec_mem_small_free(void *buf);

/**
 *  @brief Initialise the medium memory allocator
 *
 *  @param[in] num Number of buffers
 *  @param[in] len Length of each buffer
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
int iotsec_mem_medium_create(size_t num, size_t len);

/**
 *  @brief Deinitialise the medium memory allocator
 */
void iotsec_mem_medium_destroy(void);

/**
 *  @brief Get the array of buffers in the medium memory allocator
 *
 *  @returns Pointer to the array of buffers
 */
char *iotsec_mem_medium_get_buf(void);

/**
 *  @brief Get the number of buffers in the medium memory allocator
 *
 *  @returns Number of buffers
 */
size_t iotsec_mem_medium_get_num(void);

/**
 *  @brief Get the length of each buffer in the medium memory allocator
 *
 *  @returns Length of each buffer
 */
size_t iotsec_mem_medium_get_len(void);

/**
 *  @brief Get the length of the active bitset from the medium memory allocator
 *
 *  @returns Length of the active bitset from the medium memory allocator
 */
size_t iotsec_mem_medium_get_active_len(void);

/**
 *  @brief Get the active bitset from the medium memory allocator
 *
 *  @returns the active bitset from the medium memory allocator
 */
char *iotsec_mem_medium_get_active(void);

/**
 *  @brief Allocate a buffer from the medium memory allocator
 *
 *  @param[in] len Length of the buffer
 *
 *  @returns Pointer to a buffer or NULL
 */
void *iotsec_mem_medium_alloc(size_t len);

/**
 *  @brief Return a buffer back to the medium memory allocator
 *
 *  @param[in] buf Pointer to a buffer
 */
void iotsec_mem_medium_free(void *buf);

/**
 *  @brief Initialise the large memory allocator
 *
 *  @param[in] num Number of buffers
 *  @param[in] len Length of each buffer
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
int iotsec_mem_large_create(size_t num, size_t len);

/**
 *  @brief Deinitialise the large memory allocator
 */
void iotsec_mem_large_destroy(void);

/**
 *  @brief Get the array of buffers in the large memory allocator
 *
 *  @returns Pointer to the array of buffers
 */
char *iotsec_mem_large_get_buf(void);

/**
 *  @brief Get the number of buffers in the large memory allocator
 *
 *  @returns Number of buffers
 */
size_t iotsec_mem_large_get_num(void);

/**
 *  @brief Get the length of each buffer in the large memory allocator
 *
 *  @returns Length of each buffer
 */
size_t iotsec_mem_large_get_len(void);

/**
 *  @brief Get the length of the active bitset from the large memory allocator
 *
 *  @returns Length of the active bitset from the large memory allocator
 */
size_t iotsec_mem_large_get_active_len(void);

/**
 *  @brief Get the active bitset from the large memory allocator
 *
 *  @returns the active bitset from the large memory allocator
 */
char *iotsec_mem_large_get_active(void);

/**
 *  @brief Allocate a buffer from the large memory allocator
 *
 *  @param[in] len Length of the buffer
 *
 *  @returns Pointer to a buffer or NULL
 */
void *iotsec_mem_large_alloc(size_t len);

/**
 *  @brief Return a buffer back to the large memory allocator
 *
 *  @param[in] buf Pointer to a buffer
 */
void iotsec_mem_large_free(void *buf);

/**
 *  @brief Initialise all memory allocators
 *
 *  @param[in] small_num Number of small buffers
 *  @param[in] small_len Length of each small buffer
 *  @param[in] medium_num Number of medium buffers
 *  @param[in] medium_len Length of each medium buffer
 *  @param[in] large_num Number of large buffers
 *  @param[in] large_len Length of each large buffer
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
int iotsec_mem_all_create(size_t small_num, size_t small_len, size_t medium_num,
                          size_t medium_len, size_t large_num,
                          size_t large_len);

/**
 *  @brief Deinitialise all memory allocators
 */
void iotsec_mem_all_destroy(void);

#endif
