/**
 *  @file iotsec_msg.c
 *
 *  @brief Source file for the IOTsec message parser/formatter library
 */

#include "iotsec_msg.h"
#include "iotsec_mem.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define iotsec_msg_op_list_get_first(list)                                     \
  ((list)->first) /**< Get the first option from an option linked-list */
#define iotsec_msg_op_list_get_last(list)                                      \
  ((list)->last) /**< Get the last option in an option linked-list */
#define iotsec_msg_op_list_is_empty(list)                                      \
  ((list)->first ==                                                            \
   NULL) /**< Indicate whether or not an option linked-list is empty */

static int iotsec_msg_rand_init = 0; /**< Indicates whether or not the random
                                        number generator has been initialised */

void iotsec_msg_gen_rand_str(char *buf, size_t len) {
  size_t i = 0;

  if (!iotsec_msg_rand_init) {
    srand(time(NULL));
    iotsec_msg_rand_init = 1;
  }
  for (i = 0; i < len; i++) {
    buf[i] = rand() & 0x000000ff;
  }
}

int iotsec_msg_op_num_is_recognized(unsigned num) {
  switch (num) {
  case IOTSEC_MSG_IF_MATCH:
  case IOTSEC_MSG_URI_HOST:
  case IOTSEC_MSG_ETAG:
  case IOTSEC_MSG_IF_NONE_MATCH:
  case IOTSEC_MSG_URI_PORT:
  case IOTSEC_MSG_LOCATION_PATH:
  case IOTSEC_MSG_URI_PATH:
  case IOTSEC_MSG_CONTENT_FORMAT:
  case IOTSEC_MSG_MAX_AGE:
  case IOTSEC_MSG_URI_QUERY:
  case IOTSEC_MSG_ACCEPT:
  case IOTSEC_MSG_LOCATION_QUERY:
  case IOTSEC_MSG_BLOCK2:
  case IOTSEC_MSG_BLOCK1:
  case IOTSEC_MSG_SIZE2:
  case IOTSEC_MSG_PROXY_URI:
  case IOTSEC_MSG_PROXY_SCHEME:
  case IOTSEC_MSG_SIZE1:
    return 1;
  }
  return 0;
}

int iotsec_msg_op_calc_block_szx(unsigned size) {
  int szx = -EINVAL;

  switch (size) {
  case (1 << 4):
    szx = 0;
    break;
  case (1 << 5):
    szx = 1;
    break;
  case (1 << 6):
    szx = 2;
    break;
  case (1 << 7):
    szx = 3;
    break;
  case (1 << 8):
    szx = 4;
    break;
  case (1 << 9):
    szx = 5;
    break;
  case (1 << 10):
    szx = 6;
    break;
  }
  return szx;
}

int iotsec_msg_op_parse_block_val(unsigned *num, unsigned *more, unsigned *size,
                                  const char *val, unsigned len) {
  switch (len) {
  case 1:
    *size = 1 << ((val[0] & 0x07) + 4);
    *more = !!(val[0] & 0x08);
    *num = ((unsigned)(unsigned char)val[0] & 0x000000f0) >> 4;
    break;
  case 2:
    *size = 1 << ((val[1] & 0x07) + 4);
    *more = !!(val[1] & 0x08);
    *num = ((unsigned)(unsigned char)val[0] << 4) |
           (((unsigned)(unsigned char)val[1] & 0x000000f0) >> 4);
    break;
  default:
    *size = 1 << ((val[2] & 0x07) + 4);
    *more = !!(val[2] & 0x08);
    *num = ((unsigned)(unsigned char)val[0] << 12) |
           ((unsigned)(unsigned char)val[1] << 4) |
           (((unsigned)(unsigned char)val[2] & 0x000000f0) >> 4);
  }
  if (*size > IOTSEC_MSG_OP_MAX_BLOCK_SIZE) {
    return -EINVAL;
  }
  return 0;
}

int iotsec_msg_op_format_block_val(char *val, unsigned len, unsigned num,
                                   unsigned more, unsigned size) {
  unsigned szx = 0;
  int ret = 0;

  ret = iotsec_msg_op_calc_block_szx(size);
  if (ret < 0) {
    return ret;
  }
  szx = (unsigned)ret;

  switch (len) {
  case 1:
    if (num > (1 << 4)) {
      return -EINVAL;
    }
    val[0] = num << 4;
    val[0] |= (!!more) << 3;
    val[0] |= szx;
    return 1;
  case 2:
    if (num > (1 << 12)) {
      return -EINVAL;
    }
    val[0] = num >> 4;
    val[1] = num << 4;
    val[1] |= (!!more) << 3;
    val[1] |= szx;
    return 2;
  case 3:
    if (num > (1 << 20)) {
      return -EINVAL;
    }
    val[0] = num >> 12;
    val[1] = num >> 4;
    val[2] = num << 4;
    val[2] |= (!!more) << 3;
    val[2] |= szx;
    return 3;
  }
  return -EINVAL;
}

/**
 *  @brief Allocate an option structure
 *
 *  @param[in] num Option number
 *  @param[in] len Option length
 *  @param[in] val Pointer to the option value
 *
 *  @returns Pointer to the option structure
 *  @retval NULL Out-of-memory
 */
static iotsec_msg_op_t *iotsec_msg_op_new(unsigned num, unsigned len,
                                          const char *val) {
  iotsec_msg_op_t *op = NULL;

  op = (iotsec_msg_op_t *)iotsec_mem_small_alloc(sizeof(iotsec_msg_op_t));
  if (op == NULL) {
    return NULL;
  }
  op->num = num;
  op->len = len;
  op->val = (char *)iotsec_mem_medium_alloc(len);
  if (op->val == NULL) {
    iotsec_mem_medium_free(op);
    return NULL;
  }
  memcpy(op->val, val, len);
  op->next = NULL;
  return op;
}

/**
 *  @brief Free an option structure that was allocated by iotsec_msg_op_new
 *
 *  @param[in,out] op Pointer to the option structure
 */
static void iotsec_msg_op_delete(iotsec_msg_op_t *op) {
  iotsec_mem_medium_free(op->val);
  iotsec_mem_small_free(op);
}

/**
 *  @brief Initialise an option linked-list structure
 *
 *  @param[out] list Pointer to an option linked-list structure
 */
static void iotsec_msg_op_list_create(iotsec_msg_op_list_t *list) {
  memset(list, 0, sizeof(iotsec_msg_op_list_t));
}

/**
 *  @brief Deinitialise an option linked-list structure
 *
 *  @param[in,out] list Pointer to an option linked-list structure
 */
static void iotsec_msg_op_list_destroy(iotsec_msg_op_list_t *list) {
  iotsec_msg_op_t *prev = NULL;
  iotsec_msg_op_t *op = NULL;

  op = list->first;
  while (op != NULL) {
    prev = op;
    op = op->next;
    iotsec_msg_op_delete(prev);
  }
  memset(list, 0, sizeof(iotsec_msg_op_list_t));
}

/**
 *  @brief Allocate an option structure and add it to the end of an option
 * linked-list structure
 *
 *  @param[in,out] list Pointer to an option linked-list structure
 *  @param[in] num Option number
 *  @param[in] len Option length
 *  @param[in] val Pointer to a buffer containing the option value
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int iotsec_msg_op_list_add_last(iotsec_msg_op_list_t *list, unsigned num,
                                       unsigned len, const char *val) {
  iotsec_msg_op_t *op = NULL;

  op = iotsec_msg_op_new(num, len, val);
  if (op == NULL) {
    return -ENOMEM;
  }
  if (list->first == NULL) {
    list->first = op;
    list->last = op;
  } else {
    list->last->next = op;
    list->last = op;
  }
  return 0;
}

/**
 *  @brief Allocate an option structure and add it to an option linked-list
 * structure
 *
 *  The option is added to the list at a position determined by the option
 * number.
 *
 *  @param[in,out] list Pointer to an option linked-list structure
 *  @param[in] num Option number
 *  @param[in] len Option length
 *  @param[in] val Pointer to a buffer containing the option value
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int iotsec_msg_op_list_add(iotsec_msg_op_list_t *list, unsigned num,
                                  unsigned len, const char *val) {
  iotsec_msg_op_t *prev = NULL;
  iotsec_msg_op_t *op = NULL;

  op = iotsec_msg_op_new(num, len, val);
  if (op == NULL) {
    return -ENOMEM;
  }
  if (list->first == NULL) {
    /* empty list */
    list->first = op;
    list->last = op;
    return 0;
  }
  if (op->num < list->first->num) {
    /* start of the list */
    op->next = list->first;
    list->first = op;
    return 0;
  }
  prev = list->first;
  while (prev != list->last) {
    /* middle of the list */
    if ((prev->num <= op->num) && (op->num < prev->next->num)) {
      op->next = prev->next;
      prev->next = op;
      return 0;
    }
    prev = prev->next;
  }
  /* end of the list */
  list->last->next = op;
  list->last = op;
  return 0;
}

void iotsec_msg_create(iotsec_msg_t *msg) {
  memset(msg, 0, sizeof(iotsec_msg_t));
  msg->ver = IOTSEC_MSG_VER;
  iotsec_msg_op_list_create(&msg->op_list);
}

void iotsec_msg_destroy(iotsec_msg_t *msg) {
  iotsec_msg_op_list_destroy(&msg->op_list);
  if (msg->payload != NULL) {
    iotsec_mem_medium_free(msg->payload);
  }
  memset(msg, 0, sizeof(iotsec_msg_t));
}

void iotsec_msg_reset(iotsec_msg_t *msg) {
  iotsec_msg_destroy(msg);
  iotsec_msg_create(msg);
}

/**
 *  @brief Check a message for correctness
 *
 *  The following checks from RFC7252 are performed:
 *
 *  An Empty message has the Code field set to 0.00. The Token Length
 *  field MUST be set to 0 and bytes of data MUST NOT be present after
 *  the Message ID field.  If there are any bytes, they MUST be processed
 *  as a message format error.
 *
 *  The Reset message MUST echo the Message ID of the Confirmable message
 *  and MUST be Empty.
 *
 *  A Non-confirmable message always carries either a request or response
 *  and MUST NOT be Empty.
 *
 *  @param[in] msg Pointer to a message structure
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int iotsec_msg_check(iotsec_msg_t *msg) {
  if ((msg->code_class == 0) && (msg->code_detail == 0)) {
    /* empty message */
    if ((msg->type == IOTSEC_MSG_NON) || (msg->token_len != 0) ||
        (!iotsec_msg_op_list_is_empty(&msg->op_list)) ||
        (msg->payload_len != 0)) {
      return -EBADMSG;
    }
  } else {
    /* non-empty message */
    if (msg->type == IOTSEC_MSG_RST) {
      return -EBADMSG;
    }
  }
  return 0;
}

unsigned iotsec_msg_check_critical_ops(iotsec_msg_t *msg) {
  iotsec_msg_op_t *op = NULL;
  unsigned num = 0;

  op = iotsec_msg_get_first_op(msg);
  while (op != NULL) {
    num = iotsec_msg_op_get_num(op);
    if ((iotsec_msg_op_num_is_critical(num)) &&
        (!iotsec_msg_op_num_is_recognized(num))) {
      return num; /* fail */
    }
    op = iotsec_msg_op_get_next(op);
  }
  return 0; /* pass */
}

unsigned iotsec_msg_check_unsafe_ops(iotsec_msg_t *msg) {
  iotsec_msg_op_t *op = NULL;
  unsigned num = 0;

  op = iotsec_msg_get_first_op(msg);
  while (op != NULL) {
    num = iotsec_msg_op_get_num(op);
    if ((iotsec_msg_op_num_is_unsafe(num)) &&
        (!iotsec_msg_op_num_is_recognized(num))) {
      return num; /* fail */
    }
    op = iotsec_msg_op_get_next(op);
  }
  return 0; /* pass */
}

int iotsec_msg_parse_type_msg_id(char *buf, size_t len, unsigned *type,
                                 unsigned *msg_id) {
  if (len < 4) {
    return -EBADMSG;
  }
  *type = (buf[0] >> 4) & 0x03;
  *msg_id = ntohs(*((uint16_t *)(&buf[2])));
  return 0;
}

/**
 *  @brief Parse the header in a message
 *
 *  @param[out] msg Pointer to a message structure
 *  @param[in] buf Pointer to a buffer containing the message
 *  @param[in] len Length of the buffer
 *
 *  @returns Number of bytes parsed or error code
 *  @retval >0 Number of bytes parsed
 *  @retval <0 Error
 */
static ssize_t iotsec_msg_parse_hdr(iotsec_msg_t *msg, char *buf, size_t len) {
  char *p = buf;

  if (len < 4) {
    return -EBADMSG;
  }
  msg->ver = (p[0] >> 6) & 0x03;
  if (msg->ver != IOTSEC_MSG_VER) {
    return -EINVAL;
  }
  msg->type = (p[0] >> 4) & 0x03;
  msg->token_len = p[0] & 0x0f;
  if (msg->token_len > sizeof(msg->token)) {
    return -EBADMSG;
  }
  msg->code_detail = p[1] & 0x1f;
  msg->code_class = (p[1] >> 5) & 0x07;
  if ((msg->code_class != IOTSEC_MSG_REQ) &&
      (msg->code_class != IOTSEC_MSG_SUCCESS) &&
      (msg->code_class != IOTSEC_MSG_CLIENT_ERR) &&
      (msg->code_class != IOTSEC_MSG_SERVER_ERR)) {
    return -EBADMSG;
  }
  msg->msg_id = ntohs(*((uint16_t *)(&p[2])));
  p += 4;
  len -= 4;
  return p - buf;
}

/**
 *  @brief Parse the token in a message
 *
 *  @param[out] msg Pointer to a message structure
 *  @param[in] buf Pointer to a buffer containing the message
 *  @param[in] len Length of the buffer
 *
 *  @returns Number of bytes parsed or error code
 *  @retval >0 Number of bytes parsed
 *  @retval <0 Error
 */
static ssize_t iotsec_msg_parse_token(iotsec_msg_t *msg, char *buf,
                                      size_t len) {
  if (len < msg->token_len) {
    return -EBADMSG;
  }
  memcpy(msg->token, buf, msg->token_len);
  return msg->token_len;
}

/**
 *  @brief Parse an option in a message
 *
 *  @param[in,out] msg Pointer to a message structure
 *  @param[in] buf Pointer to a buffer containing the message
 *  @param[in] len Length of the buffer
 *
 *  @returns Number of bytes parsed or error code
 *  @retval >0 Number of bytes parsed
 *  @retval <0 Error
 */
static ssize_t iotsec_msg_parse_op(iotsec_msg_t *msg, char *buf, size_t len) {
  iotsec_msg_op_t *prev = NULL;
  unsigned op_delta = 0;
  unsigned op_len = 0;
  unsigned op_num = 0;
  char *p = buf;
  int ret = 0;

  if (len < 1) {
    return -EBADMSG;
  }
  op_delta = (p[0] >> 4) & 0x0f;
  op_len = p[0] & 0x0f;
  if ((op_delta == 15) || (op_len == 15)) {
    return -EBADMSG;
  }
  p++;
  len--;
  if (op_delta == 13) {
    if (len < 1) {
      return -EBADMSG;
    }
    op_delta += p[0];
    p++;
    len--;
  } else if (op_delta == 14) {
    if (len < 2) {
      return -EBADMSG;
    }
    op_delta = 269 + ntohs(*((uint16_t *)(&p[0])));
    p += 2;
    len -= 2;
  }
  if (op_len == 13) {
    if (len < 1) {
      return -EBADMSG;
    }
    op_len += p[0];
    p++;
    len--;
  } else if (op_len == 14) {
    if (len < 2) {
      return -EBADMSG;
    }
    op_len = 269 + ntohs(*((uint16_t *)(&p[0])));
    p += 2;
    len -= 2;
  }
  if (len < op_len) {
    return -EBADMSG;
  }
  prev = iotsec_msg_op_list_get_last(&msg->op_list);
  if (prev == NULL) {
    op_num = op_delta;
  } else {
    op_num = iotsec_msg_op_get_num(prev) + op_delta;
  }
  ret = iotsec_msg_op_list_add_last(&msg->op_list, op_num, op_len, p);
  if (ret < 0) {
    return ret;
  }
  p += op_len;
  return p - buf;
}

/**
 *  @brief Parse the options in a message
 *
 *  @param[in,out] msg Pointer to a message structure
 *  @param[in] buf Pointer to a buffer containing the message
 *  @param[in] len Length of the buffer
 *
 *  @returns Number of bytes parsed or error code
 *  @retval >0 Number of bytes parsed
 *  @retval <0 Error
 */
static ssize_t iotsec_msg_parse_ops(iotsec_msg_t *msg, char *buf, size_t len) {
  ssize_t num = 0;
  char *p = buf;

  while (1) {
    if (((p[0] & 0xff) == 0xff) || (len == 0)) {
      break;
    }
    num = iotsec_msg_parse_op(msg, p, len);
    if (num < 0) {
      return num;
    }
    p += num;
    len -= num;
  }
  return p - buf;
}

int iotsec_msg_parse_block_op(unsigned *num, unsigned *more, unsigned *size,
                              iotsec_msg_t *msg, int type) {
  iotsec_msg_op_t *op = NULL;
  unsigned op_num = 0;
  unsigned op_len = 0;
  char *op_val = NULL;

  op = iotsec_msg_get_first_op(msg);
  while (op != NULL) {
    op_num = iotsec_msg_op_get_num(op);
    op_len = iotsec_msg_op_get_len(op);
    op_val = iotsec_msg_op_get_val(op);
    if (((op_num == IOTSEC_MSG_BLOCK1) && (type == IOTSEC_MSG_BLOCK1)) ||
        ((op_num == IOTSEC_MSG_BLOCK2) && (type == IOTSEC_MSG_BLOCK2))) {
      return iotsec_msg_op_parse_block_val(num, more, size, op_val, op_len);
    }
    op = iotsec_msg_op_get_next(op);
  }
  return 1; /* not found */
}

/**
 *  @brief Parse the payload in a message
 *
 *  @param[out] msg Pointer to a message structure
 *  @param[in] buf Pointer to a buffer containing the message
 *  @param[in] len Length of the buffer
 *
 *  @returns Number of bytes parsed or error code
 *  @retval >0 Number of bytes parsed
 *  @retval <0 Error
 */
static ssize_t iotsec_msg_parse_payload(iotsec_msg_t *msg, char *buf,
                                        size_t len) {
  char *p = buf;

  if (len == 0) {
    return 0;
  }
  if ((p[0] & 0xff) != 0xff) {
    return -EBADMSG;
  }
  p++;
  len--;
  if (len == 0) {
    return -EBADMSG;
  }
  msg->payload = (char *)iotsec_mem_medium_alloc(len);
  if (msg->payload == NULL) {
    return -ENOMEM;
  }
  memset(msg->payload, 0, iotsec_mem_medium_get_len());
  memcpy(msg->payload, p, len);
  msg->payload_len = len;
  p += len;
  return p - buf;
}

ssize_t iotsec_msg_parse(iotsec_msg_t *msg, char *buf, size_t len) {
  ssize_t num = 0;
  char *p = buf;

  iotsec_msg_reset(msg);
  num = iotsec_msg_parse_hdr(msg, p, len);
  if (num < 0) {
    iotsec_msg_destroy(msg);
    return num;
  }
  p += num;
  len -= num;
  num = iotsec_msg_parse_token(msg, p, len);
  if (num < 0) {
    iotsec_msg_destroy(msg);
    return num;
  }
  p += num;
  len -= num;
  num = iotsec_msg_parse_ops(msg, p, len);
  if (num < 0) {
    iotsec_msg_destroy(msg);
    return num;
  }
  p += num;
  len -= num;
  num = iotsec_msg_parse_payload(msg, p, len);
  if (num < 0) {
    iotsec_msg_destroy(msg);
    return num;
  }
  return iotsec_msg_check(msg);
}

int iotsec_msg_set_type(iotsec_msg_t *msg, unsigned type) {
  if ((type != IOTSEC_MSG_CON) && (type != IOTSEC_MSG_NON) &&
      (type != IOTSEC_MSG_ACK) && (type != IOTSEC_MSG_RST)) {
    return -EINVAL;
  }
  msg->type = type;
  return 0;
}

int iotsec_msg_set_code(iotsec_msg_t *msg, unsigned code_class,
                        unsigned code_detail) {
  if (code_class > IOTSEC_MSG_MAX_CODE_CLASS) {
    return -EINVAL;
  }
  if (code_detail > IOTSEC_MSG_MAX_CODE_DETAIL) {
    return -EINVAL;
  }
  msg->code_class = code_class;
  msg->code_detail = code_detail;
  return 0;
}

int iotsec_msg_set_msg_id(iotsec_msg_t *msg, unsigned msg_id) {
  if (msg_id > IOTSEC_MSG_MAX_MSG_ID) {
    return -EINVAL;
  }
  msg->msg_id = msg_id;
  return 0;
}

int iotsec_msg_set_token(iotsec_msg_t *msg, char *buf, size_t len) {
  if (len > IOTSEC_MSG_MAX_TOKEN_LEN) {
    return -EINVAL;
  }
  memcpy(msg->token, buf, len);
  msg->token_len = len;
  return 0;
}

int iotsec_msg_add_op(iotsec_msg_t *msg, unsigned num, unsigned len,
                      const char *val) {
  return iotsec_msg_op_list_add(&msg->op_list, num, len, val);
}

int iotsec_msg_set_payload(iotsec_msg_t *msg, char *buf, size_t len) {
  msg->payload_len = 0;
  if (msg->payload != NULL) {
    iotsec_mem_medium_free(msg->payload);
    msg->payload = NULL;
  }
  if (len > 0) {
    msg->payload = (char *)iotsec_mem_medium_alloc(len);
    if (msg->payload == NULL) {
      return -ENOMEM;
    }
    memset(msg->payload, 0, iotsec_mem_medium_get_len());
    memcpy(msg->payload, buf, len);
    msg->payload_len = len;
  }
  return 0;
}

void iotsec_msg_clear_payload(iotsec_msg_t *msg) {
  msg->payload_len = 0;
  if (msg->payload != NULL) {
    iotsec_mem_medium_free(msg->payload);
    msg->payload = NULL;
  }
}

/**
 *  @brief Format the header in a message
 *
 *  @param[in] msg Pointer to a message structure
 *  @param[out] buf Pointer to a buffer to contain the formatted message
 *  @param[in] len Length of the buffer
 *
 *  @returns Length of the formatted message or error code
 *  @retval >0 Length of the formatted message
 *  @retval <0 Error
 */
static ssize_t iotsec_msg_format_hdr(iotsec_msg_t *msg, char *buf, size_t len) {
  uint16_t msg_id = 0;

  if (len < 4) {
    return -ENOSPC;
  }
  buf[0] = (char)((IOTSEC_MSG_VER << 6) | ((msg->type & 0x03) << 4) |
                  (msg->token_len & 0x0f));
  buf[1] = (char)(((msg->code_class & 0x07) << 5) | (msg->code_detail & 0x1f));
  msg_id = htons(msg->msg_id);
  memcpy(&buf[2], &msg_id, 2);
  return 4;
}

/**
 *  @brief Format the token in a message
 *
 *  @param[in] msg Pointer to a message structure
 *  @param[out] buf Pointer to a buffer to contain the formatted message
 *  @param[in] len Length of the buffer
 *
 *  @returns Length of the formatted message or error code
 *  @retval >0 Length of the formatted message
 *  @retval <0 Error
 */
static ssize_t iotsec_msg_format_token(iotsec_msg_t *msg, char *buf,
                                       size_t len) {
  if (len < msg->token_len) {
    return -ENOSPC;
  }
  memcpy(buf, msg->token, msg->token_len);
  return msg->token_len;
}

/**
 *  @brief Format an option in a message
 *
 *  @param[in] op Pointer to an option structure
 *  @param[in] prev_num option number of the previous option
 *  @param[out] buf Pointer to a buffer to contain the formatted message
 *  @param[in] len Length of the buffer
 *
 *  @returns Length of the formatted message or error code
 *  @retval >0 Length of the formatted message
 *  @retval <0 Error
 */
static ssize_t iotsec_msg_format_op(iotsec_msg_op_t *op, unsigned prev_num,
                                    char *buf, size_t len) {
  unsigned op_delta = 0;
  unsigned num = 0;
  uint16_t val = 0;
  char *p = buf;

  op_delta = op->num - prev_num;
  num++;

  /* option delta */
  if (op_delta >= 269) {
    num += 2;
  } else if (op_delta >= 13) {
    num += 1;
  }

  /* option length */
  if (op->len >= 269) {
    num += 2;
  } else if (op->num >= 13) {
    num += 1;
  }

  /* option value */
  num += op->len;
  if (num > len) {
    return -ENOSPC;
  }

  /* option delta */
  if (op_delta >= 269) {
    p[0] = 14 << 4;
  } else if (op_delta >= 13) {
    p[0] = 13 << 4;
  } else {
    p[0] = op_delta << 4;
  }

  /* option length */
  if (op->len >= 269) {
    p[0] |= 14;
  } else if (op->len >= 13) {
    p[0] |= 13;
  } else {
    p[0] |= op->len;
  }
  p++;
  len--;

  /* option delta extended */
  if (op_delta >= 269) {
    val = htons(op_delta - 269);
    memcpy(p, &val, 2);
    p += 2;
    len -= 2;
  } else if (op_delta >= 13) {
    p[0] = op_delta - 13;
    p++;
    len--;
  }

  /* option length extended */
  if (op->len >= 269) {
    val = htons(op->len - 269);
    memcpy(p, &val, 2);
    p += 2;
    len -= 2;
  } else if (op->len >= 13) {
    p[0] = op->len - 13;
    p++;
    len--;
  }

  /* option value */
  memcpy(p, op->val, op->len);
  p += op->len;

  return p - buf;
}

/**
 *  @brief Format the options in a message
 *
 *  @param[in] msg Pointer to a message structure
 *  @param[out] buf Pointer to a buffer to contain the formatted message
 *  @param[in] len Length of the buffer
 *
 *  @returns Length of the formatted message or error code
 *  @retval >0 Length of the formatted message
 *  @retval <0 Error
 */
static ssize_t iotsec_msg_format_ops(iotsec_msg_t *msg, char *buf, size_t len) {
  iotsec_msg_op_t *op = NULL;
  unsigned prev_num = 0;
  ssize_t num = 0;
  char *p = buf;

  op = iotsec_msg_op_list_get_first(&msg->op_list);
  while (op != NULL) {
    num = iotsec_msg_format_op(op, prev_num, p, len);
    if (num < 0) {
      return num;
    }
    p += num;
    len -= num;
    prev_num = iotsec_msg_op_get_num(op);
    op = iotsec_msg_op_get_next(op);
  }
  return p - buf;
}

/**
 *  @brief Format the payload in a message
 *
 *  @param[in] msg Pointer to a message structure
 *  @param[out] buf Pointer to a buffer to contain the formatted message
 *  @param[in] len Length of the buffer
 *
 *  @returns Length of the formatted message or error code
 *  @retval >0 Length of the formatted message
 *  @retval <0 Error
 */
static ssize_t iotsec_msg_format_payload(iotsec_msg_t *msg, char *buf,
                                         size_t len) {
  if (msg->payload_len == 0) {
    return 0;
  }
  if (msg->payload_len + 1 > len) {
    return -ENOSPC;
  }
  buf[0] = 0xff;
  memcpy(&buf[1], msg->payload, msg->payload_len);
  return msg->payload_len + 1;
}

ssize_t iotsec_msg_format(iotsec_msg_t *msg, char *buf, size_t len) {
  ssize_t num = 0;
  char *p = buf;
  int ret = 0;

  ret = iotsec_msg_check(msg);
  if (ret != 0) {
    return ret;
  }
  num = iotsec_msg_format_hdr(msg, p, len);
  if (num < 0) {
    return num;
  }
  p += num;
  len -= num;
  num = iotsec_msg_format_token(msg, p, len);
  if (num < 0) {
    return num;
  }
  p += num;
  len -= num;
  num = iotsec_msg_format_ops(msg, p, len);
  if (num < 0) {
    return num;
  }
  p += num;
  len -= num;
  num = iotsec_msg_format_payload(msg, p, len);
  if (num < 0) {
    return num;
  }
  p += num;
  return p - buf;
}

int iotsec_msg_copy(iotsec_msg_t *dst, iotsec_msg_t *src) {
  iotsec_msg_op_t *op = NULL;
  int ret = 0;

  dst->ver = src->ver;
  ret = iotsec_msg_set_type(dst, iotsec_msg_get_type(src));
  if (ret < 0) {
    return ret;
  }
  ret = iotsec_msg_set_code(dst, iotsec_msg_get_code_class(src),
                            iotsec_msg_get_code_detail(src));
  if (ret < 0) {
    return ret;
  }
  ret = iotsec_msg_set_msg_id(dst, iotsec_msg_get_msg_id(src));
  if (ret < 0) {
    return ret;
  }
  ret = iotsec_msg_set_token(dst, iotsec_msg_get_token(src),
                             iotsec_msg_get_token_len(src));
  if (ret < 0) {
    return ret;
  }
  op = iotsec_msg_get_first_op(src);
  while (op != NULL) {
    ret =
        iotsec_msg_add_op(dst, iotsec_msg_op_get_num(op),
                          iotsec_msg_op_get_len(op), iotsec_msg_op_get_val(op));
    if (ret < 0) {
      return ret;
    }
    op = iotsec_msg_op_get_next(op);
  }
  ret = iotsec_msg_set_payload(dst, iotsec_msg_get_payload(src),
                               iotsec_msg_get_payload_len(src));
  if (ret < 0) {
    return ret;
  }
  return 0;
}

size_t iotsec_msg_uri_path_to_str(iotsec_msg_t *msg, char *buf, size_t len) {
  iotsec_msg_op_t *op = NULL;
  size_t n = 0;
  size_t m = 0;
  size_t c = 0;
  char *p = NULL;

  if (len == 0) {
    return 0;
  }
  memset(buf, 0, len);
  p = buf;
  n = len - 1;
  op = iotsec_msg_get_first_op(msg);
  while (op != NULL) {
    if (iotsec_msg_op_get_num(op) == IOTSEC_MSG_URI_PATH) {
      m = 1;
      c += m;
      if (m > n)
        m = n;
      memcpy(p, "/", m);
      p += m;
      n -= m;

      m = iotsec_msg_op_get_len(op);
      c += m;
      if (m > n)
        m = n;
      memcpy(p, iotsec_msg_op_get_val(op), m);
      p += m;
      n -= m;
    }
    op = iotsec_msg_op_get_next(op);
  }
  if ((p == buf) && (len > 1)) {
    *p = '/';
    c = 1;
  }
  return c;
}
