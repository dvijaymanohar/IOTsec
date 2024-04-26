/**
 *  @file iotsec_log.c
 *
 *  @brief Source file for the IOTsec logging module
 */

#include "iotsec_log.h"
#include <stdarg.h>
#include <stdio.h>

static iotsec_log_level_t iotsec_log_level =
    IOTSEC_LOG_DEF_LEVEL; /**< Log level used to filter log messages */

void iotsec_log_set_level(iotsec_log_level_t level) {
  switch (level) {
  case IOTSEC_LOG_WARN:   /**< Warning log level */
  case IOTSEC_LOG_NOTICE: /**< Notice warning level */
  case IOTSEC_LOG_INFO:   /**< Informational warning level */
  case IOTSEC_LOG_DEBUG:  /**< Debug warning level */
    iotsec_log_level = level;
    break;
  default:
    iotsec_log_level = IOTSEC_LOG_DEF_LEVEL;
  }
}

iotsec_log_level_t iotsec_log_get_level(void) { return iotsec_log_level; }

void iotsec_log_error(const char *msg, ...) {
  va_list arg_list;

  va_start(arg_list, msg);
  if (IOTSEC_LOG_ERROR <= iotsec_log_level) {
    printf("Error  : ");
    vprintf(msg, arg_list);
    printf("\n");
  }
  va_end(arg_list);
}

void iotsec_log_warn(const char *msg, ...) {
  va_list arg_list;

  va_start(arg_list, msg);
  if (IOTSEC_LOG_WARN <= iotsec_log_level) {
    printf("Warning: ");
    vprintf(msg, arg_list);
    printf("\n");
  }
  va_end(arg_list);
}

void iotsec_log_notice(const char *msg, ...) {
  va_list arg_list;

  va_start(arg_list, msg);
  if (IOTSEC_LOG_NOTICE <= iotsec_log_level) {
    printf("Notice : ");
    vprintf(msg, arg_list);
    printf("\n");
  }
  va_end(arg_list);
}

void iotsec_log_info(const char *msg, ...) {
  va_list arg_list;

  va_start(arg_list, msg);
  if (IOTSEC_LOG_INFO <= iotsec_log_level) {
    printf("Info   : ");
    vprintf(msg, arg_list);
    printf("\n");
  }
  va_end(arg_list);
}

void iotsec_log_debug(const char *msg, ...) {
  va_list arg_list;

  va_start(arg_list, msg);
  if (IOTSEC_LOG_DEBUG <= iotsec_log_level) {
    printf("Debug  : ");
    vprintf(msg, arg_list);
    printf("\n");
  }
  va_end(arg_list);
}
