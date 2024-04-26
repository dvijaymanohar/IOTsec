/**
 *  @file iotsec_log.h
 *
 *  @brief Include file for the IOTsec logging module
 */

#ifndef IOTSEC_LOG_H
#define IOTSEC_LOG_H

#define IOTSEC_LOG_DEF_LEVEL IOTSEC_LOG_ERROR /**< Default log level */

/**
 *  @brief Log level
 */
typedef enum {
  IOTSEC_LOG_ERROR = 0,  /**< Error log level */
  IOTSEC_LOG_WARN = 1,   /**< Warning log level */
  IOTSEC_LOG_NOTICE = 2, /**< Notice log level */
  IOTSEC_LOG_INFO = 3,   /**< Informational log level */
  IOTSEC_LOG_DEBUG = 4   /**< Debug log level */
} iotsec_log_level_t;

/**
 *  @brief Set the log level
 *
 *  Messages with a severity below this level will be filtered.
 *  Error messages cannot be filtered.
 *
 *  @param[in] level The new log level
 */
void iotsec_log_set_level(iotsec_log_level_t level);

/**
 *  @brief Get the log level
 *
 *  @returns The current log level
 */
iotsec_log_level_t iotsec_log_get_level(void);

/**
 *  @brief Log an error message
 *
 *  @param[in] msg String containing format specifiers
 *  @param[in] ... arguments for the format specifiers
 */
void iotsec_log_error(const char *msg, ...);

/**
 *  @brief Log a warning message
 *
 *  @param[in] msg String containing format specifiers
 *  @param[in] ... arguments for the format specifiers
 */
void iotsec_log_warn(const char *msg, ...);

/**
 *  @brief Log an notice message
 *
 *  @param[in] msg String containing format specifiers
 *  @param[in] ... arguments for the format specifiers
 */
void iotsec_log_notice(const char *msg, ...);

/**
 *  @brief Log an info message
 *
 *  @param[in] msg String containing format specifiers
 *  @param[in] ... arguments for the format specifiers
 */
void iotsec_log_info(const char *msg, ...);

/**
 *  @brief Log a debug message
 *
 *  @param[in] msg String containing format specifiers
 *  @param[in] ... arguments for the format specifiers
 */
void iotsec_log_debug(const char *msg, ...);

#endif
