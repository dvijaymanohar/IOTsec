#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#ifdef IOTSEC_DTLS_EN
#include <gnutls/gnutls.h>
#endif
#include "client.h"
#include "iotsec_log.h"
#include "iotsec_mem.h"
#include "iotsec_msg.h"

#define IOTSEC_CLIENT_APP_URI_PATH_BUF_LEN 32
#define IOTSEC_CLIENT_APP_SMALL_BUF_NUM                                        \
  128 /**< Number of buffers in the small memory allocator */
#define IOTSEC_CLIENT_APP_SMALL_BUF_LEN                                        \
  256 /**< Length of each buffer in the small memory allocator */
#define IOTSEC_CLIENT_APP_MEDIUM_BUF_NUM                                       \
  128 /**< Number of buffers in the medium memory allocator */
#define IOTSEC_CLIENT_APP_MEDIUM_BUF_LEN                                       \
  1024 /**< Length of each buffer in the medium memory allocator */
#define IOTSEC_CLIENT_APP_LARGE_BUF_NUM                                        \
  32 /**< Number of buffers in the large memory allocator */
#define IOTSEC_CLIENT_APP_LARGE_BUF_LEN                                        \
  8192 /**< Length of each buffer in the large memory allocator */
#define IOTSEC_CLIENT_APP_BLOCK1_SIZE                                          \
  64 /**< Block size for data sent to the server */
#define IOTSEC_CLIENT_APP_BLOCK2_SIZE                                          \
  64 /**< Block size for data received from the server */

/* one-time initialisation */
int iotsec_client_app_init(void) {
#ifdef IOTSEC_DTLS_EN
  const char *gnutls_ver = NULL;
#endif
  int ret = 0;

  iotsec_log_set_level(IOTSEC_LOG_INFO);
  ret = iotsec_mem_all_create(
      IOTSEC_CLIENT_APP_SMALL_BUF_NUM, IOTSEC_CLIENT_APP_SMALL_BUF_LEN,
      IOTSEC_CLIENT_APP_MEDIUM_BUF_NUM, IOTSEC_CLIENT_APP_MEDIUM_BUF_LEN,
      IOTSEC_CLIENT_APP_LARGE_BUF_NUM, IOTSEC_CLIENT_APP_LARGE_BUF_LEN);
  if (ret < 0) {
    iotsec_log_error("%s", strerror(-ret));
    return -1;
  }
#ifdef IOTSEC_DTLS_EN
  gnutls_ver = gnutls_check_version(NULL);
  if (gnutls_ver == NULL) {
    iotsec_log_error("Unable to determine GnuTLS version");
    iotsec_mem_all_destroy();
    return -1;
  }
  iotsec_log_info("GnuTLS version: %s", gnutls_ver);
#endif
  return 0;
}

void iotsec_client_app_deinit(void) { iotsec_mem_all_destroy(); }

int iotsec_client_app_create(iotsec_client_app_t *client, const char *host,
                             const char *port, const char *key_file_name,
                             const char *cert_file_name,
                             const char *trust_file_name,
                             const char *crl_file_name,
                             const char *common_name) {
  int ret = 0;

  memset(client, 0, sizeof(iotsec_client_app_t));
#ifdef IOTSEC_DTLS_EN
  ret = iotsec_client_create(&client->iotsec_client, host, port, key_file_name,
                             cert_file_name, trust_file_name, crl_file_name,
                             common_name);
#else
  ret = iotsec_client_create(&client->iotsec_client, host, port);
#endif
  if (ret < 0) {
    iotsec_log_error("%s", strerror(-ret));
    memset(client, 0, sizeof(iotsec_client_app_t));
    return ret;
  }
  return 0;
}

void iotsec_client_app_destroy(iotsec_client_app_t *client) {
  iotsec_client_destroy(&client->iotsec_client);
  memset(client, 0, sizeof(iotsec_client_app_t));
}

/*  returns: { >=0, number of bytes read
 *           { <0,  error
 */
static ssize_t load_file(const char *filename, char **buf) {
  ssize_t num = 0;
  FILE *file = NULL;
  long file_len = 0;
  char *file_buf = NULL;
  int ret = 0;

  /* load file */
  file = fopen(filename, "rb");
  if (file == NULL) {
    return -errno;
  }
  ret = fseek(file, 0, SEEK_END);
  if (ret < 0) {
    fclose(file);
    return -errno;
  }
  file_len = ftell(file);
  if (file_len < 0) {
    fclose(file);
    return -errno;
  }
  ret = fseek(file, 0, SEEK_SET);
  if (ret < 0) {
    fclose(file);
    return -errno;
  }
  file_buf = (char *)malloc(file_len);
  if (file_buf == NULL) {
    fclose(file);
    return -errno;
  }
  num = fread(file_buf, 1, file_len, file);
  if (num != file_len) {
    free(file_buf);
    fclose(file);
    return -EIO;
  }
  fclose(file);
  *buf = file_buf;
  return file_len;
}

int iotsec_client_app_execute(iotsec_client_app_t *client,
                              const char *filename) {
  iotsec_msg_t resp = {0};
  iotsec_msg_t req = {0};
  ssize_t num = 0;
  size_t file_len = 0;
  char *file_buf = NULL;
  int ret = 0;

  num = load_file(filename, &file_buf);
  if (num < 0) {
    iotsec_log_error("%s", strerror(-num));
    return num;
  }
  file_len = num;

  /* generate request */
  iotsec_msg_create(&req);
  iotsec_msg_set_type(&req, IOTSEC_MSG_CON);
  iotsec_msg_set_code(&req, IOTSEC_MSG_REQ, IOTSEC_MSG_PUT);
  iotsec_log_info("Sending PUT /client/transfer request");
  ret = iotsec_msg_add_op(&req, IOTSEC_MSG_URI_PATH, 6, "client");
  if (ret < 0) {
    iotsec_log_error("Failed to set URI path in request message");
    iotsec_msg_destroy(&req);
    free(file_buf);
    return ret;
  }
  ret = iotsec_msg_add_op(&req, IOTSEC_MSG_URI_PATH, 8, "transfer");
  if (ret < 0) {
    iotsec_log_error("Failed to set URI path in request message");
    iotsec_msg_destroy(&req);
    free(file_buf);
    return ret;
  }

  /* blockwise transfer exchange */
  iotsec_msg_create(&resp);
  num = iotsec_client_exchange_blockwise(
      &client->iotsec_client, &req, &resp, IOTSEC_CLIENT_APP_BLOCK1_SIZE,
      IOTSEC_CLIENT_APP_BLOCK2_SIZE, file_buf, file_len,
      /* have_resp */ 0);
  if (num < 0) {
    if (num != -1) {
      /* a return value of -1 indicates a DTLS failure which has already been
       * logged */
      iotsec_log_error("%s", strerror(-ret));
    }
    iotsec_msg_destroy(&resp);
    iotsec_msg_destroy(&req);
    free(file_buf);
    return ret;
  }
  free(file_buf);
  iotsec_log_info("Transfer response: %u.%u", iotsec_msg_get_code_class(&resp),
                  iotsec_msg_get_code_detail(&resp));
  return 0;
}
