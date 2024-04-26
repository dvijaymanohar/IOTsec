#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#ifdef IOTSEC_DTLS_EN
#include <gnutls/gnutls.h>
#endif
#include "iotsec_log.h"
#include "iotsec_mem.h"
#include "iotsec_msg.h"
#include "server.h"

#define IOTSEC_SERVER_APP_URI_PATH_BUF_LEN 32
#define IOTSEC_SERVER_APP_SMALL_BUF_NUM                                        \
  128 /**< Number of buffers in the small memory allocator */
#define IOTSEC_SERVER_APP_SMALL_BUF_LEN                                        \
  256 /**< Length of each buffer in the small memory allocator */
#define IOTSEC_SERVER_APP_MEDIUM_BUF_NUM                                       \
  128 /**< Number of buffers in the medium memory allocator */
#define IOTSEC_SERVER_APP_MEDIUM_BUF_LEN                                       \
  1024 /**< Length of each buffer in the medium memory allocator */
#define IOTSEC_SERVER_APP_LARGE_BUF_NUM                                        \
  32 /**< Number of buffers in the large memory allocator */
#define IOTSEC_SERVER_APP_LARGE_BUF_LEN                                        \
  8192 /**< Length of each buffer in the large memory allocator */
#define IOTSEC_SERVER_APP_BLOCK1_SIZE                                          \
  64 /**< Block size for data received from the client */
#define IOTSEC_SERVER_APP_BLOCK2_SIZE                                          \
  64 /**< Block size for data sent to the client */
#define IOTSEC_SERVER_APP_FILENAME "out" /**< Filename to store received data  \
                                          */

static int iotsec_server_app_handle_rx(iotsec_server_trans_t *trans,
                                       iotsec_msg_t *req, iotsec_msg_t *resp) {
  ssize_t num = 0;
  FILE *file = NULL;

  file = fopen(IOTSEC_SERVER_APP_FILENAME, "wb");
  if (file == NULL) {
    iotsec_log_warn("%s", strerror(-num));
    return iotsec_msg_set_code(resp, IOTSEC_MSG_SERVER_ERR,
                               IOTSEC_MSG_INT_SERVER_ERR);
  }
  num = fwrite(iotsec_server_trans_get_body(trans), 1,
               iotsec_server_trans_get_body_end(trans), file);
  if (num != iotsec_server_trans_get_body_end(trans)) {
    fclose(file);
    num = -EIO;
    iotsec_log_warn("%s", strerror(-num));
    return iotsec_msg_set_code(resp, IOTSEC_MSG_SERVER_ERR,
                               IOTSEC_MSG_INT_SERVER_ERR);
  }
  fclose(file);
  iotsec_log_info("Saved %zu bytes to '%s'",
                  iotsec_server_trans_get_body_end(trans),
                  IOTSEC_SERVER_APP_FILENAME);
  iotsec_server_trans_set_body_end(trans, 0);
  return iotsec_msg_set_code(resp, IOTSEC_MSG_SUCCESS, IOTSEC_MSG_CHANGED);
}

static int iotsec_server_app_handle(iotsec_server_trans_t *trans,
                                    iotsec_msg_t *req, iotsec_msg_t *resp) {
  unsigned code_detail = 0;
  unsigned code_class = 0;
  size_t n = 0;
  char uri_path[IOTSEC_SERVER_APP_URI_PATH_BUF_LEN] = {0};

  if (iotsec_msg_get_ver(req) != IOTSEC_MSG_VER) {
    iotsec_log_warn("Received request message with invalid version: %d",
                    iotsec_msg_get_ver(req));
    return -EBADMSG;
  }
  code_class = iotsec_msg_get_code_class(req);
  code_detail = iotsec_msg_get_code_detail(req);
  if ((code_class != IOTSEC_MSG_REQ) || (code_detail != IOTSEC_MSG_PUT)) {
    iotsec_log_warn("Request method not implemented");
    return iotsec_msg_set_code(resp, IOTSEC_MSG_SERVER_ERR,
                               IOTSEC_MSG_NOT_IMPL);
  }
  n = iotsec_msg_uri_path_to_str(req, uri_path, sizeof(uri_path));
  if ((n + 1) > sizeof(uri_path)) {
    iotsec_log_warn("URI path buffer too small by %zd bytes",
                    (n + 1) - sizeof(uri_path));
    return -ENOSPC;
  }
  iotsec_log_info("Received request URI path: '%s'", uri_path);
  if (strcmp(uri_path, "/client/transfer") != 0) {
    iotsec_log_warn("URI path not recognised");
    return iotsec_msg_set_code(resp, IOTSEC_MSG_CLIENT_ERR,
                               IOTSEC_MSG_NOT_FOUND);
  }
  return iotsec_server_trans_handle_blockwise(
      trans, req, resp, IOTSEC_SERVER_APP_BLOCK1_SIZE,
      IOTSEC_SERVER_APP_BLOCK2_SIZE, NULL, 0, iotsec_server_app_handle_rx);
}

/* one-time initialisation */
int iotsec_server_app_init(void) {
#ifdef IOTSEC_DTLS_EN
  const char *gnutls_ver = NULL;
#endif
  int ret = 0;

  iotsec_log_set_level(IOTSEC_LOG_INFO);
  ret = iotsec_mem_all_create(
      IOTSEC_SERVER_APP_SMALL_BUF_NUM, IOTSEC_SERVER_APP_SMALL_BUF_LEN,
      IOTSEC_SERVER_APP_MEDIUM_BUF_NUM, IOTSEC_SERVER_APP_MEDIUM_BUF_LEN,
      IOTSEC_SERVER_APP_LARGE_BUF_NUM, IOTSEC_SERVER_APP_LARGE_BUF_LEN);
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

void iotsec_server_app_deinit(void) { iotsec_mem_all_destroy(); }

int iotsec_server_app_create(iotsec_server_app_t *server, const char *host,
                             const char *port, const char *key_file_name,
                             const char *cert_file_name,
                             const char *trust_file_name,
                             const char *crl_file_name) {
  int ret = 0;

  memset(server, 0, sizeof(iotsec_server_app_t));
#ifdef IOTSEC_DTLS_EN
  ret = iotsec_server_create(&server->iotsec_server, iotsec_server_app_handle,
                             host, port, key_file_name, cert_file_name,
                             trust_file_name, crl_file_name);
#else
  ret = iotsec_server_create(&server->iotsec_server, iotsec_server_app_handle,
                             host, port);
#endif
  if (ret < 0) {
    if (ret != -1) {
      /* a return value of -1 indicates a DTLS failure which has already been
       * logged */
      iotsec_log_error("%s", strerror(-ret));
    }
    memset(server, 0, sizeof(iotsec_server_app_t));
    return ret;
  }
  return ret;
}

void iotsec_server_app_destroy(iotsec_server_app_t *server) {
  iotsec_server_destroy(&server->iotsec_server);
  memset(server, 0, sizeof(iotsec_server_app_t));
}

int iotsec_server_app_run(iotsec_server_app_t *server) {
  int ret = 0;

  ret = iotsec_server_run(&server->iotsec_server);
  if (ret < 0) {
    if (ret != -1) {
      /* a return value of -1 indicates a DTLS failure which has already been
       * logged */
      iotsec_log_error("%s", strerror(-ret));
    }
  }
  return ret;
}
