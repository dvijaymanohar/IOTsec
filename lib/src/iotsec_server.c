/**
 *  @file iotsec_server.c
 *
 *  @brief Source file for the IOTsec server library
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#ifdef IOTSEC_DTLS_EN
#include <gnutls/x509.h>
#endif
#include "iotsec_log.h"
#include "iotsec_mem.h"
#include "iotsec_server.h"

#define IOTSEC_SERVER_ACK_TIMEOUT_SEC                                          \
  2 /**< Minimum delay to wait before retransmitting a confirmable message */
#define IOTSEC_SERVER_MAX_RETRANSMIT                                           \
  4 /**< Maximum number of times a confirmable message can be retransmitted */

#ifdef IOTSEC_DTLS_EN

#define IOTSEC_SERVER_DTLS_MTU                                                 \
  IOTSEC_MSG_MAX_BUF_LEN /**< Maximum transmission unit excluding the UDP and  \
                            IPv6 headers */
#define IOTSEC_SERVER_DTLS_RETRANS_TIMEOUT                                     \
  1000 /**< Retransmission timeout (msec) for the DTLS handshake */
#define IOTSEC_SERVER_DTLS_TOTAL_TIMEOUT                                       \
  60000 /**< Total timeout (msec) for the DTLS handshake */
#define IOTSEC_SERVER_DTLS_HANDSHAKE_ATTEMPTS                                  \
  60 /**< Maximum number of DTLS handshake attempts */
#define IOTSEC_SERVER_DTLS_NUM_DH_BITS 1024 /**< DTLS Diffie-Hellman key size  \
                                             */
#define IOTSEC_SERVER_DTLS_PRIORITIES                                          \
  "PERFORMANCE:-VERS-TLS-ALL:+VERS-DTLS1.0:%SERVER_PRECEDENCE"
/**< DTLS priorities */
#endif

static int rand_init =
    0; /**< Indicates if the random number generator has been initialised */

/**
 *  @brief Allocate a URI path structure
 *
 *  @param[in] str String representation of a URI path
 *
 *  @returns New URI path structure
 *  @retval NULL Out-of-memory
 */
static iotsec_server_path_t *iotsec_server_path_new(const char *str) {
  iotsec_server_path_t *path = NULL;

  path = (iotsec_server_path_t *)iotsec_mem_small_alloc(
      sizeof(iotsec_server_path_t));
  if (path == NULL) {
    return NULL;
  }
  path->str = (char *)iotsec_mem_small_alloc(strlen(str) + 1);
  if (path->str == NULL) {
    iotsec_mem_small_free(path);
    return NULL;
  }
  strncpy(path->str, str, iotsec_mem_small_get_len() - 1);
  path->str[iotsec_mem_small_get_len() - 1] = '\0';
  path->next = NULL;
  return path;
}

/**
 *  @brief Free a URI path structure
 *
 *  @param[in,out] path Pointer to a URI path structure
 */
static void iotsec_server_path_delete(iotsec_server_path_t *path) {
  iotsec_mem_small_free(path->str);
  iotsec_mem_small_free(path);
}

/**
 *  @brief Initialise a URI path list structure
 *
 *  @param[out] list Pointer to a URI path list structure
 */
static void iotsec_server_path_list_create(iotsec_server_path_list_t *list) {
  memset(list, 0, sizeof(iotsec_server_path_list_t));
}

/**
 *  @brief Deinitialise a URI path list structure
 *
 *  @param[in,out] list Pointer to a URI path list structure
 */
static void iotsec_server_path_list_destroy(iotsec_server_path_list_t *list) {
  iotsec_server_path_t *prev = NULL;
  iotsec_server_path_t *path = NULL;

  path = list->first;
  while (path != NULL) {
    prev = path;
    path = path->next;
    iotsec_server_path_delete(prev);
  }
  memset(list, 0, sizeof(iotsec_server_path_list_t));
}

/**
 *  @brief Add a URI path to a URI path list structure
 *
 *  @param[in,out] list Pointer to a URI path list structure
 *  @param[in] str String representation of a URI path
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int iotsec_server_path_list_add(iotsec_server_path_list_t *list,
                                       const char *str) {
  iotsec_server_path_t *path = NULL;

  path = iotsec_server_path_new(str);
  if (path == NULL) {
    return -ENOMEM;
  }
  if (list->first == NULL) {
    list->first = path;
    list->last = path;
  } else {
    list->last->next = path;
    list->last = path;
  }
  return 0;
}

/**
 *  @brief Search a URI path list structure for a URI path
 *
 *  @param[in] list Pointer to a URI path list structure
 *  @param[in] str String representation of a URI path
 *
 *  @returns Comparison value
 *  @retval 0 The URI path list structure does not contain the URI path
 *  @retval 1 The URI path list structure does contain the URI path
 */
static int iotsec_server_path_list_match(iotsec_server_path_list_t *list,
                                         const char *str) {
  iotsec_server_path_t *path = NULL;

  path = list->first;
  while (path != NULL) {
    iotsec_log_debug("Comparing URI path: '%s' with list URI path: '%s'", str,
                     path->str);
    if (strcmp(path->str, str) == 0) {
      iotsec_log_debug("Matched URI path: '%s' with list URI path: '%s'", str,
                       path->str);
      return 1;
    }
    path = path->next;
  }
  return 0;
}

#ifdef IOTSEC_DTLS_EN

/**
 *  @brief Listen for a packet from the client with a timeout
 *
 *  @param[in] trans Pointer to a transaction structure
 *  @param[in] ms Timeout value in msec
 *
 *  @returns Operation status
 *  @retval 1 Success
 *  @retval 0 Timeout
 *  @retval <0 Error
 */
static int iotsec_server_trans_dtls_listen_timeout(iotsec_server_trans_t *trans,
                                                   unsigned ms) {
  iotsec_server_t *server = NULL;
  struct timeval tv = {0};
  fd_set read_fds = {{0}};
  int ret = 0;

  server = trans->server;
  tv.tv_sec = ms / 1000;
  tv.tv_usec = (ms % 1000) * 1000;
  while (1) {
    FD_ZERO(&read_fds);
    FD_SET(server->sd, &read_fds);
    ret = select(server->sd + 1, &read_fds, NULL, NULL, &tv);
    if (ret < 0) {
      return -errno;
    }
    if (ret == 0) {
      return 0; /* timeout */
    }
    if (FD_ISSET(server->sd, &read_fds)) {
      return 1; /* success */
    }
  }
}

/**
 *  @brief Receive data from the client
 *
 *  This is a call-back function that the
 *  GnuTLS library uses to receive data.
 *  To report an error, it sets errno and
 *  returns -1.
 *
 *  @param[in,out] data Pointer to a transaction structure
 *  @param[out] buf Pointer to a buffer
 *  @param[in] len Length of the buffer
 *
 *  @returns Number of bytes received or error
 *  @retval 0 Number of bytes received
 *  @retval -1 Error
 */
static ssize_t iotsec_server_trans_dtls_pull_func(gnutls_transport_ptr_t data,
                                                  void *buf, size_t len) {
  iotsec_ipv_sockaddr_in_t client_sin = {0};
  iotsec_server_trans_t *trans = NULL;
  iotsec_server_t *server = NULL;
  socklen_t client_sin_len = 0;
  ssize_t num = 0;

  trans = (iotsec_server_trans_t *)data;
  server = trans->server;
  client_sin_len = sizeof(client_sin);
  num = recvfrom(server->sd, buf, len, MSG_PEEK, (struct sockaddr *)&client_sin,
                 &client_sin_len); /* peek data */
  if (num < 0) {
    return -1;
  }
  if ((client_sin_len != trans->client_sin_len) ||
      (memcmp(&client_sin, &trans->client_sin, trans->client_sin_len) != 0)) {
    errno = EINVAL;
    return -1;
  }
  num = recvfrom(server->sd, buf, num, 0, (struct sockaddr *)&client_sin,
                 &client_sin_len); /* consume data */
  if (num >= 0) {
    iotsec_log_debug("pulled %zd bytes", num);
  }
  return num;
}

/**
 *  @brief Wait for receive data from the client
 *
 *  This is a call-back function that the GnuTLS
 *  library uses to wait for receive data. To
 *  report an error, it sets errno and returns -1.
 *
 *  @param[in,out] data Pointer to a transaction structure
 *  @param[in] ms Timeout in msec
 *
 *  @returns Number of bytes received or error
 *  @retval >0 Number of bytes received
 *  @retval 0 Timeout
 *  @retval -1 Error
 */
static int
iotsec_server_trans_dtls_pull_timeout_func(gnutls_transport_ptr_t data,
                                           unsigned ms) {
  iotsec_ipv_sockaddr_in_t client_sin = {0};
  iotsec_server_trans_t *trans = NULL;
  iotsec_server_t *server = NULL;
  socklen_t client_sin_len = 0;
  ssize_t num = 0;
  char buf[IOTSEC_SERVER_DTLS_MTU] = {0};
  int ret = 0;

  trans = (iotsec_server_trans_t *)data;
  server = trans->server;
  ret = iotsec_server_trans_dtls_listen_timeout(trans, ms);
  if (ret == 0) {
    return 0; /* timeout */
  }
  if (ret < 0) {
    /* errno has been set by iotsec_server_trans_dtls_listen_timeout */
    return -1;
  }
  client_sin_len = sizeof(client_sin);
  num =
      recvfrom(server->sd, buf, sizeof(buf), MSG_PEEK,
               (struct sockaddr *)&client_sin, &client_sin_len); /* peek data */
  if (num < 0) {
    return -1;
  }
  if ((client_sin_len != trans->client_sin_len) ||
      (memcmp(&client_sin, &trans->client_sin, trans->client_sin_len) != 0)) {
    errno = EINVAL;
    return -1;
  }
  return num; /* success */
}

/**
 *  @brief Send data to the client
 *
 *  This is a call-back function that the
 *  GnuTLS library uses to send data. To
 *  report an error, it sets errno and
 *  returns -1.
 *
 *  @param[in] data Pointer to a transaction structure
 *  @param[in] buf Pointer to a buffer
 *  @param[in] len Length of the buffer
 *
 *  @returns Number of bytes sent or error
 *  @retval >0 Number of bytes sent
 *  @retval -1 Error
 */
static ssize_t iotsec_server_trans_dtls_push_func(gnutls_transport_ptr_t data,
                                                  const void *buf, size_t len) {
  iotsec_server_trans_t *trans = NULL;
  iotsec_server_t *server = NULL;
  ssize_t num = 0;

  trans = (iotsec_server_trans_t *)data;
  server = trans->server;
  num = sendto(server->sd, buf, len, 0, (struct sockaddr *)&trans->client_sin,
               trans->client_sin_len);
  if (num >= 0) {
    iotsec_log_debug("pushed %zd bytes", num);
  }
  return num;
}

/**
 *  @brief Perform a DTLS handshake with the client
 *
 *  @param[in,out] trans Pointer to a transaction structure
 *
 *  @returns Operation success
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int iotsec_server_trans_dtls_handshake(iotsec_server_trans_t *trans) {
  gnutls_alert_description_t alert = 0;
  gnutls_cipher_algorithm_t cipher = 0;
  gnutls_mac_algorithm_t mac = 0;
  gnutls_kx_algorithm_t kx = 0;
  const char *cipher_suite = NULL;
  const char *alert_name = NULL;
  unsigned timeout = 0;
  int ret = 0;
  int i = 0;

  iotsec_log_info("Initiating DTLS handshake");
  for (i = 0; i < IOTSEC_SERVER_DTLS_HANDSHAKE_ATTEMPTS; i++) {
    errno = 0;
    ret = gnutls_handshake(trans->session);
    iotsec_log_debug("DTLS handshake result: %s", gnutls_strerror_name(ret));
    if ((errno != 0) && (errno != EAGAIN)) {
      return -errno;
    }
    if (ret == GNUTLS_E_SUCCESS) {
      iotsec_log_info("Completed DTLS handshake");
      /* determine which cipher suite was negotiated */
      kx = gnutls_kx_get(trans->session);
      cipher = gnutls_cipher_get(trans->session);
      mac = gnutls_mac_get(trans->session);
      cipher_suite = gnutls_cipher_suite_get_name(kx, cipher, mac);
      if (cipher_suite != NULL)
        iotsec_log_info("Cipher suite is TLS_%s", cipher_suite);
      else
        iotsec_log_info("Cipher suite is unknown");
      return 0; /* success */
    }
    if (ret == GNUTLS_E_TIMEDOUT) {
      break;
    }
    if ((ret == GNUTLS_E_FATAL_ALERT_RECEIVED) ||
        (ret == GNUTLS_E_WARNING_ALERT_RECEIVED)) {
      alert = gnutls_alert_get(trans->session);
      alert_name = gnutls_alert_get_name(alert);
      if (ret == GNUTLS_E_FATAL_ALERT_RECEIVED)
        iotsec_log_error("Received DTLS alert from the client: %s", alert_name);
      else
        iotsec_log_warn("Received DTLS alert from the client: %s", alert_name);
      return -ECONNRESET;
    }
    if (ret != GNUTLS_E_AGAIN) {
      iotsec_log_error("Failed to complete DTLS handshake: %s",
                       gnutls_strerror_name(ret));
      return -1;
    }
    if (i < IOTSEC_SERVER_DTLS_HANDSHAKE_ATTEMPTS - 1) {
      timeout = gnutls_dtls_get_timeout(trans->session);
      iotsec_log_debug("Handshake timeout: %u msec", timeout);
      ret = iotsec_server_trans_dtls_listen_timeout(trans, timeout);
      if (ret < 0) {
        return ret;
      }
    }
  }
  return -ETIMEDOUT;
}

#ifdef IOTSEC_CLIENT_AUTH

/**
 *  @brief Verify the clients's certificate
 *
 *  @param[in,out] trans Pointer to a transaction structure
 *
 *  @returns Operation success
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int
iotsec_server_trans_dtls_verify_peer_cert(iotsec_server_trans_t *trans) {
  gnutls_certificate_type_t cert_type = 0;
  const gnutls_datum_t *cert_list = NULL;
  gnutls_x509_crt_t cert = {0};
  unsigned cert_list_size = 0;
  unsigned status = 0;
  time_t expiration_time = 0;
  time_t activation_time = 0;
  time_t current_time = 0;
  int ret = 0;

  ret = gnutls_certificate_verify_peers2(trans->session, &status);
  if (ret != GNUTLS_E_SUCCESS) {
    iotsec_log_error("The peer certificate was not verified: %s",
                     gnutls_strerror_name(ret));
    return -1;
  }
  if (status & GNUTLS_CERT_INVALID) {
    iotsec_log_error("The peer certificate is not trusted");
    return -1;
  }
  if (status & GNUTLS_CERT_SIGNER_NOT_FOUND) {
    iotsec_log_error("No issuer found for the peer certificate");
    return -1;
  }
  if (status & GNUTLS_CERT_SIGNER_NOT_CA) {
    iotsec_log_error(
        "The issuer for the peer certificate is not a certificate authority");
    return -1;
  }
  if (status & GNUTLS_CERT_REVOKED) {
    iotsec_log_error("The peer certificate has been revoked");
    return -1;
  }
  cert_type = gnutls_certificate_type_get(trans->session);
  if (cert_type != GNUTLS_CRT_X509) {
    iotsec_log_error("The peer certificate is not an X509 certificate");
    return -1;
  }
  ret = gnutls_x509_crt_init(&cert);
  if (ret != GNUTLS_E_SUCCESS) {
    iotsec_log_error("Unable to initialise gnutls_x509_crt_t object: %s",
                     gnutls_strerror_name(ret));
    return -1;
  }
  cert_list = gnutls_certificate_get_peers(trans->session, &cert_list_size);
  if (cert_list == NULL) {
    iotsec_log_error("No peer certificate found");
    gnutls_x509_crt_deinit(cert);
    return -1;
  }
  /* We only check the first (leaf) certificate in the chain */
  ret = gnutls_x509_crt_import(cert, &cert_list[0], GNUTLS_X509_FMT_DER);
  if (ret != GNUTLS_E_SUCCESS) {
    iotsec_log_error("Unable to parse certificate: %s",
                     gnutls_strerror_name(ret));
    gnutls_x509_crt_deinit(cert);
    return -1;
  }
  current_time = time(NULL);
  expiration_time = gnutls_x509_crt_get_expiration_time(cert);
  if ((expiration_time == -1) || (expiration_time < current_time)) {
    iotsec_log_error("The peer certificate has expired");
    gnutls_x509_crt_deinit(cert);
    return -1;
  }
  activation_time = gnutls_x509_crt_get_activation_time(cert);
  if ((activation_time == -1) || (activation_time > current_time)) {
    iotsec_log_error("The peer certificate is not yet activated");
    gnutls_x509_crt_deinit(cert);
    return -1;
  }
  iotsec_log_info("Peer certificate validated");
  gnutls_x509_crt_deinit(cert);
  return 0;
}

#endif /* IOTSEC_CLIENT_AUTH */

/**
 *  @brief Initialise the DTLS members of a transaction structure
 *
 *  Perform a DTLS handshake with the client.
 *
 *  @param[out] trans Pointer to a transaction structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int iotsec_server_trans_dtls_create(iotsec_server_trans_t *trans) {
  iotsec_server_t *server = NULL;
  int ret = 0;

  server = trans->server;
  ret = gnutls_init(&trans->session,
                    GNUTLS_SERVER | GNUTLS_DATAGRAM | GNUTLS_NONBLOCK);
  if (ret != GNUTLS_E_SUCCESS) {
    iotsec_log_error("Failed to initialise DTLS session: %s",
                     gnutls_strerror_name(ret));
    return -1;
  }
  ret = gnutls_credentials_set(trans->session, GNUTLS_CRD_CERTIFICATE,
                               server->cred);
  if (ret != GNUTLS_E_SUCCESS) {
    iotsec_log_error("Failed to assign credentials to DTLS session: %s",
                     gnutls_strerror_name(ret));
    gnutls_deinit(trans->session);
    return -1;
  }
  ret = gnutls_priority_set(trans->session, server->priority);
  if (ret != GNUTLS_E_SUCCESS) {
    iotsec_log_error("Failed to assign priorities to DTLS session: %s",
                     gnutls_strerror_name(ret));
    gnutls_deinit(trans->session);
    return -1;
  }
  gnutls_transport_set_ptr(trans->session, trans);
  gnutls_transport_set_pull_function(trans->session,
                                     iotsec_server_trans_dtls_pull_func);
  gnutls_transport_set_pull_timeout_function(
      trans->session, iotsec_server_trans_dtls_pull_timeout_func);
  gnutls_transport_set_push_function(trans->session,
                                     iotsec_server_trans_dtls_push_func);
  gnutls_dtls_set_mtu(trans->session, IOTSEC_SERVER_DTLS_MTU);
  gnutls_dtls_set_timeouts(trans->session, IOTSEC_SERVER_DTLS_RETRANS_TIMEOUT,
                           IOTSEC_SERVER_DTLS_TOTAL_TIMEOUT);
#ifdef IOTSEC_CLIENT_AUTH
  gnutls_certificate_server_set_request(trans->session, GNUTLS_CERT_REQUIRE);
#endif
  ret = iotsec_server_trans_dtls_handshake(trans);
  if (ret < 0) {
    gnutls_deinit(trans->session);
    return ret;
  }
#ifdef IOTSEC_CLIENT_AUTH
  ret = iotsec_server_trans_dtls_verify_peer_cert(trans);
  if (ret < 0) {
    gnutls_deinit(trans->session);
    return ret;
  }
#endif
  return 0;
}

/**
 *  @brief Deinitialise the DTLS members of a transaction structure
 *
 *  @param[in,out] trans Pointer to a transaction structure
 */
static void iotsec_server_trans_dtls_destroy(iotsec_server_trans_t *trans) {
  gnutls_bye(trans->session, GNUTLS_SHUT_WR);
  gnutls_deinit(trans->session);
}

#endif /* IOTSEC_DTLS_EN */

/**
 *  @brief Free the resources assigned to a blockwise transfer
 *
 *  @param[out] trans Pointer to a transaction structure
 */
static void iotsec_server_trans_clear_blockwise(iotsec_server_trans_t *trans) {
  trans->type = IOTSEC_SERVER_TRANS_REGULAR;
  if (trans->body != NULL) {
    iotsec_mem_large_free(trans->body);
    trans->body = NULL;
  }
  trans->body_len = 0;
  trans->body_end = 0;
  trans->block1_size = 0;
  trans->block2_size = 0;
  trans->block1_next = 0;
  trans->block2_next = 0;
  memset(trans->block_uri, 0, sizeof(trans->block_uri));
  trans->block_detail = 0;
  trans->block_rx = NULL;
}

/**
 *  @brief Deinitialise a transaction structure
 *
 *  @param[in,out] trans Pointer to a transaction structure
 */
static void iotsec_server_trans_destroy(iotsec_server_trans_t *trans) {
  iotsec_log_debug("Destroyed transaction for address %s and port %u",
                   trans->client_addr,
                   ntohs(trans->client_sin.IOTSEC_IPV_SIN_PORT));
  iotsec_server_trans_clear_blockwise(trans);
#ifdef IOTSEC_DTLS_EN
  iotsec_server_trans_dtls_destroy(trans);
#endif
  iotsec_msg_destroy(&trans->resp);
  iotsec_msg_destroy(&trans->req);
  close(trans->timer_fd);
  memset(trans, 0, sizeof(iotsec_server_trans_t));
}

/**
 *  @brief Mark the last time the transaction structure was used
 *
 *  @param[out] trans Pointer to a transaction structure
 */
static void iotsec_server_trans_touch(iotsec_server_trans_t *trans) {
  trans->last_use = time(NULL);
}

/**
 *  @brief Compare a received message with the request part of a transaction
 * structure
 *
 *  @param[in] trans Pointer to a trasaction structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Comparison value
 *  @retval 0 The message does not match the transaction
 *  @retval 1 The message matches the transaction
 */
static int iotsec_server_trans_match_req(iotsec_server_trans_t *trans,
                                         iotsec_msg_t *msg) {
  return ((iotsec_msg_get_ver(&trans->req) != 0) &&
          (iotsec_msg_get_msg_id(&trans->req) == iotsec_msg_get_msg_id(msg)));
}

/**
 *  @brief Compare a recevied message with the response part of a transaction
 * structure
 *
 *  @param[in] trans Pointer to a trasaction structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Comparison value
 *  @retval 0 The message does not match the transaction
 *  @retval 1 The message matches the transaction
 */
static int iotsec_server_trans_match_resp(iotsec_server_trans_t *trans,
                                          iotsec_msg_t *msg) {
  return ((iotsec_msg_get_ver(&trans->resp) != 0) &&
          (iotsec_msg_get_msg_id(&trans->resp) == iotsec_msg_get_msg_id(msg)));
}

/**
 *  @brief Clear the request message in a transaction structure
 *
 *  @param[in,out] trans Pointer to a transaction structure
 */
static void iotsec_server_trans_clear_req(iotsec_server_trans_t *trans) {
  iotsec_msg_destroy(&trans->req);
}

/**
 *  @brief Clear the response message in a transaction structure
 *
 *  @param[in,out] trans Pointer to a transaction structure
 */
static void iotsec_server_trans_clear_resp(iotsec_server_trans_t *trans) {
  iotsec_msg_destroy(&trans->resp);
}

/**
 *  @brief Set the request message in a transaction structure
 *
 *  @param[in,out] trans Pointer to a transaction structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int iotsec_server_trans_set_req(iotsec_server_trans_t *trans,
                                       iotsec_msg_t *msg) {
  iotsec_msg_reset(&trans->req);
  return iotsec_msg_copy(&trans->req, msg);
}

/**
 *  @brief Set the response message in a transaction structure
 *
 *  @param[in,out] trans Pointer to a transaction structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int iotsec_server_trans_set_resp(iotsec_server_trans_t *trans,
                                        iotsec_msg_t *msg) {
  iotsec_msg_reset(&trans->resp);
  return iotsec_msg_copy(&trans->resp, msg);
}

/**
 *  @brief Initialise the acknowledgement timer in a transaction structure
 *
 *  The timer is initialised to a random duration between:
 *
 *  ACK_TIMEOUT and (ACK_TIMEOUT * ACK_RANDOM_FACTOR)
 *  where:
 *  ACK_TIMEOUT = 2
 *  ACK_RANDOM_FACTOR = 1.5
 *
 *  @param[out] trans Pointer to a transaction structure
 */
static void iotsec_server_trans_init_ack_timeout(iotsec_server_trans_t *trans) {
  if (!rand_init) {
    srand(time(NULL));
    rand_init = 1;
  }
  trans->timeout.tv_sec = IOTSEC_SERVER_ACK_TIMEOUT_SEC;
  trans->timeout.tv_nsec = (rand() % 1000) * 1000000;
  iotsec_log_debug("Acknowledgement timeout initialised to: %lu sec, %lu nsec",
                   trans->timeout.tv_sec, trans->timeout.tv_nsec);
}

/**
 *  @brief Double the value of the timer in a transaction structure
 *
 *  @param[in,out] trans Pointer to a trans structure
 */
static void iotsec_server_trans_double_timeout(iotsec_server_trans_t *trans) {
  unsigned msec =
      2 * ((trans->timeout.tv_sec * 1000) + (trans->timeout.tv_nsec / 1000000));
  trans->timeout.tv_sec = msec / 1000;
  trans->timeout.tv_nsec = (msec % 1000) * 1000000;
  iotsec_log_debug("Timeout doubled to: %lu sec, %lu nsec",
                   trans->timeout.tv_sec, trans->timeout.tv_nsec);
}

/**
 *  @brief Start the timer in a transaction structure
 *
 *  @param[in,out] trans Pointer to a transaction structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int iotsec_server_trans_start_timer(iotsec_server_trans_t *trans) {
  struct itimerspec its = {{0}};
  int ret = 0;

  its.it_value = trans->timeout;
  ret = timerfd_settime(trans->timer_fd, 0, &its, NULL);
  if (ret < 0) {
    return -errno;
  }
  return 0;
}

/**
 *  @brief Stop the timer in a transaction structure
 *
 *  @param[out] trans Pointer to a transaction structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int iotsec_server_trans_stop_timer(iotsec_server_trans_t *trans) {
  struct itimerspec its = {{0}};
  int ret = 0;

  ret = timerfd_settime(trans->timer_fd, 0, &its, NULL);
  if (ret < 0) {
    return -errno;
  }
  return 0;
}

/**
 *  @brief Initialise and start the acknowledgement timer in a transaction
 * structure
 *
 *  @param[out] trans Pointer to a trans structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int iotsec_server_trans_start_ack_timer(iotsec_server_trans_t *trans) {
  trans->num_retrans = 0;
  iotsec_server_trans_init_ack_timeout(trans);
  return iotsec_server_trans_start_timer(trans);
}

/**
 *  @brief Stop the acknowledgement timer in a transaction structure
 *
 *  @param[out] trans Pointer to a transaction structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int iotsec_server_trans_stop_ack_timer(iotsec_server_trans_t *trans) {
  trans->num_retrans = 0;
  return iotsec_server_trans_stop_timer(trans);
}

/**
 *  @brief Update the acknowledgement timer in a transaction structure
 *
 *  Increase and restart the acknowledgement timer in a transaction structure
 *  and indicate if the maximum number of retransmits has been reached.
 *
 *  @param[in,out] trans Pointer to a trans structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int iotsec_server_trans_update_ack_timer(iotsec_server_trans_t *trans) {
  int ret = 0;

  if (trans->num_retrans >= IOTSEC_SERVER_MAX_RETRANSMIT) {
    return -ETIMEDOUT;
  }
  iotsec_server_trans_double_timeout(trans);
  ret = iotsec_server_trans_start_timer(trans);
  if (ret < 0) {
    return ret;
  }
  trans->num_retrans++;
  return 0;
}

/**
 *  @brief Send a message to the client
 *
 *  @param[in,out] trans Pointer to a transaction structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Number of bytes sent or error code
 *  @retval >0 Number of bytes sent
 *  @retval <0 Error
 */
static ssize_t iotsec_server_trans_send(iotsec_server_trans_t *trans,
                                        iotsec_msg_t *msg) {
#ifndef IOTSEC_DTLS_EN
  iotsec_server_t *server = NULL;
#endif
  ssize_t num = 0;
  char buf[IOTSEC_MSG_MAX_BUF_LEN] = {0};

  num = iotsec_msg_format(msg, buf, sizeof(buf));
  if (num < 0) {
    return num;
  }
#ifdef IOTSEC_DTLS_EN
  errno = 0;
  num = gnutls_record_send(trans->session, buf, num);
  if (errno != 0) {
    return -errno;
  }
  if (num == 0) {
    return -ECONNRESET;
  }
  if (num == GNUTLS_E_AGAIN) {
    return -EAGAIN;
  }
  if (num < 0) {
    iotsec_log_error("Failed to send to client: %s", gnutls_strerror_name(num));
    return -1;
  }
#else
  server = trans->server;
  num = sendto(server->sd, buf, num, 0, (struct sockaddr *)&trans->client_sin,
               trans->client_sin_len);
  if (num < 0) {
    return -errno;
  }
#endif
  iotsec_server_trans_touch(trans);
  iotsec_log_debug("Sent to address %s and port %u", trans->client_addr,
                   ntohs(trans->client_sin.IOTSEC_IPV_SIN_PORT));
  return num;
}

/**
 *  @brief Handle a format error in a received message
 *
 *  Special handling for the case where a received
 *  message could not be parsed due to a format error.
 *  Extract enough information from the received message
 *  to form a reset message.
 *
 *  @param[in,out] trans Pointer to a transaction structure
 *  @param[in] buf Buffer containing the message
 *  @param[in] len length of the buffer
 */
static void
iotsec_server_trans_handle_format_error(iotsec_server_trans_t *trans, char *buf,
                                        unsigned len) {
  iotsec_msg_t msg = {0};
  unsigned msg_id = 0;
  unsigned type = 0;
  int ret = 0;

  /* extract enough information to form a reset message */
  ret = iotsec_msg_parse_type_msg_id(buf, len, &type, &msg_id);
  if ((ret == 0) && (type == IOTSEC_MSG_CON)) {
    iotsec_msg_create(&msg);
    ret = iotsec_msg_set_type(&msg, IOTSEC_MSG_RST);
    if (ret < 0) {
      iotsec_msg_destroy(&msg);
      return;
    }
    ret = iotsec_msg_set_msg_id(&msg, msg_id);
    if (ret < 0) {
      iotsec_msg_destroy(&msg);
      return;
    }
    iotsec_server_trans_send(trans, &msg);
    iotsec_msg_destroy(&msg);
  }
}

/**
 *  @brief Receive a message from the client
 *
 *  @param[in,out] trans Pointer to a transaction structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Number of bytes received or error code
 *  @retval >0 Number of bytes received
 *  @retval <0 Error
 */
static ssize_t iotsec_server_trans_recv(iotsec_server_trans_t *trans,
                                        iotsec_msg_t *msg) {
#ifdef IOTSEC_DTLS_EN
  gnutls_alert_description_t alert = 0;
  const char *alert_name = NULL;
#else
  iotsec_ipv_sockaddr_in_t client_sin = {0};
  iotsec_server_t *server = NULL;
  socklen_t client_sin_len = 0;
#endif
  ssize_t num = 0;
  ssize_t ret = 0;
  char buf[IOTSEC_MSG_MAX_BUF_LEN] = {0};

#ifdef IOTSEC_DTLS_EN
  errno = 0;
  num = gnutls_record_recv(trans->session, buf, sizeof(buf));
  if (errno != 0) {
    return -errno;
  }
  if ((num == GNUTLS_E_FATAL_ALERT_RECEIVED) ||
      (num == GNUTLS_E_WARNING_ALERT_RECEIVED) || (num == 0)) {
    alert = gnutls_alert_get(trans->session);
    alert_name = gnutls_alert_get_name(alert);
    if (num == GNUTLS_E_FATAL_ALERT_RECEIVED)
      iotsec_log_error("Received DTLS alert from the client: %s", alert_name);
    else if (num == GNUTLS_E_WARNING_ALERT_RECEIVED)
      iotsec_log_warn("Received DTLS alert from the client: %s", alert_name);
    else
      iotsec_log_info("Received DTLS alert from the client: %s", alert_name);
    return -ECONNRESET;
  }
  if (num == GNUTLS_E_AGAIN) {
    return -EAGAIN;
  }
  if (num < 0) {
    iotsec_log_error("Failed to receive from client: %s",
                     gnutls_strerror_name(num));
    return -1;
  }
#else
  server = trans->server;
  client_sin_len = sizeof(client_sin);
  num = recvfrom(server->sd, buf, sizeof(buf), MSG_PEEK,
                 (struct sockaddr *)&client_sin, &client_sin_len);
  if (num < 0) {
    return -errno;
  }
  if ((client_sin_len != trans->client_sin_len) ||
      (memcmp(&client_sin, &trans->client_sin, client_sin_len) != 0)) {
    return -EINVAL;
  }
  num = recvfrom(server->sd, buf, num, 0, (struct sockaddr *)&client_sin,
                 &client_sin_len);
  if (num < 0) {
    return -errno;
  }
#endif
  ret = iotsec_msg_parse(msg, buf, num);
  if (ret < 0) {
    if (ret == -EBADMSG) {
      iotsec_server_trans_handle_format_error(trans, buf, num);
    }
    return ret;
  }
  iotsec_server_trans_touch(trans);
  iotsec_log_debug("Received from address %s and port %u", trans->client_addr,
                   ntohs(trans->client_sin.IOTSEC_IPV_SIN_PORT));
  return num;
}

/**
 *  @brief Reject a received confirmable message
 *
 *  Send a reset message to the client.
 *
 *  @param[in,out] trans Pointer to a transaction structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int iotsec_server_trans_reject_con(iotsec_server_trans_t *trans,
                                          iotsec_msg_t *msg) {
  iotsec_msg_t rej = {0};
  ssize_t num = 0;
  int ret = 0;

  iotsec_log_info("Rejecting confirmable message from address %s and port %u",
                  trans->client_addr,
                  ntohs(trans->client_sin.IOTSEC_IPV_SIN_PORT));
  iotsec_msg_create(&rej);
  ret = iotsec_msg_set_type(&rej, IOTSEC_MSG_RST);
  if (ret < 0) {
    iotsec_msg_destroy(&rej);
    return ret;
  }
  ret = iotsec_msg_set_msg_id(&rej, iotsec_msg_get_msg_id(msg));
  if (ret < 0) {
    iotsec_msg_destroy(&rej);
    return ret;
  }
  num = iotsec_server_trans_send(trans, &rej);
  iotsec_msg_destroy(&rej);
  if (num < 0) {
    return num;
  }
  return 0;
}

/**
 *  @brief Reject a received non-confirmable message
 *
 *  @param[in] trans Pointer to a transaction structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 */
static int iotsec_server_trans_reject_non(iotsec_server_trans_t *trans,
                                          iotsec_msg_t *msg) {
  iotsec_log_info(
      "Rejecting non-confirmable message from address %s and port %u",
      trans->client_addr, ntohs(trans->client_sin.IOTSEC_IPV_SIN_PORT));
  return 0;
}

/**
 *  @brief Reject a received acknowledgement message
 *
 *  @param[in] trans Pointer to a transaction structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 */
static int iotsec_server_trans_reject_ack(iotsec_server_trans_t *trans,
                                          iotsec_msg_t *msg) {
  iotsec_log_info(
      "Rejecting acknowledgement message from address %s and port %u",
      trans->client_addr, ntohs(trans->client_sin.IOTSEC_IPV_SIN_PORT));
  return 0;
}

/**
 *  @brief Reject a received reset message
 *
 *  @param[in] trans Pointer to a transaction structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 */
static int iotsec_server_trans_reject_reset(iotsec_server_trans_t *trans,
                                            iotsec_msg_t *msg) {
  iotsec_log_info("Rejecting reset message from address %s and port %u",
                  trans->client_addr,
                  ntohs(trans->client_sin.IOTSEC_IPV_SIN_PORT));
  return 0;
}

/**
 *  @brief Reject a received message
 *
 *  @param[in,out] trans Pointer to a transaction structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int iotsec_server_trans_reject(iotsec_server_trans_t *trans,
                                      iotsec_msg_t *msg) {
  if (iotsec_msg_get_type(msg) == IOTSEC_MSG_CON) {
    return iotsec_server_trans_reject_con(trans, msg);
  } else if (iotsec_msg_get_type(msg) == IOTSEC_MSG_NON) {
    return iotsec_server_trans_reject_non(trans, msg);
  } else if (iotsec_msg_get_type(msg) == IOTSEC_MSG_ACK) {
    return iotsec_server_trans_reject_ack(trans, msg);
  } else if (iotsec_msg_get_type(msg) == IOTSEC_MSG_RST) {
    return iotsec_server_trans_reject_reset(trans, msg);
  }
  return 0; /* should never arrive here */
}

/**
 *  @brief Handle a received message containing a bad option
 *
 *  @param[in,out] trans Pointer to a transaction structure
 *  @param[out] send_msg Pointer to the send message
 *  @param[in] op_num Option number of the bad option
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int iotsec_server_trans_handle_bad_option(iotsec_server_trans_t *trans,
                                                 iotsec_msg_t *send_msg,
                                                 unsigned op_num) {
  char payload[IOTSEC_SERVER_DIAG_PAYLOAD_LEN] = {0};
  int ret = 0;

  iotsec_log_info(
      "Found bad option number %u in message from address %s and port %u",
      op_num, trans->client_addr, ntohs(trans->client_sin.IOTSEC_IPV_SIN_PORT));
  iotsec_log_info("Sending 'Bad Option' response to address %s and port %u",
                  trans->client_addr,
                  ntohs(trans->client_sin.IOTSEC_IPV_SIN_PORT));
  ret = iotsec_msg_set_code(send_msg, IOTSEC_MSG_CLIENT_ERR,
                            IOTSEC_MSG_BAD_OPTION);
  if (ret < 0) {
    return ret;
  }
  snprintf(payload, sizeof(payload), "Bad option number: %u", op_num);
  ret = iotsec_msg_set_payload(send_msg, payload, strlen(payload));
  if (ret < 0) {
    return ret;
  }
  return 0;
}

/**
 *  @brief Send an acknowledgement message to the client
 *
 *  @param[in,out] trans Pointer to a transaction structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int iotsec_server_trans_send_ack(iotsec_server_trans_t *trans,
                                        iotsec_msg_t *msg) {
  iotsec_msg_t ack = {0};
  ssize_t num = 0;
  int ret = 0;

  iotsec_log_info(
      "Acknowledging confirmable message from address %s and port %u",
      trans->client_addr, ntohs(trans->client_sin.IOTSEC_IPV_SIN_PORT));
  iotsec_msg_create(&ack);
  ret = iotsec_msg_set_type(&ack, IOTSEC_MSG_ACK);
  if (ret < 0) {
    iotsec_msg_destroy(&ack);
    return ret;
  }
  ret = iotsec_msg_set_msg_id(&ack, iotsec_msg_get_msg_id(msg));
  if (ret < 0) {
    iotsec_msg_destroy(&ack);
    return ret;
  }
  num = iotsec_server_trans_send(trans, &ack);
  iotsec_msg_destroy(&ack);
  if (num < 0) {
    return num;
  }
  return 0;
}

/**
 *  @brief Handle an acknowledgement timeout
 *
 *  Update the acknowledgement timer in the transaction structure
 *  and if the maximum number of retransmits has not been reached
 *  then retransmit the last response to the client.
 *
 *  @param[in,out] trans Pointer to a transaction structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int
iotsec_server_trans_handle_ack_timeout(iotsec_server_trans_t *trans) {
  ssize_t num = 0;
  int ret = 0;

  iotsec_log_debug("Transaction expired for address %s and port %u",
                   trans->client_addr,
                   ntohs(trans->client_sin.IOTSEC_IPV_SIN_PORT));
  ret = iotsec_server_trans_update_ack_timer(trans);
  if (ret == 0) {
    iotsec_log_debug("Retransmitting to address %s and port %u",
                     trans->client_addr,
                     ntohs(trans->client_sin.IOTSEC_IPV_SIN_PORT));
    num = iotsec_server_trans_send(trans, &trans->resp);
    if (num < 0) {
      return num;
    }
  } else if (ret == -ETIMEDOUT) {
    iotsec_log_debug("Stopped retransmitting to address %s and port %u",
                     trans->client_addr,
                     ntohs(trans->client_sin.IOTSEC_IPV_SIN_PORT));
    iotsec_log_info("No acknowledgement received from address %s and port %u",
                    trans->client_addr,
                    ntohs(trans->client_sin.IOTSEC_IPV_SIN_PORT));
    iotsec_server_trans_destroy(trans);
    ret = 0;
  }
  return ret;
}

/**
 *  @brief Initialise a transaction structure
 *
 *  @param[out] trans Pointer to a transaction structure
 *  @param[in] server Pointer to a server structure
 *  @param[in] client_sin Pointer to a socket structure
 *  @param[in] client_sin_len Length of the socket structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int iotsec_server_trans_create(iotsec_server_trans_t *trans,
                                      iotsec_server_t *server,
                                      iotsec_ipv_sockaddr_in_t *client_sin,
                                      socklen_t client_sin_len) {
  const char *p = NULL;
#ifdef IOTSEC_DTLS_EN
  int ret = 0;
#endif

  memset(trans, 0, sizeof(iotsec_server_trans_t));
  trans->active = 1;
  iotsec_server_trans_touch(trans);
  trans->timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
  if (trans->timer_fd < 0) {
    memset(trans, 0, sizeof(iotsec_server_trans_t));
    return -errno;
  }
  memcpy(&trans->client_sin, client_sin, client_sin_len);
  trans->client_sin_len = client_sin_len;
  p = inet_ntop(IOTSEC_IPV_AF_INET, &client_sin->IOTSEC_IPV_SIN_ADDR,
                trans->client_addr, sizeof(trans->client_addr));
  if (p == NULL) {
    close(trans->timer_fd);
    memset(trans, 0, sizeof(iotsec_server_trans_t));
    return -errno;
  }
  iotsec_msg_create(&trans->req);
  iotsec_msg_create(&trans->resp);
  trans->server = server;
#ifdef IOTSEC_DTLS_EN
  ret = iotsec_server_trans_dtls_create(trans);
  if (ret < 0) {
    iotsec_msg_destroy(&trans->resp);
    iotsec_msg_destroy(&trans->req);
    close(trans->timer_fd);
    memset(trans, 0, sizeof(iotsec_server_trans_t));
    return ret;
  }
#endif
  iotsec_log_debug("Created transaction for address %s and port %u",
                   trans->client_addr,
                   ntohs(trans->client_sin.IOTSEC_IPV_SIN_PORT));
  return 0;
}

/**
 *  @brief Generate a response for the next block in a blockwise transfer
 *
 *  This function will choose the smaller of the block1_size
 *  value passed to the iotsec_server_trans_handle_blockwise
 *  function by the application and any value specified in
 *  the request message and similarly for the block2_size value.
 *
 *  @param[in,out] trans Pointer to a transaction structure
 *  @param[in] req Pointer to the request message
 *  @param[out] resp Pointer to the response message
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int iotsec_server_trans_handle_next_block(iotsec_server_trans_t *trans,
                                                 iotsec_msg_t *req,
                                                 iotsec_msg_t *resp) {
  iotsec_msg_success_t code_detail = 0;
  unsigned payload_len = 0;
  unsigned block1_size = 0;
  unsigned block2_size = 0;
  unsigned block1_more = 0;
  unsigned block2_more = 0;
  unsigned block1_num = 0;
  unsigned block2_num = 0;
  unsigned block_len = 0;
  size_t block1_next = 0;
  size_t block2_next = 0;
  char block_uri[IOTSEC_MSG_OP_URI_PATH_MAX_LEN + 1] = {0};
  char block_val[IOTSEC_MSG_OP_MAX_BLOCK_VAL_LEN] = {0};
  int block1_szx = -1;
  int block2_szx = -1;
  int ret = 0;

  /* allow the client to resize the blocks */
  ret = iotsec_msg_parse_block_op(&block1_num, &block1_more, &block1_size, req,
                                  IOTSEC_MSG_BLOCK1);
  if (ret < 0) {
    iotsec_log_info(
        "Unable to parse block1 option in message from address %s and port %u",
        trans->client_addr, ntohs(trans->client_sin.IOTSEC_IPV_SIN_PORT));
    iotsec_server_trans_clear_blockwise(trans);
    return iotsec_msg_set_code(resp, IOTSEC_MSG_CLIENT_ERR, IOTSEC_MSG_BAD_REQ);
  }
  if ((ret == 0) && (block1_size < trans->block1_size)) {
    trans->block1_size = block1_size;
  }
  ret = iotsec_msg_parse_block_op(&block2_num, &block2_more, &block2_size, req,
                                  IOTSEC_MSG_BLOCK2);
  if (ret < 0) {
    iotsec_log_info(
        "Unable to parse block2 option in message from address %s and port %u",
        trans->client_addr, ntohs(trans->client_sin.IOTSEC_IPV_SIN_PORT));
    iotsec_server_trans_clear_blockwise(trans);
    return iotsec_msg_set_code(resp, IOTSEC_MSG_CLIENT_ERR, IOTSEC_MSG_BAD_REQ);
  }
  if ((ret == 0) && (block2_size < trans->block2_size)) {
    trans->block2_size = block2_size;
  }
  iotsec_msg_uri_path_to_str(req, block_uri, sizeof(block_uri));
  if ((trans->type == IOTSEC_SERVER_TRANS_BLOCKWISE_GET) ||
      (trans->type == IOTSEC_SERVER_TRANS_BLOCKWISE_PUT2) ||
      (trans->type == IOTSEC_SERVER_TRANS_BLOCKWISE_POST2)) {
    iotsec_log_debug(
        "Handling block with start byte index %u for blockwise transfer",
        trans->block2_next);
    /* check for continuity between the current and previous blocks
     * the client may not include a block2 option in the first message
     * but must include a block2 option in subsequent messages
     */
    block2_next =
        block2_num * trans->block2_size; /* start byte index according to the
                                            client or for the first block */
    if (((trans->type == IOTSEC_SERVER_TRANS_BLOCKWISE_GET) &&
         (iotsec_msg_get_code_detail(req) != IOTSEC_MSG_GET)) ||
        ((trans->type == IOTSEC_SERVER_TRANS_BLOCKWISE_PUT2) &&
         (iotsec_msg_get_code_detail(req) != IOTSEC_MSG_PUT)) ||
        ((trans->type == IOTSEC_SERVER_TRANS_BLOCKWISE_POST2) &&
         (iotsec_msg_get_code_detail(req) != IOTSEC_MSG_POST)) ||
        (strcmp(block_uri, trans->block_uri) != 0) ||
        (block2_next != trans->block2_next)) {
      iotsec_log_info("Unexpected request message during blockwise transfer "
                      "from address %s and port %u",
                      trans->client_addr,
                      ntohs(trans->client_sin.IOTSEC_IPV_SIN_PORT));
      iotsec_server_trans_clear_blockwise(trans);
      return iotsec_msg_set_code(resp, IOTSEC_MSG_CLIENT_ERR,
                                 IOTSEC_MSG_BAD_REQ);
    }
    ret = iotsec_msg_op_calc_block_szx(trans->block2_size);
    if (ret < 0) {
      iotsec_log_warn(
          "Failed to calculate block size exponent from block2 size %u",
          trans->block2_size);
      iotsec_server_trans_clear_blockwise(trans);
      return ret;
    }
    block2_szx = ret;
    block2_more = 1;
    payload_len = trans->block2_size;
    if (trans->block2_next + trans->block2_size > trans->body_end) {
      block2_more = 0;
      payload_len = trans->body_end - trans->block2_next;
    }
    block2_num = iotsec_msg_block_start_to_num(trans->block2_next, block2_szx);
    ret =
        iotsec_msg_op_format_block_val(block_val, sizeof(block_val), block2_num,
                                       block2_more, trans->block2_size);
    if (ret < 0) {
      iotsec_log_warn(
          "Failed to format block2 option value, num %u, more %u, size %u",
          block2_num, block2_more, trans->block2_size);
      iotsec_server_trans_clear_blockwise(trans);
      return ret;
    }
    block_len = ret;
    ret = iotsec_msg_add_op(resp, IOTSEC_MSG_BLOCK2, block_len, block_val);
    if (ret < 0) {
      iotsec_server_trans_clear_blockwise(trans);
      return ret;
    }
    ret = iotsec_msg_set_payload(resp, trans->body + trans->block2_next,
                                 payload_len);
    if (ret < 0) {
      iotsec_server_trans_clear_blockwise(trans);
      return ret;
    }
    trans->block2_next += payload_len;
    code_detail = IOTSEC_MSG_CONTINUE;
    if (!block2_more) {
      if (trans->type == IOTSEC_SERVER_TRANS_BLOCKWISE_GET) {
        iotsec_log_info("Completed GET library-level blockwise transfer with "
                        "address %s and port %u",
                        trans->client_addr,
                        ntohs(trans->client_sin.IOTSEC_IPV_SIN_PORT));
        code_detail = IOTSEC_MSG_CONTENT;
      } else if (trans->type == IOTSEC_SERVER_TRANS_BLOCKWISE_PUT2) {
        iotsec_log_info("Completed PUT library-level blockwise transfer with "
                        "address %s and port %u",
                        trans->client_addr,
                        ntohs(trans->client_sin.IOTSEC_IPV_SIN_PORT));
        code_detail = trans->block_detail;
      } else {
        iotsec_log_info("Completed POST library-level blockwise transfer with "
                        "address %s and port %u",
                        trans->client_addr,
                        ntohs(trans->client_sin.IOTSEC_IPV_SIN_PORT));
        code_detail = trans->block_detail;
      }
      iotsec_server_trans_clear_blockwise(trans);
    }
    return iotsec_msg_set_code(resp, IOTSEC_MSG_SUCCESS, code_detail);
  } else if ((trans->type == IOTSEC_SERVER_TRANS_BLOCKWISE_PUT1) ||
             (trans->type == IOTSEC_SERVER_TRANS_BLOCKWISE_POST1)) {
    iotsec_log_debug(
        "Handling block with start byte index %u for blockwise transfer",
        trans->block1_next);
    /* check for continuity between the current and previous blocks */
    block1_next =
        block1_num *
        trans->block1_size; /* start byte index according to the client */
    if (((trans->type == IOTSEC_SERVER_TRANS_BLOCKWISE_PUT1) &&
         (iotsec_msg_get_code_detail(req) != IOTSEC_MSG_PUT)) ||
        ((trans->type == IOTSEC_SERVER_TRANS_BLOCKWISE_POST1) &&
         (iotsec_msg_get_code_detail(req) != IOTSEC_MSG_POST)) ||
        (strcmp(block_uri, trans->block_uri) != 0)) {
      iotsec_log_info("Unexpected request message during blockwise transfer "
                      "from address %s and port %u",
                      trans->client_addr,
                      ntohs(trans->client_sin.IOTSEC_IPV_SIN_PORT));
      iotsec_server_trans_clear_blockwise(trans);
      return iotsec_msg_set_code(resp, IOTSEC_MSG_CLIENT_ERR,
                                 IOTSEC_MSG_BAD_REQ);
    }
    if (block1_next != trans->block1_next) {
      iotsec_log_info(
          "Out-of-sequence block received from address %s and port %u",
          trans->client_addr, ntohs(trans->client_sin.IOTSEC_IPV_SIN_PORT));
      iotsec_server_trans_clear_blockwise(trans);
      return iotsec_msg_set_code(resp, IOTSEC_MSG_CLIENT_ERR,
                                 IOTSEC_MSG_INCOMPLETE);
    }
    if (iotsec_msg_get_payload(req) == NULL) {
      iotsec_log_info("Missing payload in request message during blockwise "
                      "transfer from address %s and port %u",
                      trans->client_addr,
                      ntohs(trans->client_sin.IOTSEC_IPV_SIN_PORT));
      iotsec_server_trans_clear_blockwise(trans);
      return iotsec_msg_set_code(resp, IOTSEC_MSG_CLIENT_ERR,
                                 IOTSEC_MSG_BAD_REQ);
    }
    ret = iotsec_msg_op_calc_block_szx(trans->block1_size);
    if (ret < 0) {
      iotsec_log_warn(
          "Failed to calculate block size exponent from block1 size %u",
          trans->block1_size);
      iotsec_server_trans_clear_blockwise(trans);
      return ret;
    }
    block1_szx = ret;
    payload_len = iotsec_msg_get_payload_len(req);
    if (trans->block1_next + payload_len > trans->body_len) {
      iotsec_log_info("Insufficient buffer size in blockwise transfer from "
                      "address %s and port %u",
                      trans->client_addr,
                      ntohs(trans->client_sin.IOTSEC_IPV_SIN_PORT));
      iotsec_server_trans_clear_blockwise(trans);
      return iotsec_msg_set_code(resp, IOTSEC_MSG_CLIENT_ERR,
                                 IOTSEC_MSG_REQ_ENT_TOO_LARGE);
    }
    block1_num = iotsec_msg_block_start_to_num(trans->block1_next, block1_szx);
    ret =
        iotsec_msg_op_format_block_val(block_val, sizeof(block_val), block1_num,
                                       block1_more, trans->block1_size);
    if (ret < 0) {
      iotsec_log_warn("Failed to format block2 option value, num %d, size %d",
                      block1_num, trans->block1_size);
      iotsec_server_trans_clear_blockwise(trans);
      return ret;
    }
    block_len = ret;
    ret = iotsec_msg_add_op(resp, IOTSEC_MSG_BLOCK1, block_len, block_val);
    if (ret < 0) {
      iotsec_server_trans_clear_blockwise(trans);
      return ret;
    }
    memcpy(trans->body + trans->block1_next, iotsec_msg_get_payload(req),
           payload_len);
    trans->block1_next += payload_len;
    trans->body_end += payload_len;
    code_detail = IOTSEC_MSG_CONTINUE;
    if (!block1_more) {
      /* copy received data to the application's buffer */
      if (trans->type == IOTSEC_SERVER_TRANS_BLOCKWISE_PUT1) {
        iotsec_log_info("Completed PUT library-level blockwise transfer with "
                        "address %s and port %u",
                        trans->client_addr,
                        ntohs(trans->client_sin.IOTSEC_IPV_SIN_PORT));
      } else {
        iotsec_log_info("Completed POST library-level blockwise transfer with "
                        "address %s and port %u",
                        trans->client_addr,
                        ntohs(trans->client_sin.IOTSEC_IPV_SIN_PORT));
      }
      /* allow the application to process the received data */
      /* and generate a body for the response */
      ret = (*trans->block_rx)(trans, req, resp);
      if (ret < 0) {
        iotsec_log_warn("Call to blockwise receive callback function failed");
        iotsec_server_trans_clear_blockwise(trans);
        return ret;
      }
      if (iotsec_msg_get_code_class(resp) != IOTSEC_MSG_SUCCESS) {
        /* return the response generated by the call to trans->block_rx */
        iotsec_server_trans_clear_blockwise(trans);
        return 0;
      }
      code_detail = iotsec_msg_get_code_detail(resp);
      if (trans->body_end > 0) {
        if (trans->type == IOTSEC_SERVER_TRANS_BLOCKWISE_PUT1) {
          trans->type = IOTSEC_SERVER_TRANS_BLOCKWISE_PUT2;
        } else {
          trans->type = IOTSEC_SERVER_TRANS_BLOCKWISE_POST2;
        }
        trans->block_detail = iotsec_msg_get_code_detail(resp);
        /* the response contains a body as well as the request
         * handle this block twice:
         *   this time to process the request payload
         *   next time to generate the response
         */
        return iotsec_server_trans_handle_next_block(trans, req, resp);
      }
      iotsec_server_trans_clear_blockwise(trans);
    }
    return iotsec_msg_set_code(resp, IOTSEC_MSG_SUCCESS, code_detail);
  }
  return 0;
}

int iotsec_server_trans_handle_blockwise(
    iotsec_server_trans_t *trans, iotsec_msg_t *req, iotsec_msg_t *resp,
    unsigned block1_size, unsigned block2_size, char *body, size_t body_len,
    iotsec_server_trans_handler_t block_rx) {
  unsigned code_detail = 0;
  int ret = 0;

  iotsec_server_trans_clear_blockwise(trans);
  if (block1_size > 0) {
    ret = iotsec_msg_op_calc_block_szx(block1_size);
    if (ret < 0) {
      return -EINVAL;
    }
  }
  if (block2_size > 0) {
    ret = iotsec_msg_op_calc_block_szx(block2_size);
    if (ret < 0) {
      return -EINVAL;
    }
  }
  if (body_len > iotsec_mem_large_get_len()) {
    return -ENOSPC;
  }
  trans->body = iotsec_mem_large_alloc(body_len);
  if (trans->body == NULL) {
    return -ENOMEM;
  }
  trans->body_len = iotsec_mem_large_get_len();
  memset(trans->body, 0, trans->body_len);
  code_detail = iotsec_msg_get_code_detail(req);
  if (code_detail == IOTSEC_MSG_GET) {
    iotsec_log_info("Starting new GET library-level blockwise transfer with "
                    "address %s and port %u",
                    trans->client_addr,
                    ntohs(trans->client_sin.IOTSEC_IPV_SIN_PORT));
    trans->type = IOTSEC_SERVER_TRANS_BLOCKWISE_GET;
    memcpy(trans->body, body, body_len);
    trans->body_end = body_len;
  } else if ((code_detail == IOTSEC_MSG_PUT) ||
             (code_detail == IOTSEC_MSG_POST)) {
    if (block_rx == NULL) {
      iotsec_server_trans_clear_blockwise(trans);
      return -EINVAL;
    }
    if (code_detail == IOTSEC_MSG_PUT) {
      iotsec_log_info("Starting new PUT library-level blockwise transfer with "
                      "address %s and port %u",
                      trans->client_addr,
                      ntohs(trans->client_sin.IOTSEC_IPV_SIN_PORT));
      trans->type = IOTSEC_SERVER_TRANS_BLOCKWISE_PUT1;
    } else {
      iotsec_log_info("Starting new POST library-level blockwise transfer with "
                      "address %s and port %u",
                      trans->client_addr,
                      ntohs(trans->client_sin.IOTSEC_IPV_SIN_PORT));
      trans->type = IOTSEC_SERVER_TRANS_BLOCKWISE_POST1;
    }
    memset(trans->body, 0, trans->body_len);
    trans->body_end = 0;
  } else {
    iotsec_log_warn("Request method unsupported in blockwise transfer with "
                    "address %s and port %u",
                    trans->client_addr,
                    ntohs(trans->client_sin.IOTSEC_IPV_SIN_PORT));
    iotsec_server_trans_clear_blockwise(trans);
    return iotsec_msg_set_code(resp, IOTSEC_MSG_SERVER_ERR,
                               IOTSEC_MSG_NOT_IMPL);
  }
  trans->block1_size = block1_size;
  trans->block2_size = block2_size;
  iotsec_msg_uri_path_to_str(req, trans->block_uri, sizeof(trans->block_uri));
  trans->block_rx = block_rx;
  return iotsec_server_trans_handle_next_block(trans, req, resp);
}

#ifdef IOTSEC_DTLS_EN

/****************************************************************************************************
 *                                         iotsec_server_dtls *
 ****************************************************************************************************/

/**
 *  @brief Initialise the DTLS members of a server structure
 *
 *  @param[out] server Pointer to a server structure
 *  @param[in] key_file_name String containing the DTLS key file name
 *  @param[in] cert_file_name String containing the DTLS certificate file name
 *  @param[in] trust_file_name String containing the DTLS trust file name
 *  @param[in] crl_file_name String containing the DTLS certificate revocation
 * list file name
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval -1 Error
 */
static int iotsec_server_dtls_create(iotsec_server_t *server,
                                     const char *key_file_name,
                                     const char *cert_file_name,
                                     const char *trust_file_name,
                                     const char *crl_file_name) {
  int ret = 0;

  ret = gnutls_global_init();
  if (ret != GNUTLS_E_SUCCESS) {
    iotsec_log_error("Failed to initialise DTLS library: %s",
                     gnutls_strerror_name(ret));
    return -1;
  }
  ret = gnutls_certificate_allocate_credentials(&server->cred);
  if (ret != GNUTLS_E_SUCCESS) {
    gnutls_global_deinit();
    iotsec_log_error("Failed to allocate DTLS credentials: %s",
                     gnutls_strerror_name(ret));
    return -1;
  }
  if ((trust_file_name != NULL) && (strlen(trust_file_name) != 0)) {
    ret = gnutls_certificate_set_x509_trust_file(server->cred, trust_file_name,
                                                 GNUTLS_X509_FMT_PEM);
    if (ret <= 0) {
      if (ret < 0)
        iotsec_log_error(
            "Failed to assign X.509 trust file to DTLS credentials: %s",
            gnutls_strerror_name(ret));
      else
        iotsec_log_error(
            "Failed to assign X.509 trust file to DTLS credentials");
      gnutls_certificate_free_credentials(server->cred);
      gnutls_global_deinit();
      return -1;
    }
  }
  if ((crl_file_name != NULL) && (strlen(crl_file_name) != 0)) {
    ret = gnutls_certificate_set_x509_crl_file(server->cred, crl_file_name,
                                               GNUTLS_X509_FMT_PEM);
    if (ret <= 0) {
      if (ret < 0)
        iotsec_log_error("Failed to assign X.509 certificate revocation list "
                         "to DTLS credentials: %s",
                         gnutls_strerror_name(ret));
      else
        iotsec_log_error("Failed to assign X.509 certificate revocation list "
                         "to DTLS credentials");
      gnutls_certificate_free_credentials(server->cred);
      gnutls_global_deinit();
      return -1;
    }
  }
  ret = gnutls_certificate_set_x509_key_file(
      server->cred, cert_file_name, key_file_name, GNUTLS_X509_FMT_PEM);
  if (ret != GNUTLS_E_SUCCESS) {
    iotsec_log_error("Failed to assign X.509 certificate file and key file to "
                     "DTLS credentials: %s",
                     gnutls_strerror_name(ret));
    gnutls_certificate_free_credentials(server->cred);
    gnutls_global_deinit();
    return -1;
  }
  ret = gnutls_dh_params_init(&server->dh_params);
  if (ret != GNUTLS_E_SUCCESS) {
    iotsec_log_error("Failed to initialise Diffie-Hellman parameters for DTLS "
                     "credentials: %s",
                     gnutls_strerror_name(ret));
    gnutls_certificate_free_credentials(server->cred);
    gnutls_global_deinit();
    return -1;
  }
  ret = gnutls_dh_params_generate2(server->dh_params,
                                   IOTSEC_SERVER_DTLS_NUM_DH_BITS);
  if (ret != GNUTLS_E_SUCCESS) {
    iotsec_log_error(
        "Failed to generate Diffie-Hellman parameters for DTLS credentials: %s",
        gnutls_strerror_name(ret));
    gnutls_dh_params_deinit(server->dh_params);
    gnutls_certificate_free_credentials(server->cred);
    gnutls_global_deinit();
    return -1;
  }
  gnutls_certificate_set_dh_params(server->cred, server->dh_params);
  ret = gnutls_priority_init(&server->priority, IOTSEC_SERVER_DTLS_PRIORITIES,
                             NULL);
  if (ret != GNUTLS_E_SUCCESS) {
    iotsec_log_error("Failed to initialise priorities for DTLS session: %s",
                     gnutls_strerror_name(ret));
    gnutls_dh_params_deinit(server->dh_params);
    gnutls_certificate_free_credentials(server->cred);
    gnutls_global_deinit();
    return -1;
  }
  return 0;
}

/**
 *  @brief Deinitialise the DTLS members of a server structure
 *
 *  @param[in,out] trans Pointer to a server structure
 */
static void iotsec_server_dtls_destroy(iotsec_server_t *server) {
  gnutls_priority_deinit(server->priority);
  gnutls_certificate_free_credentials(server->cred);
  gnutls_dh_params_deinit(server->dh_params);
  gnutls_global_deinit();
}

#endif /* IOTSEC_DTLS_EN */

#ifdef IOTSEC_DTLS_EN
int iotsec_server_create(iotsec_server_t *server,
                         iotsec_server_trans_handler_t handle, const char *host,
                         const char *port, const char *key_file_name,
                         const char *cert_file_name,
                         const char *trust_file_name, const char *crl_file_name)
#else
int iotsec_server_create(iotsec_server_t *server,
                         iotsec_server_trans_handler_t handle, const char *host,
                         const char *port)
#endif
{
  unsigned char msg_id[2] = {0};
  struct addrinfo hints = {0};
  struct addrinfo *list = NULL;
  struct addrinfo *node = NULL;
  int opt_val = 0;
  int flags = 0;
  int ret = 0;

  if ((server == NULL) || (host == NULL) || (port == NULL)) {
    return -EINVAL;
  }
  memset(server, 0, sizeof(iotsec_server_t));
  /* resolve host and port */
  hints.ai_flags = 0;
  hints.ai_family = IOTSEC_IPV_AF_INET; /* preferred socket domain */
  hints.ai_socktype = SOCK_DGRAM;       /* preferred socket type */
  hints.ai_protocol = 0; /* preferred protocol (3rd argument to socket()) - 0
                            specifies that any protocol will do */
  hints.ai_addrlen = 0;  /* must be 0 */
  hints.ai_addr = NULL;  /* must be NULL */
  hints.ai_canonname = NULL; /* must be NULL */
  hints.ai_next = NULL;      /* must be NULL */
  ret = getaddrinfo(host, port, &hints, &list);
  if (ret < 0) {
    return -EBUSY;
  }
  for (node = list; node != NULL; node = node->ai_next) {
    if ((node->ai_family == IOTSEC_IPV_AF_INET) &&
        (node->ai_socktype == SOCK_DGRAM)) {
      server->sd =
          socket(node->ai_family, node->ai_socktype, node->ai_protocol);
      if (server->sd < 0) {
        continue;
      }
      opt_val = 1;
      ret = setsockopt(server->sd, SOL_SOCKET, SO_REUSEADDR, &opt_val,
                       (socklen_t)sizeof(opt_val));
      if (ret < 0) {
        close(server->sd);
        freeaddrinfo(list);
        return -EBUSY;
      }
      ret = bind(server->sd, node->ai_addr, node->ai_addrlen);
      if (ret < 0) {
        close(server->sd);
        continue;
      }
      break;
    }
  }
  freeaddrinfo(list);
  if (node == NULL) {
    memset(server, 0, sizeof(iotsec_server_t));
    return -EBUSY;
  }
  flags = fcntl(server->sd, F_GETFL, 0);
  if (flags < 0) {
    close(server->sd);
    memset(server, 0, sizeof(iotsec_server_t));
    return -errno;
  }
  ret = fcntl(server->sd, F_SETFL, flags | O_NONBLOCK);
  if (ret < 0) {
    close(server->sd);
    memset(server, 0, sizeof(iotsec_server_t));
    return -errno;
  }
  iotsec_msg_gen_rand_str((char *)msg_id, sizeof(msg_id));
  server->msg_id = (((unsigned)msg_id[1]) << 8) | (unsigned)msg_id[0];
  iotsec_server_path_list_create(&server->sep_list);
  server->handle = handle;
#ifdef IOTSEC_DTLS_EN
  ret = iotsec_server_dtls_create(server, key_file_name, cert_file_name,
                                  trust_file_name, crl_file_name);
  if (ret < 0) {
    iotsec_server_path_list_destroy(&server->sep_list);
    close(server->sd);
    memset(server, 0, sizeof(iotsec_server_t));
    return ret;
  }
#endif
  iotsec_log_notice("Listening on address %s and port %s", host, port);
  return 0;
}

void iotsec_server_destroy(iotsec_server_t *server) {
  iotsec_server_trans_t *trans = NULL;
  unsigned i = 0;

  for (i = 0; i < IOTSEC_SERVER_NUM_TRANS; i++) {
    trans = &server->trans[i];
    if (trans->active) {
      iotsec_server_trans_destroy(trans);
    }
  }
#ifdef IOTSEC_DTLS_EN
  iotsec_server_dtls_destroy(server);
#endif
  iotsec_server_path_list_destroy(&server->sep_list);
  close(server->sd);
  memset(server, 0, sizeof(iotsec_server_t));
}

unsigned iotsec_server_get_next_msg_id(iotsec_server_t *server) {
  unsigned char msg_id[2] = {0};

  server->msg_id++;
  while (server->msg_id > IOTSEC_MSG_MAX_MSG_ID) {
    iotsec_msg_gen_rand_str((char *)msg_id, sizeof(msg_id));
    server->msg_id = (((unsigned)msg_id[1]) << 8) | (unsigned)msg_id[0];
  }
  return server->msg_id;
}

/**
 *  @brief Check that all of the options in a message are acceptable
 *
 *  For a proxy, options are acceptable if they are safe to forward or
 * recognized or both. For a server, options are acceptable if they are elective
 * or recognized or both.
 *
 *  @param[in] msg Pointer to message structure
 *
 *  @returns Operation status or bad option number
 *  @retval 0 Success
 *  @retval >0 Bad option number
 */
static unsigned iotsec_server_check_options(iotsec_msg_t *msg) {
#ifdef IOTSEC_PROXY
  return iotsec_msg_check_unsafe_ops(msg);
#else  /* !IOTSEC_PROXY */
  return iotsec_msg_check_critical_ops(msg);
#endif /* IOTSEC_PROXY */
}

/**
 *  @brief Search for a transaction structure in a server structure that matches
 * an endpoint
 *
 *  @param[in] server Pointer to a server structure
 *  @param[in] client_sin Pointer to a socket structure
 *  @param[in] client_sin_len Length of the socket structure
 *
 *  @returns Pointer to a transaction structure
 *  @retval NULL No matching transaction structure found
 */
static iotsec_server_trans_t *
iotsec_server_find_trans(iotsec_server_t *server,
                         iotsec_ipv_sockaddr_in_t *client_sin,
                         socklen_t client_sin_len) {
  iotsec_server_trans_t *trans = NULL;
  unsigned i = 0;

  for (i = 0; i < IOTSEC_SERVER_NUM_TRANS; i++) {
    trans = &server->trans[i];
    if ((trans->active) && (trans->client_sin_len == client_sin_len) &&
        (memcmp(&trans->client_sin, client_sin, client_sin_len) == 0)) {
      iotsec_log_debug("Found existing transaction at index %u", i);
      return trans;
    }
  }
  return NULL;
}

/**
 *  @brief Search for an empty transaction structure in a server structure
 *
 *  @param[in] server Pointer to a server structure
 *
 *  @returns Pointer to a transaction structure
 *  @retval NULL No empty transaction structures available
 */
static iotsec_server_trans_t *
iotsec_server_find_empty_trans(iotsec_server_t *server) {
  iotsec_server_trans_t *trans = NULL;
  unsigned i = 0;

  for (i = 0; i < IOTSEC_SERVER_NUM_TRANS; i++) {
    trans = &server->trans[i];
    if (!trans->active) {
      iotsec_log_debug("Found empty transaction at index %u", i);
      return trans;
    }
  }
  return NULL;
}

/**
 *  @brief Search for the oldest transaction structure in a server structure
 *
 *  Search for the transaction structure in a server structure that was
 *  used least recently.
 *
 *  @param[in] server Pointer to a server structure
 *
 *  @returns Pointer to a transaction structure
 */
static iotsec_server_trans_t *
iotsec_server_find_oldest_trans(iotsec_server_t *server) {
  iotsec_server_trans_t *oldest = NULL;
  iotsec_server_trans_t *trans = NULL;
  unsigned i = 0;
  unsigned j = 0;
  time_t min_last_use = 0;

  for (i = 0; i < IOTSEC_SERVER_NUM_TRANS; i++) {
    trans = &server->trans[i];
    if (trans->active) {
      if ((min_last_use == 0) || (trans->last_use < min_last_use)) {
        oldest = trans;
        min_last_use = trans->last_use;
        j = i;
      }
    }
  }
  iotsec_log_debug("Found oldest transaction at index %u", j);
  return oldest != NULL ? oldest : &server->trans[0];
}

/**
 *  @brief Wait for a message to arrive or an acknowledgement
 *         timer in any of the active transactions to expire
 *
 *  @param[in,out] server Pointer to a server structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int iotsec_server_listen(iotsec_server_t *server) {
  iotsec_server_trans_t *trans = NULL;
  unsigned i = 0;
  fd_set read_fds = {{0}};
  int max_fd = 0;
  int ret = 0;

  while (1) {
    FD_ZERO(&read_fds);
    FD_SET(server->sd, &read_fds);
    max_fd = server->sd;
    for (i = 0; i < IOTSEC_SERVER_NUM_TRANS; i++) {
      trans = &server->trans[i];
      if (trans->active) {
        FD_SET(trans->timer_fd, &read_fds);
        if (trans->timer_fd > max_fd) {
          max_fd = trans->timer_fd;
        }
      }
    }
    ret = select(max_fd + 1, &read_fds, NULL, NULL, NULL);
    if (ret < 0) {
      return -errno;
    }
    if (FD_ISSET(server->sd, &read_fds)) {
      return 0;
    }
    for (i = 0; i < IOTSEC_SERVER_NUM_TRANS; i++) {
      trans = &server->trans[i];
      if ((trans->active) && (FD_ISSET(trans->timer_fd, &read_fds))) {
        ret = iotsec_server_trans_handle_ack_timeout(trans);
        if (ret < 0) {
          return ret;
        }
      }
    }
  }
  return 0;
}

/**
 *  @brief Accept an incoming connection
 *
 *  @param[in] server Pointer to a server structure
 *  @param[out] client_sin Pointer to a socket structure
 *  @param[out] client_sin_len Length of the socket structure
 *
 *  Get the address and port number of the client.
 *  Do not read the received data.
 *
 *  @returns Number of bytes received or error code
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int iotsec_server_accept(iotsec_server_t *server,
                                iotsec_ipv_sockaddr_in_t *client_sin,
                                socklen_t *client_sin_len) {
  ssize_t num = 0;
  char buf[IOTSEC_MSG_MAX_BUF_LEN] = {0};

  *client_sin_len = sizeof(iotsec_ipv_sockaddr_in_t);
  num = recvfrom(server->sd, buf, sizeof(buf), MSG_PEEK,
                 (struct sockaddr *)client_sin, client_sin_len);
  if (num < 0) {
    return -errno;
  }
  return 0;
}

int iotsec_server_add_sep_resp_uri_path(iotsec_server_t *server,
                                        const char *str) {
  return iotsec_server_path_list_add(&server->sep_list, str);
}

/**
 *  @brief Determine whether a request warrants a piggy-backed
 *         response or a separate response
 *
 *  This function makes the decision on whether to send a separate
 *  response or a piggy-backed response by searching for the URI
 *  path taken from the request message structure in a user supplied
 *  URI path list. The idea being that some resources will consistently
 *  require time to retrieve and others will not.
 *
 *  @param[in] server Pointer to a server structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Response type
 *  @retval IOTSEC_SERVER_PIGGYBACKED Piggy-backed response
 *  @retval IOTSEC_SERVER_SEPARATE Separate response
 */
static int iotsec_server_get_resp_type(iotsec_server_t *server,
                                       iotsec_msg_t *msg) {
  char buf[IOTSEC_MSG_OP_URI_PATH_MAX_LEN] = {0};
  int match = 0;

  iotsec_msg_uri_path_to_str(msg, buf, sizeof(buf));
  match = iotsec_server_path_list_match(&server->sep_list, buf);
  return match ? IOTSEC_SERVER_SEPARATE : IOTSEC_SERVER_PIGGYBACKED;
}

/**
 *  @brief Receive a request from the client and send the response
 *
 *  @param[in,out] server Pointer to a client structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int iotsec_server_exchange(iotsec_server_t *server) {
  iotsec_ipv_sockaddr_in_t client_sin = {0};
  iotsec_server_trans_t *trans = NULL;
  iotsec_msg_t *prev_resp_msg = NULL;
  iotsec_msg_t recv_msg = {0};
  iotsec_msg_t send_msg = {0};
  socklen_t client_sin_len = 0;
  unsigned op_num = 0;
  unsigned msg_id = 0;
  ssize_t num = 0;
  int resp_type = 0;
  int ret = 0;

  /* accept incoming connection */
  ret = iotsec_server_accept(server, &client_sin, &client_sin_len);
  if (ret < 0) {
    return ret;
  }

  /* find or create transaction */
  trans = iotsec_server_find_trans(server, &client_sin, client_sin_len);
  if (trans == NULL) {
    trans = iotsec_server_find_empty_trans(server);
    if (trans == NULL) {
      trans = iotsec_server_find_oldest_trans(server);
      iotsec_server_trans_destroy(trans);
    }
    ret =
        iotsec_server_trans_create(trans, server, &client_sin, client_sin_len);
    if (ret < 0) {
      return ret;
    }
#ifdef IOTSEC_DTLS_EN
    /* if DTLS is enabled then iotsec_server_trans_create has consumed */
    /* the received data as part of the handshake, we need to wait for */
    /* more data to arrive and identify the sender */
    return 0;
#endif
  }

  /* receive message */
  iotsec_msg_create(&recv_msg);
  num = iotsec_server_trans_recv(trans, &recv_msg);
  if (num == -EAGAIN) {
    iotsec_msg_destroy(&recv_msg);
    return 0;
  }
  if (num < 0) {
    iotsec_msg_destroy(&recv_msg);
    iotsec_server_trans_destroy(trans);
    return num;
  }

  /* check for duplicate request */
  if (iotsec_server_trans_match_req(trans, &recv_msg)) {
    if (iotsec_msg_get_type(&recv_msg) == IOTSEC_MSG_CON) {
      /* message deduplication */
      iotsec_log_info(
          "Received duplicate confirmable request from address %s and port %u",
          trans->client_addr, ntohs(trans->client_sin.IOTSEC_IPV_SIN_PORT));
      resp_type = iotsec_server_get_resp_type(server, &recv_msg);
      if (resp_type == IOTSEC_SERVER_SEPARATE) {
        /* send another acknowledgement */
        ret = iotsec_server_trans_send_ack(trans, &recv_msg);
        iotsec_msg_destroy(&recv_msg);
        if (ret < 0) {
          iotsec_server_trans_destroy(trans);
          return ret;
        }
      } else {
        /* send the previous piggy-backed response */
        prev_resp_msg = iotsec_server_trans_get_resp(trans);
        num = iotsec_server_trans_send(trans, prev_resp_msg);
        iotsec_msg_destroy(&recv_msg);
        if (num < 0) {
          iotsec_server_trans_destroy(trans);
          return ret;
        }
      }
      return 0;
    } else if (iotsec_msg_get_type(&recv_msg) == IOTSEC_MSG_NON) {
      /* message deduplication */
      /* do not acknowledge the (non-confirmable) request again */
      iotsec_log_info("Received duplicate non-confirmable request from address "
                      "%s and port %u",
                      trans->client_addr,
                      ntohs(trans->client_sin.IOTSEC_IPV_SIN_PORT));
      iotsec_msg_destroy(&recv_msg);
      return 0;
    }
  }

  /* check for an ack for a previous response */
  if (iotsec_server_trans_match_resp(trans, &recv_msg)) {
    if (iotsec_msg_get_type(&recv_msg) == IOTSEC_MSG_ACK) {
      /* the server must stop retransmitting its response */
      /* on any matching acknowledgement or reset message */
      iotsec_log_info("Received acknowledgement from address %s and port %u",
                      trans->client_addr,
                      ntohs(trans->client_sin.IOTSEC_IPV_SIN_PORT));
      ret = iotsec_server_trans_stop_ack_timer(trans);
      iotsec_msg_destroy(&recv_msg);
      if (ret < 0) {
        iotsec_server_trans_destroy(trans);
        return ret;
      }
      return 0;
    } else if (iotsec_msg_get_type(&recv_msg) == IOTSEC_MSG_RST) {
      /* the server must stop retransmitting its response */
      /* on any matching acknowledgement or reset message */
      iotsec_log_info("Received reset from address %s and port %u",
                      trans->client_addr,
                      ntohs(trans->client_sin.IOTSEC_IPV_SIN_PORT));
      ret = iotsec_server_trans_stop_ack_timer(trans);
      iotsec_msg_destroy(&recv_msg);
      if (ret < 0) {
        iotsec_server_trans_destroy(trans);
        return ret;
      }
      return 0;
    }
  }

  /* check for a valid request */
  if ((iotsec_msg_get_type(&recv_msg) == IOTSEC_MSG_ACK) ||
      (iotsec_msg_get_type(&recv_msg) == IOTSEC_MSG_RST) ||
      (iotsec_msg_get_code_class(&recv_msg) != IOTSEC_MSG_REQ)) {
    iotsec_server_trans_reject(trans, &recv_msg);
    iotsec_msg_destroy(&recv_msg);
    iotsec_server_trans_destroy(trans);
    return -EBADMSG;
  }

  if (iotsec_msg_get_type(&recv_msg) == IOTSEC_MSG_CON) {
    iotsec_log_info("Received confirmable request from address %s and port %u",
                    trans->client_addr,
                    ntohs(trans->client_sin.IOTSEC_IPV_SIN_PORT));
  } else if (iotsec_msg_get_type(&recv_msg) == IOTSEC_MSG_NON) {
    iotsec_log_info(
        "Received non-confirmable request from address %s and port %u",
        trans->client_addr, ntohs(trans->client_sin.IOTSEC_IPV_SIN_PORT));
  }

  /* clear details of the previous request/response */
  iotsec_server_trans_clear_req(trans);
  iotsec_server_trans_clear_resp(trans);

  /* determine response type */
  if (iotsec_msg_get_type(&recv_msg) == IOTSEC_MSG_CON) {
    resp_type = iotsec_server_get_resp_type(server, &recv_msg);
    if (resp_type == IOTSEC_SERVER_SEPARATE) {
      iotsec_log_info("Request URI path requires a separate response to "
                      "address %s and port %u",
                      trans->client_addr,
                      ntohs(trans->client_sin.IOTSEC_IPV_SIN_PORT));
    } else {
      iotsec_log_info("Request URI path requires a piggy-backed response to "
                      "address %s and port %u",
                      trans->client_addr,
                      ntohs(trans->client_sin.IOTSEC_IPV_SIN_PORT));
    }
  }

  /* send an acknowledgement if necessary */
  if ((iotsec_msg_get_type(&recv_msg) == IOTSEC_MSG_CON) &&
      (resp_type == IOTSEC_SERVER_SEPARATE)) {
    ret = iotsec_server_trans_send_ack(trans, &recv_msg);
    if (ret < 0) {
      iotsec_server_trans_destroy(trans);
      iotsec_msg_destroy(&recv_msg);
      return ret;
    }
  }

  /* generate response */
  iotsec_log_info("Responding to address %s and port %u", trans->client_addr,
                  ntohs(trans->client_sin.IOTSEC_IPV_SIN_PORT));
  iotsec_msg_create(&send_msg);
  /* check options */
  op_num = iotsec_server_check_options(&recv_msg);
  if (op_num != 0) {
    ret = iotsec_server_trans_handle_bad_option(trans, &send_msg, op_num);
  } else if (iotsec_server_trans_get_type(trans) !=
             IOTSEC_SERVER_TRANS_REGULAR) {
    ret = iotsec_server_trans_handle_next_block(trans, &recv_msg, &send_msg);
  } else {
    ret = (*server->handle)(trans, &recv_msg, &send_msg);
  }
  if (ret < 0) {
    iotsec_msg_destroy(&send_msg);
    iotsec_server_trans_destroy(trans);
    iotsec_msg_destroy(&recv_msg);
    return ret;
  }
  if ((iotsec_msg_get_type(&recv_msg) == IOTSEC_MSG_CON) &&
      (resp_type == IOTSEC_SERVER_PIGGYBACKED)) {
    /* copy the message ID from the request to the response */
    msg_id = iotsec_msg_get_msg_id(&recv_msg);
  } else {
    /* generate a new message ID */
    msg_id = iotsec_server_get_next_msg_id(server);
  }
  ret = iotsec_msg_set_msg_id(&send_msg, msg_id);
  if (ret < 0) {
    iotsec_msg_destroy(&send_msg);
    iotsec_server_trans_destroy(trans);
    iotsec_msg_destroy(&recv_msg);
    return ret;
  }
  /* copy the token from the request to the response */
  ret = iotsec_msg_set_token(&send_msg, iotsec_msg_get_token(&recv_msg),
                             iotsec_msg_get_token_len(&recv_msg));
  if (ret < 0) {
    iotsec_msg_destroy(&send_msg);
    iotsec_server_trans_destroy(trans);
    iotsec_msg_destroy(&recv_msg);
    return ret;
  }
  /* set the response type */
  /* we have already verified that the received message */
  /* is either a confirmable or a non-confirmable request */
  if (iotsec_msg_get_type(&recv_msg) == IOTSEC_MSG_CON) {
    if (resp_type == IOTSEC_SERVER_PIGGYBACKED)
      ret = iotsec_msg_set_type(&send_msg, IOTSEC_MSG_ACK);
    else
      ret = iotsec_msg_set_type(&send_msg, IOTSEC_MSG_CON);
  } else {
    ret = iotsec_msg_set_type(&send_msg, IOTSEC_MSG_NON);
  }
  if (ret < 0) {
    iotsec_msg_destroy(&send_msg);
    iotsec_server_trans_destroy(trans);
    iotsec_msg_destroy(&recv_msg);
    return ret;
  }

  /* send response */
  num = iotsec_server_trans_send(trans, &send_msg);
  if (num < 0) {
    iotsec_msg_destroy(&send_msg);
    iotsec_server_trans_destroy(trans);
    iotsec_msg_destroy(&recv_msg);
    return num;
  }

  /* record the request in the transaction structure */
  ret = iotsec_server_trans_set_req(trans, &recv_msg);
  if (ret < 0) {
    iotsec_msg_destroy(&send_msg);
    iotsec_server_trans_destroy(trans);
    iotsec_msg_destroy(&recv_msg);
    return ret;
  }

  /* record the response in the transaction structure */
  ret = iotsec_server_trans_set_resp(trans, &send_msg);
  if (ret < 0) {
    iotsec_msg_destroy(&send_msg);
    iotsec_server_trans_destroy(trans);
    iotsec_msg_destroy(&recv_msg);
    return ret;
  }

  /* start the acknowledgement timer if an acknowledgement is expected */
  if (iotsec_msg_get_type(&send_msg) == IOTSEC_MSG_CON) {
    iotsec_log_info("Expecting acknowledgement from address %s and port %u",
                    trans->client_addr,
                    ntohs(trans->client_sin.IOTSEC_IPV_SIN_PORT));
    ret = iotsec_server_trans_start_ack_timer(trans);
    if (ret < 0) {
      iotsec_msg_destroy(&send_msg);
      iotsec_server_trans_destroy(trans);
      iotsec_msg_destroy(&recv_msg);
      return ret;
    }
  }

  iotsec_msg_destroy(&send_msg);
  iotsec_msg_destroy(&recv_msg);
  return 0;
}

int iotsec_server_run(iotsec_server_t *server) {
  int ret = 0;

  while (1) {
    ret = iotsec_server_listen(server);
    if (ret < 0) {
      return ret;
    }
    ret = iotsec_server_exchange(server);
    if (ret < 0) {
      if ((ret == -ETIMEDOUT) || (ret == -ECONNRESET)) {
        iotsec_log_info("%s", strerror(-ret));
      } else if (ret != -1) /* a return value of -1 indicates a DTLS error */
      {
        iotsec_log_error("%s", strerror(-ret));
      }
    }
  }
  return 0;
}
