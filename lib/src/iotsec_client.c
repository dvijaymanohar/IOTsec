/**
 *  @file iotsec_client.c
 *
 *  @brief Source file for the IOTsec client library
 */

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
#include <unistd.h>
#ifdef IOTSEC_DTLS_EN
#include <gnutls/x509.h>
#endif
#include "iotsec_client.h"
#include "iotsec_log.h"
#include "iotsec_mem.h"

#define IOTSEC_CLIENT_ACK_TIMEOUT_SEC                                          \
  2 /**< Minimum delay to wait before retransmitting a confirmable message */
#define IOTSEC_CLIENT_MAX_RETRANSMIT                                           \
  4 /**< Maximum number of times a confirmable message can be retransmitted */
#define IOTSEC_CLIENT_RESP_TIMEOUT_SEC                                         \
  30 /**< Maximum amount of time to wait for a response */

#ifdef IOTSEC_DTLS_EN

#define IOTSEC_CLIENT_DTLS_MTU                                                 \
  IOTSEC_MSG_MAX_BUF_LEN /**< Maximum transmission unit excluding the UDP and  \
                            IPv6 headers */
#define IOTSEC_CLIENT_DTLS_RETRANS_TIMEOUT                                     \
  1000 /**< Retransmission timeout (msec) for the DTLS handshake */
#define IOTSEC_CLIENT_DTLS_TOTAL_TIMEOUT                                       \
  60000 /**< Total timeout (msec) for the DTLS handshake */
#define IOTSEC_CLIENT_DTLS_HANDSHAKE_ATTEMPTS                                  \
  60 /**< Maximum number of DTLS handshake attempts */
#define IOTSEC_CLIENT_DTLS_PRIORITIES                                          \
  "PERFORMANCE:-VERS-TLS-ALL:+VERS-DTLS1.0:%SERVER_PRECEDENCE"
/**< DTLS priorities */
#endif

static int rand_init = 0; /**< Indicates whether or not the random number
                             generator has been initialised */

#ifdef IOTSEC_DTLS_EN

/**
 *  @brief Listen for a packet from the server with a timeout
 *
 *  @param[in] client Pointer to a client structure
 *  @param[in] ms Timeout value in msec
 *
 *  @returns Operation status
 *  @retval 1 Success
 *  @retval 0 Timeout
 *  @retval <0 Error
 */
static int iotsec_client_dtls_listen_timeout(iotsec_client_t *client,
                                             unsigned ms) {
  struct timeval tv = {0};
  fd_set read_fds = {{0}};
  int ret = 0;

  tv.tv_sec = ms / 1000;
  tv.tv_usec = (ms % 1000) * 1000;
  while (1) {
    FD_ZERO(&read_fds);
    FD_SET(client->sd, &read_fds);
    ret = select(client->sd + 1, &read_fds, NULL, NULL, &tv);
    if (ret < 0) {
      return -errno;
    }
    if (ret == 0) {
      return 0; /* timeout */
    }
    if (FD_ISSET(client->sd, &read_fds)) {
      return 1; /* success */
    }
  }
}

/**
 *  @brief Receive data from the server
 *
 *  This is a call-back function that the
 *  GnuTLS library uses to receive data.
 *  To report an error, it sets errno and
 *  returns -1.
 *
 *  @param[in,out] data Pointer to a client structure
 *  @param[out] buf Pointer to a buffer
 *  @param[in] len Length of the buffer
 *
 *  @returns Number of bytes received or error
 *  @retval >0 Number of bytes received
 *  @retval -1 Error
 */
static ssize_t iotsec_client_dtls_pull_func(gnutls_transport_ptr_t data,
                                            void *buf, size_t len) {
  iotsec_client_t *client = NULL;
  ssize_t num = 0;

  client = (iotsec_client_t *)data;
  num = recv(client->sd, buf, len, 0);
  if (num >= 0) {
    iotsec_log_debug("pulled %zd bytes", num);
  }
  return num;
}

/**
 *  @brief Wait for receive data from the server
 *
 *  This is a call-back function that the GnuTLS
 *  library uses to wait for receive data. To
 *  report an error, it sets errno and returns -1.
 *
 *  @param[in] data Pointer to a client structure
 *  @param[in] ms Timeout in msec
 *
 *  @returns Number of bytes received or error
 *  @retval >0 Number of bytes received
 *  @retval 0 Timeout
 *  @retval -1 Error
 */
static int iotsec_client_dtls_pull_timeout_func(gnutls_transport_ptr_t data,
                                                unsigned ms) {
  iotsec_client_t *client = NULL;
  char buf[IOTSEC_CLIENT_DTLS_MTU] = {0};
  int ret = 0;

  client = (iotsec_client_t *)data;
  ret = iotsec_client_dtls_listen_timeout(client, ms);
  if (ret == 0) {
    return 0; /* timeout */
  }
  if (ret < 0) {
    /* errno has been set by iotsec_client_dtls_listen_timeout */
    return -1;
  }
  return recv(client->sd, buf, sizeof(buf), MSG_PEEK);
}

/**
 *  @brief Send data to the server
 *
 *  This is a call-back function that the
 *  GnuTLS library uses to send data. To
 *  report an error, it sets errno and
 *  returns -1.
 *
 *  @param[in] data Pointer to a client structure
 *  @param[in] buf Pointer to a buffer
 *  @param[in] len Length of the buffer
 *
 *  @returns Number of bytes sent or error
 *  @retval >0 Number of bytes sent
 *  @retval -1 Error
 */
static ssize_t iotsec_client_dtls_push_func(gnutls_transport_ptr_t data,
                                            const void *buf, size_t len) {
  iotsec_client_t *client = NULL;
  ssize_t num = 0;

  client = (iotsec_client_t *)data;
  num = sendto(client->sd, buf, len, 0, (struct sockaddr *)&client->server_sin,
               client->server_sin_len);
  if (num >= 0) {
    iotsec_log_debug("pushed %zd bytes", num);
  }
  return num;
}

/**
 *  @brief Perform a DTLS handshake with the server
 *
 *  @param[in,out] client Pointer to a client structure
 *
 *  @returns Operation success
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int iotsec_client_dtls_handshake(iotsec_client_t *client) {
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
  for (i = 0; i < IOTSEC_CLIENT_DTLS_HANDSHAKE_ATTEMPTS; i++) {
    errno = 0;
    ret = gnutls_handshake(client->session);
    iotsec_log_debug("DTLS handshake result: %s", gnutls_strerror_name(ret));
    if ((errno != 0) && (errno != EAGAIN)) {
      return -errno;
    }
    if (ret == GNUTLS_E_SUCCESS) {
      iotsec_log_info("Completed DTLS handshake");
      /* determine which cipher suite was negotiated */
      kx = gnutls_kx_get(client->session);
      cipher = gnutls_cipher_get(client->session);
      mac = gnutls_mac_get(client->session);
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
      alert = gnutls_alert_get(client->session);
      alert_name = gnutls_alert_get_name(alert);
      if (ret == GNUTLS_E_FATAL_ALERT_RECEIVED)
        iotsec_log_error("Received DTLS alert from the server: %s", alert_name);
      else
        iotsec_log_warn("Received DTLS alert from the server: %s", alert_name);
      return -ECONNRESET;
    }
    if (ret != GNUTLS_E_AGAIN) {
      iotsec_log_error("Failed to complete DTLS handshake: %s",
                       gnutls_strerror_name(ret));
      return -1;
    }
    if (i < IOTSEC_CLIENT_DTLS_HANDSHAKE_ATTEMPTS - 1) {
      timeout = gnutls_dtls_get_timeout(client->session);
      iotsec_log_debug("Handshake timeout: %u msec", timeout);
      ret = iotsec_client_dtls_listen_timeout(client, timeout);
      if (ret < 0) {
        return ret;
      }
    }
  }
  return -ETIMEDOUT;
}

/**
 *  @brief Verify the server's certificate
 *
 *  @param[in] client Pointer to a client structure
 *  @param[in] common_name String containing the common name for the server
 *
 *  @returns Operation success
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int iotsec_client_dtls_verify_peer_cert(iotsec_client_t *client,
                                               const char *common_name) {
  gnutls_certificate_type_t cert_type = 0;
  const gnutls_datum_t *cert_list = NULL;
  gnutls_x509_crt_t cert = {0};
  unsigned cert_list_size = 0;
  unsigned status = 0;
  time_t expiration_time = 0;
  time_t activation_time = 0;
  time_t current_time = 0;
  int ret = 0;

  ret = gnutls_certificate_verify_peers2(client->session, &status);
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
  cert_type = gnutls_certificate_type_get(client->session);
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
  cert_list = gnutls_certificate_get_peers(client->session, &cert_list_size);
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
  if (common_name != NULL) {
    ret = gnutls_x509_crt_check_hostname(cert, common_name);
    if (ret == 0) {
      iotsec_log_error("The peer certificate's owner does not match: '%s'",
                       common_name);
      gnutls_x509_crt_deinit(cert);
      return -1;
    }
  }
  iotsec_log_info("Peer certificate validated");
  gnutls_x509_crt_deinit(cert);
  return 0;
}

/**
 *  @brief Initialise the DTLS members of a client structure
 *
 *  @param[out] client Pointer to a client structure
 *  @param[in] key_file_name String containing the DTLS key file name
 *  @param[in] cert_file_name String containing the DTLS certificate file name
 *  @param[in] trust_file_name String containing the DTLS trust file name
 *  @param[in] crls_file_name String containing the DTLS certificate revocation
 * list file name
 *  @param[in] common_name String containing the common name of the server
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int iotsec_client_dtls_create(iotsec_client_t *client,
                                     const char *key_file_name,
                                     const char *cert_file_name,
                                     const char *trust_file_name,
                                     const char *crl_file_name,
                                     const char *common_name) {
  int ret = 0;

  ret = gnutls_global_init();
  if (ret != GNUTLS_E_SUCCESS) {
    iotsec_log_error("Failed to initialise DTLS library: %s",
                     gnutls_strerror_name(ret));
    return -1;
  }
  ret = gnutls_certificate_allocate_credentials(&client->cred);
  if (ret != GNUTLS_E_SUCCESS) {
    iotsec_log_error("Failed to allocate DTLS credentials: %s",
                     gnutls_strerror_name(ret));
    gnutls_global_deinit();
    return -1;
  }
  if ((trust_file_name != NULL) && (strlen(trust_file_name) != 0)) {
    ret = gnutls_certificate_set_x509_trust_file(client->cred, trust_file_name,
                                                 GNUTLS_X509_FMT_PEM);
    if (ret <= 0) {
      if (ret < 0)
        iotsec_log_error(
            "Failed to assign X.509 trust file to DTLS credentials: %s",
            gnutls_strerror_name(ret));
      else
        iotsec_log_error(
            "Failed to assign X.509 trust file to DTLS credentials");
      gnutls_certificate_free_credentials(client->cred);
      gnutls_global_deinit();
      return -1;
    }
  }
  if ((crl_file_name != NULL) && (strlen(crl_file_name) != 0)) {
    ret = gnutls_certificate_set_x509_crl_file(client->cred, crl_file_name,
                                               GNUTLS_X509_FMT_PEM);
    if (ret <= 0) {
      if (ret < 0)
        iotsec_log_error("Failed to assign X.509 certificate revocation list "
                         "to DTLS credentials: %s",
                         gnutls_strerror_name(ret));
      else
        iotsec_log_error("Failed to assign X.509 certificate revocation list "
                         "to DTLS credentials");
      gnutls_certificate_free_credentials(client->cred);
      gnutls_global_deinit();
      return -1;
    }
  }
  ret = gnutls_certificate_set_x509_key_file(
      client->cred, cert_file_name, key_file_name, GNUTLS_X509_FMT_PEM);
  if (ret != GNUTLS_E_SUCCESS) {
    iotsec_log_error("Failed to assign X.509 certificate file and key file to "
                     "DTLS credentials: %s",
                     gnutls_strerror_name(ret));
    gnutls_certificate_free_credentials(client->cred);
    gnutls_global_deinit();
    return -1;
  }
  ret = gnutls_priority_init(&client->priority, IOTSEC_CLIENT_DTLS_PRIORITIES,
                             NULL);
  if (ret != GNUTLS_E_SUCCESS) {
    iotsec_log_error("Failed to initialise priorities for DTLS session: %s",
                     gnutls_strerror_name(ret));
    gnutls_certificate_free_credentials(client->cred);
    gnutls_global_deinit();
    return -1;
  }
  ret = gnutls_init(&client->session,
                    GNUTLS_CLIENT | GNUTLS_DATAGRAM | GNUTLS_NONBLOCK);
  if (ret != GNUTLS_E_SUCCESS) {
    iotsec_log_error("Failed to initialise DTLS session: %s",
                     gnutls_strerror_name(ret));
    gnutls_priority_deinit(client->priority);
    gnutls_certificate_free_credentials(client->cred);
    gnutls_global_deinit();
    return -1;
  }
  ret = gnutls_credentials_set(client->session, GNUTLS_CRD_CERTIFICATE,
                               client->cred);
  if (ret != GNUTLS_E_SUCCESS) {
    iotsec_log_error("Failed to assign credentials to DTLS session: %s",
                     gnutls_strerror_name(ret));
    gnutls_deinit(client->session);
    gnutls_priority_deinit(client->priority);
    gnutls_certificate_free_credentials(client->cred);
    gnutls_global_deinit();
    return -1;
  }
  ret = gnutls_priority_set(client->session, client->priority);
  if (ret != GNUTLS_E_SUCCESS) {
    iotsec_log_error("Failed to assign priorities to DTLS session: %s",
                     gnutls_strerror_name(ret));
    gnutls_deinit(client->session);
    gnutls_priority_deinit(client->priority);
    gnutls_certificate_free_credentials(client->cred);
    gnutls_global_deinit();
    return -1;
  }
  gnutls_transport_set_ptr(client->session, client);
  gnutls_transport_set_pull_function(client->session,
                                     iotsec_client_dtls_pull_func);
  gnutls_transport_set_pull_timeout_function(
      client->session, iotsec_client_dtls_pull_timeout_func);
  gnutls_transport_set_push_function(client->session,
                                     iotsec_client_dtls_push_func);
  gnutls_dtls_set_mtu(client->session, IOTSEC_CLIENT_DTLS_MTU);
  gnutls_dtls_set_timeouts(client->session, IOTSEC_CLIENT_DTLS_RETRANS_TIMEOUT,
                           IOTSEC_CLIENT_DTLS_TOTAL_TIMEOUT);
  ret = iotsec_client_dtls_handshake(client);
  if (ret < 0) {
    gnutls_deinit(client->session);
    gnutls_priority_deinit(client->priority);
    gnutls_certificate_free_credentials(client->cred);
    gnutls_global_deinit();
    return ret;
  }
  ret = iotsec_client_dtls_verify_peer_cert(client, common_name);
  if (ret < 0) {
    gnutls_deinit(client->session);
    gnutls_priority_deinit(client->priority);
    gnutls_certificate_free_credentials(client->cred);
    gnutls_global_deinit();
    return ret;
  }
  return 0;
}

/**
 *  @brief Deinitialise a client structure
 *
 *  @param[in,out] client Pointer to a client structure
 */
static void iotsec_client_dtls_destroy(iotsec_client_t *client) {
  gnutls_bye(client->session, GNUTLS_SHUT_WR);
  gnutls_deinit(client->session);
  gnutls_priority_deinit(client->priority);
  gnutls_certificate_free_credentials(client->cred);
  gnutls_global_deinit();
}

#endif /* IOTSEC_DTLS_EN */

#ifdef IOTSEC_DTLS_EN
int iotsec_client_create(iotsec_client_t *client, const char *host,
                         const char *port, const char *key_file_name,
                         const char *cert_file_name,
                         const char *trust_file_name, const char *crl_file_name,
                         const char *common_name)
#else
int iotsec_client_create(iotsec_client_t *client, const char *host,
                         const char *port)
#endif
{
  struct addrinfo hints = {0};
  struct addrinfo *list = NULL;
  struct addrinfo *node = NULL;
  int flags = 0;
  int ret = 0;

  if ((client == NULL) || (host == NULL) || (port == NULL)) {
    return -EINVAL;
  }
  memset(client, 0, sizeof(iotsec_client_t));
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
      client->sd =
          socket(node->ai_family, node->ai_socktype, node->ai_protocol);
      if (client->sd < 0) {
        continue;
      }
      ret = connect(client->sd, node->ai_addr, node->ai_addrlen);
      if (ret < 0) {
        close(client->sd);
        continue;
      }
      memcpy(&client->server_sin, node->ai_addr, node->ai_addrlen);
      client->server_sin_len = node->ai_addrlen;
      break;
    }
  }
  freeaddrinfo(list);
  if (node == NULL) {
    memset(client, 0, sizeof(iotsec_client_t));
    return -EBUSY;
  }
  flags = fcntl(client->sd, F_GETFL, 0);
  if (flags < 0) {
    close(client->sd);
    memset(client, 0, sizeof(iotsec_client_t));
    return -errno;
  }
  ret = fcntl(client->sd, F_SETFL, flags | O_NONBLOCK);
  if (ret < 0) {
    close(client->sd);
    memset(client, 0, sizeof(iotsec_client_t));
    return -errno;
  }
  strncpy(client->server_host, host, sizeof(client->server_host) - 1);
  strncpy(client->server_port, port, sizeof(client->server_port) - 1);
  client->timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
  if (client->timer_fd < 0) {
    close(client->sd);
    memset(client, 0, sizeof(iotsec_client_t));
    return -errno;
  }
#ifdef IOTSEC_DTLS_EN
  ret = iotsec_client_dtls_create(client, key_file_name, cert_file_name,
                                  trust_file_name, crl_file_name, common_name);
  if (ret < 0) {
    close(client->timer_fd);
    close(client->sd);
    memset(client, 0, sizeof(iotsec_client_t));
    return ret;
  }
#endif
  iotsec_log_notice("Connected to host %s and port %s", client->server_host,
                    client->server_port);
  return 0;
}

void iotsec_client_destroy(iotsec_client_t *client) {
#ifdef IOTSEC_DTLS_EN
  iotsec_client_dtls_destroy(client);
#endif
  close(client->timer_fd);
  close(client->sd);
  memset(client, 0, sizeof(iotsec_client_t));
}

/**
 *  @brief Initialise the acknowledgement timer in a client structure
 *
 *  The timer is initialised to a random duration between:
 *
 *  ACK_TIMEOUT and (ACK_TIMEOUT * ACK_RANDOM_FACTOR)
 *  where:
 *  ACK_TIMEOUT = 2
 *  ACK_RANDOM_FACTOR = 1.5
 *
 *  @param[out] client Pointer to a client structure
 */
static void iotsec_client_init_ack_timeout(iotsec_client_t *client) {
  if (!rand_init) {
    srand(time(NULL));
    rand_init = 1;
  }
  client->timeout.tv_sec = IOTSEC_CLIENT_ACK_TIMEOUT_SEC;
  client->timeout.tv_nsec = (rand() % 1000) * 1000000;
  iotsec_log_debug("Acknowledgement timeout initialised to: %lu sec, %lu nsec",
                   client->timeout.tv_sec, client->timeout.tv_nsec);
}

/**
 *  @brief Initialise the response timer in a client structure
 *
 *  The timer is initialised to a constant value.
 *
 *  @param[out] client Pointer to a client structure
 */
static void iotsec_client_init_resp_timeout(iotsec_client_t *client) {
  client->timeout.tv_sec = IOTSEC_CLIENT_RESP_TIMEOUT_SEC;
  client->timeout.tv_nsec = 0;
  iotsec_log_debug("Response timeout initialised to: %lu sec, %lu nsec",
                   client->timeout.tv_sec, client->timeout.tv_nsec);
}

/**
 *  @brief Double the value of the timer in a client structure
 *
 *  @param[in,out] client Pointer to a client structure
 */
static void iotsec_client_double_timeout(iotsec_client_t *client) {
  unsigned msec = 2 * ((client->timeout.tv_sec * 1000) +
                       (client->timeout.tv_nsec / 1000000));
  client->timeout.tv_sec = msec / 1000;
  client->timeout.tv_nsec = (msec % 1000) * 1000000;
  iotsec_log_debug("Timeout doubled to: %lu sec, %lu nsec",
                   client->timeout.tv_sec, client->timeout.tv_nsec);
}

/**
 *  @brief Start the timer in a client structure
 *
 *  @param[in,out] client Pointer to a client structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int iotsec_client_start_timer(iotsec_client_t *client) {
  struct itimerspec its = {{0}};
  int ret = 0;

  its.it_value = client->timeout;
  ret = timerfd_settime(client->timer_fd, 0, &its, NULL);
  if (ret < 0) {
    return -errno;
  }
  return 0;
}

/**
 *  @brief Initialise and start the acknowledgement timer in a client structure
 *
 *  @param[out] client Pointer to a client structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int iotsec_client_start_ack_timer(iotsec_client_t *client) {
  client->num_retrans = 0;
  iotsec_client_init_ack_timeout(client);
  return iotsec_client_start_timer(client);
}

/**
 *  @brief Update the acknowledgement timer in a client structure
 *
 *  Increase and restart the acknowledgement timer in a client structure
 *  and indicate if the maximum number of retransmits has been reached.
 *
 *  @param[in,out] client Pointer to a client structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int iotsec_client_update_ack_timer(iotsec_client_t *client) {
  int ret = 0;

  if (client->num_retrans >= IOTSEC_CLIENT_MAX_RETRANSMIT) {
    return -ETIMEDOUT;
  }
  iotsec_client_double_timeout(client);
  ret = iotsec_client_start_timer(client);
  if (ret < 0) {
    return ret;
  }
  client->num_retrans++;
  return 0;
}

/**
 *  @brief Initialise and start the response timer in a client structure
 *
 *  @param[out] client Pointer to a client structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int iotsec_client_start_resp_timer(iotsec_client_t *client) {
  iotsec_client_init_resp_timeout(client);
  return iotsec_client_start_timer(client);
}

/**
 *  @brief Send a message to the server
 *
 *  @param[in,out] client Pointer to a client structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Number of bytes sent or error code
 *  @retval >0 Number of bytes sent
 *  @retval <0 Error
 */
static ssize_t iotsec_client_send(iotsec_client_t *client, iotsec_msg_t *msg) {
  ssize_t num = 0;
  char buf[IOTSEC_MSG_MAX_BUF_LEN] = {0};

  num = iotsec_msg_format(msg, buf, sizeof(buf));
  if (num < 0) {
    return num;
  }
#ifdef IOTSEC_DTLS_EN
  errno = 0;
  num = gnutls_record_send(client->session, buf, num);
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
    iotsec_log_error("Failed to send to server: %s", gnutls_strerror_name(num));
    return -1;
  }
#else
  num = send(client->sd, buf, num, 0);
  if (num < 0) {
    return -errno;
  }
#endif
  iotsec_log_debug("Sent to host %s and port %s", client->server_host,
                   client->server_port);
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
 *  @param[in,out] client Pointer to a client structure
 *  @param[in] buf Buffer containing the message
 *  @param[in] len length of the buffer
 */
static void iotsec_client_handle_format_error(iotsec_client_t *client,
                                              char *buf, size_t len) {
  iotsec_msg_t msg = {0};
  unsigned msg_id = 0;
  unsigned type = 0;
  int ret = 0;

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
    iotsec_client_send(client, &msg);
    iotsec_msg_destroy(&msg);
  }
}

/**
 *  @brief Receive a message from the server
 *
 *  @param[in,out] client Pointer to a client structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Number of bytes received or error code
 *  @retval >0 Number of bytes received
 *  @retval <0 Error
 */
static ssize_t iotsec_client_recv(iotsec_client_t *client, iotsec_msg_t *msg) {
#ifdef IOTSEC_DTLS_EN
  gnutls_alert_description_t alert = 0;
  const char *alert_name = NULL;
#endif
  ssize_t num = 0;
  ssize_t ret = 0;
  char buf[IOTSEC_MSG_MAX_BUF_LEN] = {0};

#ifdef IOTSEC_DTLS_EN
  errno = 0;
  num = gnutls_record_recv(client->session, buf, sizeof(buf));
  if (errno != 0) {
    return -errno;
  }
  if ((num == GNUTLS_E_FATAL_ALERT_RECEIVED) ||
      (num == GNUTLS_E_WARNING_ALERT_RECEIVED) || (num == 0)) {
    alert = gnutls_alert_get(client->session);
    alert_name = gnutls_alert_get_name(alert);
    if (num == GNUTLS_E_FATAL_ALERT_RECEIVED)
      iotsec_log_error("Received DTLS alert from the server: %s", alert_name);
    else if (num == GNUTLS_E_WARNING_ALERT_RECEIVED)
      iotsec_log_warn("Received DTLS alert from the server: %s", alert_name);
    else
      iotsec_log_info("Received DTLS alert from the server: %s", alert_name);
    return -ECONNRESET;
  }
  if (num == GNUTLS_E_AGAIN) {
    return -EAGAIN;
  }
  if (num < 0) {
    iotsec_log_error("Failed to receive from server: %s",
                     gnutls_strerror_name(num));
    return -1;
  }
#else
  num = recv(client->sd, buf, sizeof(buf), 0);
  if (num < 0) {
    return -errno;
  }
#endif
  ret = iotsec_msg_parse(msg, buf, num);
  if (ret < 0) {
    if (ret == -EBADMSG) {
      iotsec_client_handle_format_error(client, buf, num);
    }
    return ret;
  }
  iotsec_log_debug("Received from host %s and port %s", client->server_host,
                   client->server_port);
  return num;
}

/**
 *  @brief Reject a received confirmable message
 *
 *  Send a reset message to the server.
 *
 *  @param[in,out] client Pointer to a client structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int iotsec_client_reject_con(iotsec_client_t *client,
                                    iotsec_msg_t *msg) {
  iotsec_msg_t rej = {0};
  int num = 0;
  int ret = 0;

  iotsec_log_info("Rejecting confirmable message from host %s and port %s",
                  client->server_host, client->server_port);
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
  num = iotsec_client_send(client, &rej);
  iotsec_msg_destroy(&rej);
  if (num < 0) {
    return num;
  }
  return 0;
}

/**
 *  @brief Reject a received non-confirmable message
 *
 *  @param[in] client Pointer to a client structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 */
static int iotsec_client_reject_non(iotsec_client_t *client,
                                    iotsec_msg_t *msg) {
  iotsec_log_info("Rejecting non-confirmable message from host %s and port %s",
                  client->server_host, client->server_port);
  return 0;
}

/**
 *  @brief Reject a received acknowledgement message
 *
 *  @param[in] client Pointer to a client structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 */
static int iotsec_client_reject_ack(iotsec_client_t *client,
                                    iotsec_msg_t *msg) {
  iotsec_log_info("Rejecting acknowledgement message from host %s and port %s",
                  client->server_host, client->server_port);
  return 0;
}

/**
 *  @brief Reject a received reset message
 *
 *  @param[in] client Pointer to a client structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 */
static int iotsec_client_reject_reset(iotsec_client_t *client,
                                      iotsec_msg_t *msg) {
  iotsec_log_info("Rejecting reset message from host %s and port %s",
                  client->server_host, client->server_port);
  return 0;
}

/**
 *  @brief Reject a received message
 *
 *  @param[in,out] client Pointer to a client structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int iotsec_client_reject(iotsec_client_t *client, iotsec_msg_t *msg) {
  if (iotsec_msg_get_type(msg) == IOTSEC_MSG_CON) {
    return iotsec_client_reject_con(client, msg);
  } else if (iotsec_msg_get_type(msg) == IOTSEC_MSG_NON) {
    return iotsec_client_reject_non(client, msg);
  } else if (iotsec_msg_get_type(msg) == IOTSEC_MSG_ACK) {
    return iotsec_client_reject_ack(client, msg);
  } else if (iotsec_msg_get_type(msg) == IOTSEC_MSG_RST) {
    return iotsec_client_reject_reset(client, msg);
  }
  return 0; /* should never arrive here */
}

/**
 *  @brief Send an acknowledgement message to the server
 *
 *  @param[in,out] client Pointer to a client structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int iotsec_client_send_ack(iotsec_client_t *client, iotsec_msg_t *msg) {
  iotsec_msg_t ack = {0};
  int num = 0;
  int ret = 0;

  iotsec_log_info("Acknowledging confirmable message from host %s and port %s",
                  client->server_host, client->server_port);
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
  num = iotsec_client_send(client, &ack);
  iotsec_msg_destroy(&ack);
  if (num < 0) {
    return num;
  }
  return 0;
}

/**
 *  @brief Handle an acknowledgement timeout
 *
 *  Update the acknowledgement timer in the client structure
 *  and if the maximum number of retransmits has not been
 *  reached then retransmit the last request to the server.
 *
 *  @param[in,out] client Pointer to a client structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int iotsec_client_handle_ack_timeout(iotsec_client_t *client,
                                            iotsec_msg_t *msg) {
  ssize_t num = 0;
  int ret = 0;

  iotsec_log_debug("Transaction expired for host %s and port %s",
                   client->server_host, client->server_port);
  ret = iotsec_client_update_ack_timer(client);
  if (ret == 0) {
    iotsec_log_debug("Retransmitting to host %s and port %s",
                     client->server_host, client->server_port);
    num = iotsec_client_send(client, msg);
    if (num < 0) {
      return num;
    }
  } else if (ret == -ETIMEDOUT) {
    iotsec_log_debug("Stopped retransmitting to host %s and port %s",
                     client->server_host, client->server_port);
    iotsec_log_info("No acknowledgement received from host %s and port %s",
                    client->server_host, client->server_port);
  }
  return ret;
}

/**
 *  @brief Wait for a message to arrive or the acknowledgement timer to expire
 *
 *  @param[in,out] client Pointer to a client structure
 *  @param[in] msg Pointer to a message structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int iotsec_client_listen_ack(iotsec_client_t *client,
                                    iotsec_msg_t *msg) {
  fd_set read_fds = {{0}};
  int max_fd = 0;
  int ret = 0;

  while (1) {
    FD_ZERO(&read_fds);
    FD_SET(client->sd, &read_fds);
    FD_SET(client->timer_fd, &read_fds);
    max_fd = client->sd;
    if (client->timer_fd > max_fd) {
      max_fd = client->timer_fd;
    }
    ret = select(max_fd + 1, &read_fds, NULL, NULL, NULL);
    if (ret < 0) {
      return -errno;
    }
    if (FD_ISSET(client->sd, &read_fds)) {
      break;
    }
    if (FD_ISSET(client->timer_fd, &read_fds)) {
      ret = iotsec_client_handle_ack_timeout(client, msg);
      if (ret < 0) {
        return ret;
      }
    }
  }
  return 0;
}

/**
 *  @brief Wait for a message to arrive or the response timer to expire
 *
 *  @param[in] client Pointer to a client structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int iotsec_client_listen_resp(iotsec_client_t *client) {
  fd_set read_fds = {{0}};
  int max_fd = 0;
  int ret = 0;

  while (1) {
    FD_ZERO(&read_fds);
    FD_SET(client->sd, &read_fds);
    FD_SET(client->timer_fd, &read_fds);
    max_fd = client->sd;
    if (client->timer_fd > max_fd) {
      max_fd = client->timer_fd;
    }
    ret = select(max_fd + 1, &read_fds, NULL, NULL, NULL);
    if (ret < 0) {
      return -errno;
    }
    if (FD_ISSET(client->sd, &read_fds)) {
      break;
    }
    if (FD_ISSET(client->timer_fd, &read_fds)) {
      return -ETIMEDOUT;
    }
  }
  return 0;
}

/**
 *  @brief Compare the token values in a request message and a response message
 *
 *  @param[in] req Pointer to the request message
 *  @param[in] resp Pointer to the response message
 *
 *  @returns Comparison value
 *  @retval 0 the tokens are not equal
 *  @retval 1 the tokens are equal
 */
static int iotsec_client_match_token(iotsec_msg_t *req, iotsec_msg_t *resp) {
  return ((iotsec_msg_get_token_len(resp) == iotsec_msg_get_token_len(req)) &&
          (memcmp(iotsec_msg_get_token(resp), iotsec_msg_get_token(req),
                  iotsec_msg_get_token_len(req)) == 0));
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
static unsigned iotsec_client_check_options(iotsec_msg_t *msg) {
#ifdef IOTSEC_PROXY
  return iotsec_msg_check_unsafe_ops(msg);
#else  /* !IOTSEC_PROXY */
  return iotsec_msg_check_critical_ops(msg);
#endif /* IOTSEC_PROXY */
}

/**
 *  @brief Handle a received piggy-backed response message
 *
 *  An acknowledgement has been received that contains
 *  the same token as the request. Check the response
 *  contained within it.
 *
 *  @param[in,out] client Pointer to a client structure
 *  @param[in] resp Pointer to the response message
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int iotsec_client_handle_piggybacked_response(iotsec_client_t *client,
                                                     iotsec_msg_t *resp) {
  unsigned op_num = 0;

  op_num = iotsec_client_check_options(resp);
  if (op_num != 0) {
    iotsec_log_info(
        "Found bad option number %u in message from host %s and port %s",
        op_num, client->server_host, client->server_port);
    iotsec_client_reject(client, resp);
    return -EBADMSG;
  }
  iotsec_log_info(
      "Received acknowledgement and response from host %s and port %s",
      client->server_host, client->server_port);
  return 0;
}

/**
 *  @brief Handle a received separate response message
 *
 *  A separate response has been received that contains
 *  the same token as the request. Check the response
 *  and send an acknowledgement if necessary.
 *
 *  @param[in,out] client Pointer to a client structure
 *  @param[in] resp Pointer to the response message
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int iotsec_client_handle_sep_response(iotsec_client_t *client,
                                             iotsec_msg_t *resp) {
  unsigned op_num = 0;

  if (iotsec_msg_get_type(resp) == IOTSEC_MSG_CON) {
    iotsec_log_info("Received confirmable response from host %s and port %s",
                    client->server_host, client->server_port);
    op_num = iotsec_client_check_options(resp);
    if (op_num != 0) {
      iotsec_log_info(
          "Found bad option number %u in message from host %s and port %s",
          op_num, client->server_host, client->server_port);
      iotsec_client_reject(client, resp);
      return -EBADMSG;
    }
    return iotsec_client_send_ack(client, resp);
  } else if (iotsec_msg_get_type(resp) == IOTSEC_MSG_NON) {
    iotsec_log_info(
        "Received non-confirmable response from host %s and port %s",
        client->server_host, client->server_port);
    op_num = iotsec_client_check_options(resp);
    if (op_num != 0) {
      iotsec_log_info(
          "Found bad option number %u in message from host %s and port %s",
          op_num, client->server_host, client->server_port);
      iotsec_client_reject(client, resp);
      return -EBADMSG;
    }
    return 0;
  }
  iotsec_client_reject(client, resp);
  return -EBADMSG;
}

/**
 *  @brief Handle a separate response to a confirmable request
 *
 *  An acknowledgement has been received. Receive the
 *  response and send an acknowledgement back to the server.
 *
 *  @param[in,out] client Pointer to a client structure
 *  @param[in] req Pointer to the request message
 *  @param[out] resp Pointer to the response message
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int iotsec_client_exchange_sep(iotsec_client_t *client,
                                      iotsec_msg_t *req, iotsec_msg_t *resp) {
  ssize_t num = 0;
  int ret = 0;

  /* wait for a separate response to a confirmable request */
  iotsec_log_info("Expecting response from host %s and port %s",
                  client->server_host, client->server_port);
  iotsec_client_start_resp_timer(client);
  while (1) {
    ret = iotsec_client_listen_resp(client);
    if (ret < 0) {
      return ret;
    }
    num = iotsec_client_recv(client, resp);
    if (num == -EAGAIN) {
      continue;
    }
    if (num < 0) {
      return num;
    }
    if (iotsec_msg_get_msg_id(resp) == iotsec_msg_get_msg_id(req)) {
      if (iotsec_msg_get_type(resp) == IOTSEC_MSG_ACK) {
        /* message deduplication */
        iotsec_log_info(
            "Received duplicate acknowledgement from host %s and port %s",
            client->server_host, client->server_port);
        continue;
      } else if (iotsec_msg_get_type(resp) == IOTSEC_MSG_RST) {
        return -ECONNRESET;
      }
      iotsec_client_reject(client, resp);
      return -EBADMSG;
    }
    if (iotsec_client_match_token(req, resp)) {
      return iotsec_client_handle_sep_response(client, resp);
    }
    /* message deduplication */
    /* we might have received a duplicate message that was already received from
     * the same server */
    /* reject the message and continue listening */
    ret = iotsec_client_reject(client, resp);
    if (ret < 0) {
      return ret;
    }
  }
  return 0;
}

/**
 *  @brief Handle the response to a confirmable request
 *
 *  A confirmable request has been sent to the server.
 *  Receive the acknowledgement and response. Send an
 *  acknowledgement if necessary.
 *
 *  @param[in,out] client Pointer to a client structure
 *  @param[in] req Pointer to the request message
 *  @param[out] resp Pointer to the response message
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
static int iotsec_client_exchange_con(iotsec_client_t *client,
                                      iotsec_msg_t *req, iotsec_msg_t *resp) {
  ssize_t num = 0;
  int ret = 0;

  /*  wait for piggy-backed response in ack message
   *  or ack message and separate response message
   */
  iotsec_log_info("Expecting acknowledgement from host %s and port %s",
                  client->server_host, client->server_port);
  iotsec_client_start_ack_timer(client);
  while (1) {
    ret = iotsec_client_listen_ack(client, req);
    if (ret < 0) {
      return ret;
    }
    num = iotsec_client_recv(client, resp);
    if (num == -EAGAIN) {
      continue;
    }
    if (num < 0) {
      return num;
    }
    if (iotsec_msg_get_msg_id(resp) == iotsec_msg_get_msg_id(req)) {
      if (iotsec_msg_get_type(resp) == IOTSEC_MSG_ACK) {
        if (iotsec_msg_is_empty(resp)) {
          /* received ack message, wait for separate response message */
          iotsec_log_info("Received acknowledgement from host %s and port %s",
                          client->server_host, client->server_port);
          return iotsec_client_exchange_sep(client, req, resp);
        } else if (iotsec_client_match_token(req, resp)) {
          return iotsec_client_handle_piggybacked_response(client, resp);
        }
      } else if (iotsec_msg_get_type(resp) == IOTSEC_MSG_RST) {
        return -ECONNRESET;
      }
      iotsec_client_reject(client, resp);
      return -EBADMSG;
    } else if (iotsec_client_match_token(req, resp)) {
      /* RFC7252
       * as the underlying datagram transport may not be sequence-preserving,
       * the Confirmable message carrying the response may actually arrive
       * before or after the Acknowledgement message for the request; for
       * the purposes of terminating the retransmission sequence, this also
       * serves as an acknowledgement.
       */
      return iotsec_client_handle_sep_response(client, resp);
    }
    /* message deduplication */
    /* we might have received a duplicate message that was already received from
     * the same server */
    /* reject the message and continue listening */
    ret = iotsec_client_reject(client, resp);
    if (ret < 0) {
      return ret;
    }
  }
  return 0;
}

/**
 *  @brief Handle the response to a non-confirmable request
 *
 *  A non-confirmable request has been sent to the server.
 *  Receive the response.
 *
 *  @param[in,out] client Pointer to a client structure
 *  @param[in] req Pointer to the request message
 *  @param[out] resp Pointer to the response message
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 **/
static int iotsec_client_exchange_non(iotsec_client_t *client,
                                      iotsec_msg_t *req, iotsec_msg_t *resp) {
  ssize_t num = 0;
  int ret = 0;

  iotsec_log_info("Expecting response from host %s and port %s",
                  client->server_host, client->server_port);
  iotsec_client_start_resp_timer(client);
  while (1) {
    ret = iotsec_client_listen_resp(client);
    if (ret < 0) {
      return ret;
    }
    num = iotsec_client_recv(client, resp);
    if (num == -EAGAIN) {
      continue;
    }
    if (num < 0) {
      return num;
    }
    if (iotsec_msg_get_msg_id(resp) == iotsec_msg_get_msg_id(req)) {
      if (iotsec_msg_get_type(resp) == IOTSEC_MSG_RST) {
        return -ECONNRESET;
      }
      iotsec_client_reject(client, resp);
      return -EBADMSG;
    }
    if (iotsec_client_match_token(req, resp)) {
      return iotsec_client_handle_sep_response(client, resp);
    }
    /* message deduplication */
    /* we might have received a duplicate message that was already received from
     * the same server */
    /* reject the message and continue listening */
    ret = iotsec_client_reject(client, resp);
    if (ret < 0) {
      return ret;
    }
  }
  return 0;
}

int iotsec_client_exchange(iotsec_client_t *client, iotsec_msg_t *req,
                           iotsec_msg_t *resp) {
  unsigned char msg_id_buf[2] = {0};
  unsigned msg_id = 0;
  ssize_t num = 0;
  char token[4] = {0};
  int ret = 0;

  /* check for a valid request */
  if ((iotsec_msg_get_type(req) == IOTSEC_MSG_ACK) ||
      (iotsec_msg_get_type(req) == IOTSEC_MSG_RST) ||
      (iotsec_msg_get_code_class(req) != IOTSEC_MSG_REQ)) {
    return -EINVAL;
  }

  /* generate the message ID */
  iotsec_msg_gen_rand_str((char *)msg_id_buf, sizeof(msg_id_buf));
  msg_id = (((unsigned)msg_id_buf[1]) << 8) | (unsigned)msg_id_buf[0];
  ret = iotsec_msg_set_msg_id(req, msg_id);
  if (ret < 0) {
    return ret;
  }

  /* generate the token */
  iotsec_msg_gen_rand_str(token, sizeof(token));
  ret = iotsec_msg_set_token(req, token, sizeof(token));
  if (ret < 0) {
    return ret;
  }

  if (iotsec_msg_get_type(req) == IOTSEC_MSG_CON) {
    iotsec_log_info("Sending confirmable request to host %s and port %s",
                    client->server_host, client->server_port);
  } else if (iotsec_msg_get_type(req) == IOTSEC_MSG_NON) {
    iotsec_log_info("Sending non-confirmable request to host %s and port %s",
                    client->server_host, client->server_port);
  }

  num = iotsec_client_send(client, req);
  if (num < 0) {
    return num;
  }

  if (iotsec_msg_get_type(req) == IOTSEC_MSG_CON) {
    return iotsec_client_exchange_con(client, req, resp);
  } else if (iotsec_msg_get_type(req) == IOTSEC_MSG_NON) {
    return iotsec_client_exchange_non(client, req, resp);
  }
  return -EINVAL;
}

/**
 *  @brief Exchange a request with the server using blockwise transfers
 *
 *  A block1 transfer (from client to server, i.e. PUT or POST)
 *  can invoke a response payload. The client includes a block2
 *  option in the final block1 message exchange to instruct the
 *  server to use a blockwise transfer for the response payload
 *  if there is one.
 *
 *  @param[in,out] client Pointer to a client structure
 *  @param[in] req Pointer to the request message
 *  @param[out] resp Pointer to the response message
 *  @param[in] block1_size Block1 size
 *  @param[in] block2_size Block2 size
 *  @param[in] body Pointer to a buffer to hold the body
 *  @param[in] body_len Length of the buffer to hold the body
 *
 *  @returns Operation status
 *  @retval >=0 Length of the data sent
 *  @retval <0 Error
 **/
static ssize_t iotsec_client_exchange_blockwise1(
    iotsec_client_t *client, iotsec_msg_t *req, iotsec_msg_t *resp,
    unsigned block1_size, unsigned block2_size, char *body, size_t body_len) {
  iotsec_msg_t msg = {0};
  unsigned tmp_block_size = 0;
  unsigned payload_len = 0;
  unsigned block1_more = 0;
  unsigned block1_num = 0;
  unsigned block1_len = 0;
  unsigned block2_len = 0;
  size_t block1_start = 0;
  char block_val[IOTSEC_MSG_OP_MAX_BLOCK_VAL_LEN] = {0};
  int block1_szx = -1;
  int ret = 0;

  /* use a block1 option to describe the size of the blocks in the request */
  if ((block1_size == 0) || (block2_size == 0)) {
    return -EINVAL;
  }
  ret = iotsec_msg_op_calc_block_szx(block1_size);
  if (ret < 0) {
    return ret;
  }
  block1_szx = ret;
  ret = iotsec_msg_op_calc_block_szx(block2_size);
  if (ret < 0) {
    return ret;
  }
  iotsec_msg_create(&msg);
  while (1) {
    iotsec_log_debug("Handling block with start byte index: %u for "
                     "library-level blockwise transfer",
                     block1_start);
    /* copy the request message so we can add a block1 option */
    ret = iotsec_msg_copy(&msg, req);
    if (ret < 0) {
      return ret;
    }
    block1_more = 1;
    payload_len = block1_size;
    if (block1_start + block1_size >= body_len) {
      block1_more = 0;
      payload_len = body_len - block1_start;
    }
    block1_num = iotsec_msg_block_start_to_num(block1_start, block1_szx);
    /* format the block1 option */
    ret = iotsec_msg_op_format_block_val(block_val, sizeof(block_val),
                                         block1_num, block1_more, block1_size);
    if (ret < 0) {
      iotsec_msg_destroy(&msg);
      return ret;
    }
    block1_len = ret;
    /* add the block1 option */
    ret = iotsec_msg_add_op(&msg, IOTSEC_MSG_BLOCK1, block1_len, block_val);
    if (ret < 0) {
      iotsec_msg_destroy(&msg);
      return ret;
    }
    if (block1_more == 0) {
      /* format the block2 option for the last block1 message exchange */
      ret = iotsec_msg_op_format_block_val(block_val, sizeof(block_val), 0, 0,
                                           block2_size);
      if (ret < 0) {
        iotsec_msg_destroy(&msg);
        return ret;
      }
      block2_len = ret;
      /* add the block2 option */
      ret = iotsec_msg_add_op(&msg, IOTSEC_MSG_BLOCK2, block2_len, block_val);
      if (ret < 0) {
        iotsec_msg_destroy(&msg);
        return ret;
      }
    }
    /* add the payload */
    ret = iotsec_msg_set_payload(&msg, body + block1_start, payload_len);
    if (ret < 0) {
      iotsec_msg_destroy(&msg);
      return ret;
    }
    /* exchange with the server */
    ret = iotsec_client_exchange(client, &msg, resp);
    if (ret < 0) {
      iotsec_msg_destroy(&msg);
      return ret;
    }
    if (!(iotsec_msg_get_code_class(resp) == IOTSEC_MSG_SUCCESS)) {
      iotsec_msg_destroy(&msg);
      return 0;
    }
    if ((iotsec_msg_get_code_detail(resp) != IOTSEC_MSG_CONTINUE) &&
        (iotsec_msg_get_code_detail(resp) != IOTSEC_MSG_CREATED) &&
        (iotsec_msg_get_code_detail(resp) != IOTSEC_MSG_CHANGED)) {
      iotsec_msg_destroy(&msg);
      return 0;
    }
    /* inspect the block1 option in the response */
    ret = iotsec_msg_parse_block_op(&block1_num, &block1_more, &tmp_block_size,
                                    resp, IOTSEC_MSG_BLOCK1);
    if (ret != 0) {
      iotsec_msg_destroy(&msg);
      return -EBADMSG;
    }
    /* allow the server to resize the blocks */
    if (tmp_block_size < block1_size) {
      block1_size = tmp_block_size;
    }
    /* check that the acknowledged block is the next one in sequence */
    if (block1_num * block1_size != block1_start) {
      iotsec_msg_destroy(&msg);
      return -EBADMSG;
    }
    /* recalculate the block size exponent */
    ret = iotsec_msg_op_calc_block_szx(block1_size);
    if (ret < 0) {
      iotsec_msg_destroy(&msg);
      return -EBADMSG;
    }
    block1_szx = ret;
    /* advance to the next block */
    block1_start += payload_len;
    /* check for completion */
    if (block1_start >= body_len) {
      iotsec_msg_destroy(&msg);
      return block1_start; /* success */
    }
    iotsec_msg_reset(&msg);
    iotsec_msg_reset(resp);
  }
}

/**
 *  @brief Exchange a response with the server using blockwise transfers
 *
 *  @param[in,out] client Pointer to a client structure
 *  @param[in] req Pointer to the request message
 *  @param[out] resp Pointer to the response message
 *  @param[in] block2_size Block2 size
 *  @param[in] body Pointer to a buffer to hold the body
 *  @param[in] body_len Length of the buffer to hold the body
 *  @param[in] have_resp Flag to indicate that the first response has already
 *been received
 *
 *  @returns Operation status
 *  @retval >=0 Length of the data received
 *  @retval <0 Error
 **/
static ssize_t
iotsec_client_exchange_blockwise2(iotsec_client_t *client, iotsec_msg_t *req,
                                  iotsec_msg_t *resp, unsigned block2_size,
                                  char *body, size_t body_len, int have_resp) {
  iotsec_msg_t msg = {0};
  unsigned tmp_block_size = 0;
  unsigned payload_len = 0;
  unsigned block2_more = 0;
  unsigned block2_num = 0;
  unsigned block2_len = 0;
  size_t block2_start = 0;
  char block_val[IOTSEC_MSG_OP_MAX_BLOCK_VAL_LEN] = {0};
  int block2_szx = -1;
  int ret = 0;

  /* use a block2 option to control the size of the blocks in the response */
  if (block2_size == 0) {
    return -EINVAL;
  }
  ret = iotsec_msg_op_calc_block_szx(block2_size);
  if (ret < 0) {
    return ret;
  }
  block2_szx = ret;
  iotsec_msg_create(&msg);
  while (1) {
    iotsec_log_debug("Handling block with start byte index: %u for GET "
                     "library-level blockwise transfer",
                     block2_start);
    if (!have_resp) {
      /* copy the request message so we can add a block2 option */
      ret = iotsec_msg_copy(&msg, req);
      if (ret < 0) {
        return ret;
      }
      block2_more = 0; /* more must be zero for this use case */
      block2_num = iotsec_msg_block_start_to_num(block2_start, block2_szx);
      /* format the block2 option */
      ret = iotsec_msg_op_format_block_val(
          block_val, sizeof(block_val), block2_num, block2_more, block2_size);
      if (ret < 0) {
        iotsec_msg_destroy(&msg);
        return ret;
      }
      block2_len = ret;
      /* add the block2 option */
      ret = iotsec_msg_add_op(&msg, IOTSEC_MSG_BLOCK2, block2_len, block_val);
      if (ret < 0) {
        iotsec_msg_destroy(&msg);
        return ret;
      }
      /* exchange with the server */
      ret = iotsec_client_exchange(client, &msg, resp);
      if (ret < 0) {
        iotsec_msg_destroy(&msg);
        return ret;
      }
    }
    if (!(iotsec_msg_get_code_class(resp) == IOTSEC_MSG_SUCCESS)) {
      iotsec_msg_destroy(&msg);
      return 0;
    }
    if (iotsec_msg_get_code_detail(req) == IOTSEC_MSG_GET) {
      if ((iotsec_msg_get_code_detail(resp) != IOTSEC_MSG_CONTINUE) &&
          (iotsec_msg_get_code_detail(resp) != IOTSEC_MSG_CONTENT)) {
        iotsec_msg_destroy(&msg);
        return 0;
      }
    } else {
      if ((iotsec_msg_get_code_detail(resp) != IOTSEC_MSG_CONTINUE) &&
          (iotsec_msg_get_code_detail(resp) != IOTSEC_MSG_CREATED) &&
          (iotsec_msg_get_code_detail(resp) != IOTSEC_MSG_CHANGED)) {
        iotsec_msg_destroy(&msg);
        return 0;
      }
    }
    /* inspect the block2 option in the response */
    ret = iotsec_msg_parse_block_op(&block2_num, &block2_more, &tmp_block_size,
                                    resp, IOTSEC_MSG_BLOCK2);
    if (ret != 0) {
      iotsec_msg_destroy(&msg);
      return -EBADMSG;
    }
    /* allow the server to resize the blocks */
    if (tmp_block_size < block2_size) {
      block2_size = tmp_block_size;
    }
    /* check that the received block is the next one in sequence */
    if (block2_num * block2_size != block2_start) {
      iotsec_msg_destroy(&msg);
      return -EBADMSG;
    }
    /* recalculate the block size exponent */
    ret = iotsec_msg_op_calc_block_szx(block2_size);
    if (ret < 0) {
      iotsec_msg_destroy(&msg);
      return -EBADMSG;
    }
    block2_szx = ret;
    /* check that the payload in the response has the correct size */
    payload_len = iotsec_msg_get_payload_len(resp);
    if (payload_len > block2_size) {
      iotsec_msg_destroy(&msg);
      return -EBADMSG;
    }
    if ((block2_more) && (payload_len != block2_size)) {
      iotsec_msg_destroy(&msg);
      return -EBADMSG;
    }
    /* check for potential buffer overrun */
    if (block2_start + payload_len > body_len) {
      iotsec_msg_destroy(&msg);
      return -ENOSPC;
    }
    /* copy the payload data from the response */
    memcpy(body + block2_start, iotsec_msg_get_payload(resp), payload_len);
    /* advance to the next block */
    block2_start += payload_len;
    /* check for completion */
    if (block2_more == 0) {
      iotsec_msg_destroy(&msg);
      return block2_start; /* success */
    }
    iotsec_msg_reset(&msg);
    iotsec_msg_reset(resp);
    have_resp = 0;
  }
  return 0;
}

ssize_t iotsec_client_exchange_blockwise(iotsec_client_t *client,
                                         iotsec_msg_t *req, iotsec_msg_t *resp,
                                         unsigned block1_size,
                                         unsigned block2_size, char *body,
                                         size_t body_len, int have_resp) {
  ssize_t num = 0;

  if (iotsec_msg_get_code_detail(req) == IOTSEC_MSG_GET) {
    iotsec_log_info("Starting new GET library-level blockwise transfer");
    num = iotsec_client_exchange_blockwise2(client, req, resp, block2_size,
                                            body, body_len, have_resp);
    if (num <= 0) {
      return num;
    }
    iotsec_log_info("Completed GET library-level blockwise transfer");
    return num;
  } else if (iotsec_msg_get_code_detail(req) == IOTSEC_MSG_PUT) {
    iotsec_log_info("Starting new PUT library-level blockwise transfer");
    num = iotsec_client_exchange_blockwise1(client, req, resp, block1_size,
                                            block2_size, body, body_len);
    if (num <= 0) {
      return num;
    }
    if (iotsec_msg_get_payload_len(resp) == 0) {
      iotsec_log_info("Completed PUT library-level blockwise transfer");
      return 0;
    }
    num = iotsec_client_exchange_blockwise2(client, req, resp, block2_size,
                                            body, body_len, 1);
    if (num <= 0) {
      return num;
    }
    iotsec_log_info("Completed PUT library-level blockwise transfer");
    return num;
  } else if (iotsec_msg_get_code_detail(req) == IOTSEC_MSG_POST) {
    iotsec_log_info("Starting new POST library-level blockwise transfer");
    num = iotsec_client_exchange_blockwise1(client, req, resp, block1_size,
                                            block2_size, body, body_len);
    if (num <= 0) {
      return num;
    }
    if (iotsec_msg_get_payload_len(resp) == 0) {
      iotsec_log_info("Completed POST library-level blockwise transfer");
      return 0;
    }
    num = iotsec_client_exchange_blockwise2(client, req, resp, block2_size,
                                            body, body_len, 1);
    if (num <= 0) {
      return num;
    }
    iotsec_log_info("Completed POST library-level blockwise transfer");
    return num;
  }
  iotsec_log_warn("Request method unsupported in blockwise transfer");
  return -EINVAL;
}
