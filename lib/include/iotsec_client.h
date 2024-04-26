/**
 *  @file iotsec_client.h
 *
 *  @brief Include file for the IOTsec client library
 */

#ifndef IOTSEC_CLIENT_H
#define IOTSEC_CLIENT_H

#include <netinet/in.h>
#include <time.h>
#ifdef IOTSEC_DTLS_EN
#include <gnutls/dtls.h>
#include <gnutls/gnutls.h>
#endif
#include "iotsec_ipv.h"
#include "iotsec_msg.h"

#define IOTSEC_CLIENT_HOST_BUF_LEN 128 /**< Buffer length for host addresses   \
                                        */
#define IOTSEC_CLIENT_PORT_BUF_LEN 8   /**< Buffer length for port numbers */

/**
 *  @brief Client structure
 */
typedef struct {
  int sd;                              /**< Socket descriptor */
  int timer_fd;                        /**< Timer file descriptor */
  struct timespec timeout;             /**< Timeout value */
  unsigned num_retrans;                /**< Current number of retransmissions */
  iotsec_ipv_sockaddr_in_t server_sin; /**< Socket structture */
  socklen_t server_sin_len;            /**< Socket structure length */
  char server_host[IOTSEC_CLIENT_HOST_BUF_LEN]; /**< String to hold the server
                                                   host address */
  char server_port[IOTSEC_CLIENT_PORT_BUF_LEN]; /**< String to hold the server
                                                   port number */
#ifdef IOTSEC_DTLS_EN
  gnutls_session_t session;              /**< DTLS session */
  gnutls_certificate_credentials_t cred; /**< DTLS credentials */
  gnutls_priority_t priority;            /**< DTLS priorities */
#endif
} iotsec_client_t;

#ifdef IOTSEC_DTLS_EN

/**
 *  @brief Initialise a client structure
 *
 *  @param[out] client Pointer to a client structure
 *  @param[in] host Pointer to a string containing the host address of the
 * server
 *  @param[in] port Port number of the server
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
int iotsec_client_create(iotsec_client_t *client, const char *host,
                         const char *port, const char *key_file_name,
                         const char *cert_file_name,
                         const char *trust_file_name, const char *crl_file_name,
                         const char *common_name);

#else /* !IOTSEC_DTLS_EN */

/**
 *  @brief Initialise a client structure
 *
 *  @param[out] client Pointer to a client structure
 *  @param[in] host Pointer to a string containing the host address of the
 * server
 *  @param[in] port Port number of the server
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
int iotsec_client_create(iotsec_client_t *client, const char *host,
                         const char *port);

#endif /* IOTSEC_DTLS_EN */

/**
 *  @brief Deinitialise a client structure
 *
 *  @param[in,out] client Pointer to a client structure
 */
void iotsec_client_destroy(iotsec_client_t *client);

/**
 *  @brief Send a request to the server and receive the response
 *
 *  This function sets the message ID and token fields of
 *  the request message overriding any values set by the
 *  calling function.
 *
 *  @param[in,out] client Pointer to a client structure
 *  @param[in] req Pointer to the request message
 *  @param[out] resp Pointer to the response message
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 **/
int iotsec_client_exchange(iotsec_client_t *client, iotsec_msg_t *req,
                           iotsec_msg_t *resp);

/**
 *  @brief Exchange with the server using blockwise transfers
 *
 *  The calling application should not pass in a request
 *  message that contains a block1 or block2 option. This
 *  function will add block1 and block2 options internally.
 *  This function sets the message ID and token fields of
 *  the request message overriding any values set by the
 *  calling function.
 *
 *  @param[in,out] client Pointer to a client structure
 *  @param[in] req Pointer to the request message
 *  @param[out] resp Pointer to the response message
 *  @param[in] block1_size Block1 size
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
ssize_t iotsec_client_exchange_blockwise(iotsec_client_t *client,
                                         iotsec_msg_t *req, iotsec_msg_t *resp,
                                         unsigned block1_size,
                                         unsigned block2_size, char *body,
                                         size_t body_len, int have_resp);

#endif
