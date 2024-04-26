/**
 *  @file iotsec_server.h
 *
 *  @brief Include file for the IOTsec server library
 */

#ifndef IOTSEC_SERVER_H
#define IOTSEC_SERVER_H

#include <netinet/in.h>
#include <time.h>
#ifdef IOTSEC_DTLS_EN
#include <gnutls/dtls.h>
#include <gnutls/gnutls.h>
#endif
#include "iotsec_ipv.h"
#include "iotsec_msg.h"

#define IOTSEC_SERVER_NUM_TRANS                                                \
  8 /**< Maximum number of active transactions per server */
#define IOTSEC_SERVER_ADDR_BUF_LEN 128 /**< Buffer length for host addresses   \
                                        */
#define IOTSEC_SERVER_DIAG_PAYLOAD_LEN                                         \
  128 /**< Buffer length for diagnostic payloads */

#define iotsec_server_trans_get_type(trans)                                    \
  ((trans)->type) /**< Get the type of transaction */
#define iotsec_server_trans_get_req(trans)                                     \
  (&(trans)->req) /**< Get the last request message received for this          \
                     transaction */
#define iotsec_server_trans_get_resp(trans)                                    \
  (&(trans)->resp) /**< Get the last response message sent for this            \
                      transaction */
#define iotsec_server_trans_get_body(trans)                                    \
  ((trans)->body) /**< Get the body of a blockwise transfer */
#define iotsec_server_trans_get_body_len(trans)                                \
  ((trans)->body_len) /**< Get the length of the body of a blockwise transfer  \
                       */
#define iotsec_server_trans_get_body_end(trans)                                \
  ((trans)->body_end) /**< Get the amount of relevant data in body of a        \
                         blockwise transfer */
#define iotsec_server_trans_set_body_end(trans, i)                             \
  ((trans)->body_end = (i)) /**< Get the amount of relevant data in body of a  \
                               blockwise transfer */

/**
 *  @brief Transaction type enumeration
 */
typedef enum {
  IOTSEC_SERVER_TRANS_REGULAR =
      0, /**< Regular (i.e. non-blockwise) transaction */
  IOTSEC_SERVER_TRANS_BLOCKWISE_GET = 1, /**< Blockwise GET transaction */
  IOTSEC_SERVER_TRANS_BLOCKWISE_PUT1 =
      2, /**< Request phase of a blockwise PUT transaction */
  IOTSEC_SERVER_TRANS_BLOCKWISE_PUT2 =
      3, /**< Response phase of a blockwise PUT transaction */
  IOTSEC_SERVER_TRANS_BLOCKWISE_POST1 =
      4, /**< Request phase of a Blockwise POST transaction */
  IOTSEC_SERVER_TRANS_BLOCKWISE_POST2 =
      5 /**< Response phase of a Blockwise POST transaction */
} iotsec_server_trans_type_t;

/**
 *  @brief Response type enumeration
 */
typedef enum {
  IOTSEC_SERVER_PIGGYBACKED = 0, /**< Piggybacked response */
  IOTSEC_SERVER_SEPARATE = 1     /**< Separate response */
} iotsec_server_resp_t;

/**
 *  @brief Forward declaration of transaction structure
 */
struct iotsec_server_trans;

/**
 *  @brief Server transaction handler callback function
 *
 *  @param[in,out] trans Pointer to a transaction structure
 *  @param[in] req Pointer to the request message
 *  @param[out] resp Pointer to the response message
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
typedef int (*iotsec_server_trans_handler_t)(struct iotsec_server_trans *trans,
                                             iotsec_msg_t *req,
                                             iotsec_msg_t *resp);

/**
 *  @brief URI path structure
 */
typedef struct iotsec_server_path {
  char *str; /**< String containing a path */
  struct iotsec_server_path
      *next; /**< Pointer to the next URI path structure in the list */
} iotsec_server_path_t;

/**
 *  @brief URI path list structure
 */
typedef struct {
  iotsec_server_path_t
      *first; /**< Pointer to the first URI path structure in the list */
  iotsec_server_path_t
      *last; /**< Pointer to the last URI path structure in the list */
} iotsec_server_path_list_t;

struct iotsec_server;

/**
 *  @brief Transaction structure
 */
typedef struct iotsec_server_trans {
  int active; /**< Flag to indicate if this transaction structure contains valid
                 data */
  iotsec_server_trans_type_t type; /**< Transaction type */
  time_t
      last_use; /**< The time that this transaction structure was last used */
  int timer_fd; /**< Timer file descriptor */
  struct timespec timeout;             /**< Timeout value */
  unsigned num_retrans;                /**< Current number of retransmissions */
  iotsec_ipv_sockaddr_in_t client_sin; /**< Socket structure */
  socklen_t client_sin_len;            /**< Socket structure length */
  char client_addr[IOTSEC_SERVER_ADDR_BUF_LEN]; /**< String to hold the client
                                                   address */
  iotsec_msg_t req;  /**< Last request message received for this transaction */
  iotsec_msg_t resp; /**< Last response message sent for this transaction */
  char *body;        /**< Pointer to a buffer for blockwise transfers */
  size_t body_len;   /**< Length of the buffer for blockwise transfers */
  size_t body_end;   /**< Amount of relevant data in the buffer for blockwise
                        transfers */
  unsigned block1_size; /**< Block1 size for blockwise transfers */
  unsigned block2_size; /**< Block2 size for blockwise transfers */
  size_t block1_next;   /**< Byte offset of the next block in the request */
  size_t block2_next;   /**< Byte offset of the next block in the response */
  char block_uri[IOTSEC_MSG_OP_URI_PATH_MAX_LEN +
                 1]; /**< The URI for the current blockwise transfer */
  iotsec_msg_success_t
      block_detail; /**< Code detail for a PUT or POST blockwise operation */
  iotsec_server_trans_handler_t
      block_rx; /**< User-supplied callback function to be called when the body
                   of a blockwise transfer has been fully received */
  struct iotsec_server
      *server; /**< Pointer to the containing server structure */
#ifdef IOTSEC_DTLS_EN
  gnutls_session_t session; /**< DTLS session */
#endif
} iotsec_server_trans_t;

/**
 *  @brief Server structure
 */
typedef struct iotsec_server {
  int sd;          /**< Socket descriptor */
  unsigned msg_id; /**< Last message ID value used in a response message */
  iotsec_server_path_list_t
      sep_list; /**< List of URI paths that require separate responses */
  iotsec_server_trans_t
      trans[IOTSEC_SERVER_NUM_TRANS];   /**< Array of transaction structures */
  iotsec_server_trans_handler_t handle; /**< Call-back function to handle
                                           requests and generate responses */
#ifdef IOTSEC_DTLS_EN
  gnutls_certificate_credentials_t cred; /**< DTLS credentials */
  gnutls_priority_t priority;            /**< DTLS priorities */
  gnutls_dh_params_t dh_params;          /**< Diffie-Hellman parameters */
#endif
} iotsec_server_t;

/**
 *  @brief Handle a library-level blockwise transfer
 *
 *  Configure the transaction structure to do a library-level
 *  blockwise transfer. This function should be called by the
 *  application from the handle callback function.
 *
 *  @param[in,out] trans Pointer to a transaction structure
 *  @param[in] req Pointer to the request message
 *  @param[out] resp Pointer to the response message
 *  @param[in] block1_size Preferred block1 size
 *  @param[in] block2_size Preferred block2 size
 *  @param[in] body Buffer containing the body
 *  @param[in] body_len length of the buffer
 *  @param[in] block_rx Callback function to be called when the body of a
 * blockwise transfer has been fully received
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
int iotsec_server_trans_handle_blockwise(
    iotsec_server_trans_t *trans, iotsec_msg_t *req, iotsec_msg_t *resp,
    unsigned block1_size, unsigned block2_size, char *body, size_t body_len,
    iotsec_server_trans_handler_t block_rx);

#ifdef IOTSEC_DTLS_EN

/**
 *  @brief Initialise a server structure
 *
 *  @param[out] server Pointer to a server structure
 *  @param[in] handle Call-back function to handle client requests
 *  @param[in] host String containing the host address of the server
 *  @param[in] port String containing the port number of the server
 *  @param[in] key_file_name String containing the DTLS key file name
 *  @param[in] cert_file_name String containing the DTLS certificate file name
 *  @param[in] trust_file_name String containing the DTLS trust file name
 *  @param[in] crl_file_name String containing the DTLS certificate revocation
 * list file name
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
int iotsec_server_create(iotsec_server_t *server,
                         iotsec_server_trans_handler_t handle, const char *host,
                         const char *port, const char *key_file_name,
                         const char *cert_file_name,
                         const char *trust_file_name,
                         const char *crl_file_name);

#else /* !IOTSEC_DTLS_EN */

/**
 *  @brief Initialise a server structure
 *
 *  @param[out] server Pointer to a server structure
 *  @param[in] handle Call-back function to handle client requests
 *  @param[in] host String containing the host address of the server
 *  @param[in] port String containing the port number of the server
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
int iotsec_server_create(iotsec_server_t *server,
                         iotsec_server_trans_handler_t handle, const char *host,
                         const char *port);

#endif /* IOTSEC_DTLS_EN */

/**
 *  @brief Deinitialise a server structure
 *
 *  @param[in,out] server Pointer to a server structure
 */
void iotsec_server_destroy(iotsec_server_t *server);

/**
 *  @brief Get a new message ID value
 *
 *  @param[in,out] server Pointer to a server structure
 *
 *  @returns message ID value
 */
unsigned iotsec_server_get_next_msg_id(iotsec_server_t *server);

/**
 *  @brief Register a URI path that requires a separate response
 *
 *  @param[in,out] server Pointer to a server structure
 *  @param[in] str String representation of a URI path
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
int iotsec_server_add_sep_resp_uri_path(iotsec_server_t *server,
                                        const char *str);

/**
 *  @brief Run the server
 *
 *  Listen for incoming requests. For each request received,
 *  call the handle call-back function in the server structure
 *  and send the response to the client.
 *
 *  @param[in,out] server Pointer to a server structure
 *
 *  @returns Operation status
 *  @retval 0 Success
 *  @retval <0 Error
 */
int iotsec_server_run(iotsec_server_t *server);

#endif
