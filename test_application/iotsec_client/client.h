#ifndef IOTSEC_CLIENT_APP_H
#define IOTSEC_CLIENT_APP_H

#include "iotsec_client.h"
#include <stddef.h>

typedef struct {
  iotsec_client_t iotsec_client;
} iotsec_client_app_t;

int iotsec_client_app_init(void);
void iotsec_client_app_deinit(void);
int iotsec_client_app_create(iotsec_client_app_t *client, const char *host,
                             const char *port, const char *key_file_name,
                             const char *cert_file_name,
                             const char *trust_file_name,
                             const char *crl_file_name,
                             const char *common_name);
void iotsec_client_app_destroy(iotsec_client_app_t *client);
int iotsec_client_app_execute(iotsec_client_app_t *client,
                              const char *filename);

#endif
