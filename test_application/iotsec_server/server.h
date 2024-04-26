#ifndef IOTSEC_SERVER_APP_H
#define IOTSEC_SERVER_APP_H

#include "iotsec_server.h"

typedef struct {
  iotsec_server_t iotsec_server;
} iotsec_server_app_t;

int iotsec_server_app_init(void);
void iotsec_server_app_deinit(void);
int iotsec_server_app_create(iotsec_server_app_t *server, const char *host,
                             const char *port, const char *key_file_name,
                             const char *cert_file_name,
                             const char *trust_file_name,
                             const char *crl_file_name);
void iotsec_server_app_destroy(iotsec_server_app_t *server);
int iotsec_server_app_run(iotsec_server_app_t *server);

#endif
