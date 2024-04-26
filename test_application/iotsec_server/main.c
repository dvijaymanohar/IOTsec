#include "server.h"
#include <stdio.h>
#include <stdlib.h>

#define KEY_FILE_NAME "../certs/server_privkey.pem"
#define CERT_FILE_NAME "../certs/server_cert.pem"
#define TRUST_FILE_NAME "../certs/root_client_cert.pem"
#define CRL_FILE_NAME ""

int main(int argc, char **argv) {
  iotsec_server_app_t server = {0};
  int ret = 0;

  if (argc != 3) {
    fprintf(stderr, "usage: transfer_server host port\n");
    fprintf(stderr, "    host: IP address or host name to listen on (0.0.0.0 "
                    "to listen on all interfaces)\n");
    fprintf(stderr, "    port: port number to listen on\n");
    return EXIT_FAILURE;
  }
  ret = iotsec_server_app_init();
  if (ret < 0) {
    return EXIT_FAILURE;
  }
  ret =
      iotsec_server_app_create(&server, argv[1], argv[2], KEY_FILE_NAME,
                               CERT_FILE_NAME, TRUST_FILE_NAME, CRL_FILE_NAME);
  if (ret < 0) {
    iotsec_server_app_deinit();
    return EXIT_FAILURE;
  }
  ret = iotsec_server_app_run(&server);
  iotsec_server_app_destroy(&server);
  iotsec_server_app_deinit();
  if (ret < 0) {
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
