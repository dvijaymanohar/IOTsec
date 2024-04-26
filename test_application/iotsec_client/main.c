#include "client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KEY_FILE_NAME "../certs/client_privkey.pem"
#define CERT_FILE_NAME "../certs/client_cert.pem"
#define TRUST_FILE_NAME "../certs/root_server_cert.pem"
#define CRL_FILE_NAME ""
#define COMMON_NAME "dummy/server"

int main(int argc, char **argv) {
  iotsec_client_app_t client = {0};
  int ret = 0;

  if (argc != 4) {
    fprintf(stderr, "usage: transfer_client host port client filename\n");
    fprintf(stderr, "    host: IP address or host name to connect to\n");
    fprintf(stderr, "    port: port number to connect to\n");
    fprintf(stderr, "    filename: file to transfer\n");
    return EXIT_FAILURE;
  }
  ret = iotsec_client_app_init();
  if (ret < 0) {
    return EXIT_FAILURE;
  }
  ret = iotsec_client_app_create(&client, argv[1], argv[2], KEY_FILE_NAME,
                                 CERT_FILE_NAME, TRUST_FILE_NAME, CRL_FILE_NAME,
                                 COMMON_NAME);
  if (ret < 0) {
    iotsec_client_app_deinit();
    return EXIT_FAILURE;
  }
  ret = iotsec_client_app_execute(&client, argv[3]);
  if (ret < 0) {
    iotsec_client_app_destroy(&client);
    iotsec_client_app_deinit();
    return EXIT_FAILURE;
  }
  iotsec_client_app_destroy(&client);
  iotsec_client_app_deinit();
  return EXIT_SUCCESS;
}
