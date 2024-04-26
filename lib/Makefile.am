AUTOMAKE_OPTIONS = subdir-objects
AM_CFLAGS = -I$(srcdir)/include -DIOTSEC_DTLS_EN
lib_LTLIBRARIES = libiotsec.la
libiotsec_la_SOURCES = src/iotsec_msg.c include/iotsec_msg.h src/iotsec_log.c include/iotsec_log.h src/iotsec_client.c include/iotsec_client.h src/iotsec_server.c include/iotsec_server.h include/iotsec_ipv.h src/iotsec_mem.c include/iotsec_mem.h
libiotsec_la_LDFLAGS = -version-info 0:5:0
include_HEADERS = include/iotsec_msg.h include/iotsec_log.h include/iotsec_client.h include/iotsec_server.h include/iotsec_ipv.h include/iotsec_mem.h
