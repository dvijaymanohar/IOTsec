ifeq ($(ip6),y)
IP6_CFLAGS = -DIOTSEC_IP6
endif
ifneq ($(dtls),n)
DTLS_CFLAGS = -DIOTSEC_DTLS_EN
DTLS_LIBS = -lgmp \
            -lhogweed \
            -lnettle \
            -lgnutls
endif
I1 = ../../lib/include
S1 = ../../lib/src
CC_ ?= gcc
CFLAGS = -Wall \
         -I$(I1)
CFLAGS += $(IP6_CFLAGS)
CFLAGS += $(DTLS_CFLAGS)
LD_ ?= gcc
LDFLAGS =
INCS = client.h \
       $(I1)/iotsec_client.h \
       $(I1)/iotsec_msg.h \
       $(I1)/iotsec_mem.h \
       $(I1)/iotsec_log.h \
       $(I1)/iotsec_ipv.h
OBJS = main.o \
       client.o \
       iotsec_client.o \
       iotsec_msg.o \
       iotsec_mem.o \
       iotsec_log.o
LIBS = $(DTLS_LIBS)
PROG = client
RM = /bin/rm -f

$(PROG): $(OBJS)
	$(LD_) $(LDFLAGS) $(OBJS) -o $@ $(LIBS)

%.o: %.c $(INCS)
	$(CC_) $(CFLAGS) -c $<

%.o: $(S1)/%.c $(INCS)
	$(CC_) $(CFLAGS) -c $<

%.o: $(T1)/%.c $(INCS)
	$(CC_) $(CFLAGS) -c $<

clean:
	$(RM) $(PROG) $(OBJS)
