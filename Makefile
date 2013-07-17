VERSION=v0.1

CC=$(CROSS_COMPILE)gcc
LD=$(CROSS_COMPILE)ld
CRYPTO=-lssl -lcrypto -lz
RTMP=-Llibrtmpnb -lrtmpnb
LIBS=$(RTMP) $(CRYPTO)

RTMPNB=librtmpnb/librtmpnb.a
PROGS=main
all: $(RTMPNB) $(PROGS)

FORCE:

$(RTMPNB): FORCE
	@cd librtmpnb; $(MAKE) all

$(PROGS): $(RTMPNB)

main: main.o
	$(CC) $(LDFLAGS) -o $@ $@.o $(LIBS)

clean:
	rm -f *.o main
	@cd librtmpnb; $(MAKE) clean
