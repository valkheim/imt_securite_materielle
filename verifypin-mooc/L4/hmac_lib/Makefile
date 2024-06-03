TC= arm-none-eabi-
CC=$(TC)gcc
AR=$(TC)ar

CFLAGS = -mcpu=cortex-m3 -mthumb

all:
	$(CC) $(CFLAGS) -c sha256.c hmac-sha256.c
	$(AR) rcs libsha256.a sha256.o hmac-sha256.o

clean:
	rm *.o *.a