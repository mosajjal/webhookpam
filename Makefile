CC = gcc
CC_FALGS = -Wall

LD = ld

LIBS = -lcurl -lpam -lc

TARGET = pam_webhook

ARCH = $(shell arch)

all: $(TARGET)

$(TARGET):
	$(CC) $(CC_FALGS) $(LIBS) -fPIC -o $(TARGET).o -c $(TARGET).c
	$(LD) $(LIBS) -shared -o $(TARGET).so $(TARGET).o

install:
ifeq ($(ARCH),x86_64)
	cp $(TARGET).so /lib64/security/
else
	cp $(TARGET).so /lib/security/
endif

uninstall:
	rm -f /lib64/security/$(TARGET).so
	rm -f /lib/security/$(TARGET).so

clean:
	rm $(TARGET).so
	rm $(TARGET).o